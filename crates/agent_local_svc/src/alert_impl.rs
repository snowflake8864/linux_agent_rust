use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use grpc_gateway::alert::{
    alert_service_server::AlertService,
    AlertEvent, AlertFilter,
    AlertLogQuery, AlertLogResponse, AlertLogItem,
    AlertHandleRequest, AlertHandleResponse,
};
use crate::data_hub::AgentDataHub;

type AlertStream = Pin<
    Box<dyn tokio_stream::Stream<Item = Result<AlertEvent, Status>> + Send>,
>;

pub struct AlertServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl AlertService for AlertServiceImpl {
    type SubscribeAlertsStream = AlertStream;

    async fn subscribe_alerts(
        &self,
        request: Request<AlertFilter>,
    ) -> Result<Response<Self::SubscribeAlertsStream>, Status> {
        let filter = request.into_inner();
        let mut broadcast_rx = grpc_gateway::notify::subscribe_alerts();
        let (tx, rx) = mpsc::channel::<Result<AlertEvent, Status>>(256);

        tokio::spawn(async move {
            loop {
                match broadcast_rx.recv().await {
                    Ok(event) => {
                        // Apply filter (0 = ALL)
                        if filter.r#type != 0 && event.r#type != filter.r#type {
                            continue;
                        }
                        if tx.send(Ok(event)).await.is_err() {
                            break; // client disconnected
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        log::warn!("Alert broadcast lagged by {} messages", n);
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    /// 查询历史告警日志（分页）。
    /// 客户端启动时调用一次获取历史数据，随后通过 SubscribeAlerts 接收新告警。
    async fn get_alert_logs(
        &self,
        request: Request<AlertLogQuery>,
    ) -> Result<Response<AlertLogResponse>, Status> {
        let q = request.into_inner();
        let page      = if q.page == 0 { 1 } else { q.page };
        let page_size = if q.page_size == 0 { 20 } else { q.page_size };
        // handle_status: -1 表示全部
        let status_filter = if q.handle_status < 0 { None } else { Some(q.handle_status) };

        let rows = local_store::alert_log::query_page(status_filter, page, page_size)
            .map_err(|e| Status::internal(format!("query alert_log 失败: {}", e)))?;

        let total = local_store::alert_log::count(status_filter)
            .map_err(|e| Status::internal(format!("count alert_log 失败: {}", e)))?;

        let items = rows.into_iter().map(|r| AlertLogItem {
            id:                  r.id,
            alert_type:          r.alert_type,
            level:               r.level,
            process:             r.process,
            path:                r.path,
            pid:                 r.pid,
            detail:              r.detail,
            handle_status:       r.handle_status,
            handle_status_label: r.handle_status_label,
            handle_user:         r.handle_user,
            handled_at:          r.handled_at,
            created_at:          r.created_at,
            n_type:              0, // alert.db 未存 n_type，预留字段默认 0
        }).collect();

        Ok(Response::new(AlertLogResponse { items, total }))
    }

    /// 处置告警：标记为已处理或已忽略。
    /// handle_status 只接受 1=已处理 / 2=已忽略，传其他值返回 INVALID_ARGUMENT。
    async fn handle_alert(
        &self,
        request: Request<AlertHandleRequest>,
    ) -> Result<Response<AlertHandleResponse>, Status> {
        let req = request.into_inner();

        if req.id <= 0 {
            return Ok(Response::new(AlertHandleResponse {
                success: false,
                message: "id 无效".to_string(),
                affected: 0,
            }));
        }

        let label = match req.handle_status {
            1 => "已处理",
            2 => "已忽略",
            _ => return Err(Status::invalid_argument(
                format!("handle_status 只能是 1(已处理) 或 2(已忽略)，收到: {}", req.handle_status),
            )),
        };

        let affected = local_store::alert_log::update_handle_status(
            req.id,
            req.handle_status,
            label,
            &req.handle_user,
        ).map_err(|e| Status::internal(format!("更新处置状态失败: {}", e)))?;

        let success = affected > 0;
        let message = if success {
            format!("告警 #{} 已标记为 {}", req.id, label)
        } else {
            format!("告警 #{} 不存在或状态未变更", req.id)
        };

        Ok(Response::new(AlertHandleResponse {
            success,
            message,
            affected: affected as i32,
        }))
    }
}
