use std::sync::Arc;
use tonic::{Request, Response, Status};

use grpc_gateway::task_local::{
    local_task_service_server::LocalTaskService, SubmitTaskRequest, SubmitTaskResponse, TaskResult,
    TriggerLocalUpdateRequest, TriggerLocalUpdateResponse,
};
use crate::data_hub::{require_offline, AgentDataHub};

pub struct LocalTaskServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl LocalTaskService for LocalTaskServiceImpl {
    async fn submit_task(
        &self,
        request: Request<SubmitTaskRequest>,
    ) -> Result<Response<SubmitTaskResponse>, Status> {
        require_offline()?;
        let req = request.into_inner();

        let mut results = Vec::new();
        for task_id in req.task_ids {
            if grpc_gateway::notify::submit_local_task(task_id) {
                results.push(TaskResult {
                    task_id,
                    success: true,
                    message: "任务已提交".into(),
                });
            } else {
                results.push(TaskResult {
                    task_id,
                    success: false,
                    message: "任务通道未就绪（Agent 未完全启动）".into(),
                });
            }
        }

        Ok(Response::new(SubmitTaskResponse {
            success: results.iter().all(|r| r.success),
            results,
        }))
    }

    async fn trigger_local_update(
        &self,
        request: Request<TriggerLocalUpdateRequest>,
    ) -> Result<Response<TriggerLocalUpdateResponse>, Status> {
        // 本地升级测试用，不检查离线状态
        let req = request.into_inner();
        let zip_path = req.zip_path;

        let desc = if zip_path.is_empty() {
            "自动扫描 /opt/osec/upgrade/".to_string()
        } else {
            format!("指定路径: {}", zip_path)
        };
        log::info!("[gRPC] TriggerLocalUpdate: {}", desc);

        if grpc_gateway::notify::submit_local_upgrade(zip_path) {
            Ok(Response::new(TriggerLocalUpdateResponse {
                success: true,
                message: format!("本地升级已触发 ({})", desc),
            }))
        } else {
            Ok(Response::new(TriggerLocalUpdateResponse {
                success: false,
                message: "升级通道未就绪（Agent 未完全启动）".into(),
            }))
        }
    }
}
