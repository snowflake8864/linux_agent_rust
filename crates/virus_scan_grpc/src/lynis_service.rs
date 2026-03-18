// crates/virus_scan_grpc/src/lynis_service.rs
// Lynis 扫描 gRPC 服务实现

use crate::lynis_scanner::{LynisScanner, LynisScanResult};
use crate::proto::lynis_scan_service_server::LynisScanService;
use crate::proto::{
    LynisClientMessage, LynisServerMessage, LynisStartResponse, LynisScanProgress,
    LynisScanCompleted, LynisScanError, LynisPong, LynisWarning, LynisSuggestion, LynisDetail,
    StartLynisScanRequest, StopLynisScanRequest, LynisPing,
};
use futures::Stream;
use futures::StreamExt;
use logging::{log_error, log_info};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use uuid::Uuid;

/// 扫描任务状态：保存取消令牌，可直接取消 lynis OS 进程
type ScanTaskMap = Arc<Mutex<std::collections::HashMap<String, CancellationToken>>>;

/// Lynis 扫描 gRPC 服务
pub struct LynisScanGrpcService {
    active_scans: ScanTaskMap,
}

impl LynisScanGrpcService {
    pub fn new() -> Self {
        Self {
            active_scans: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// 停止指定扫描任务（通过取消令牌直接杀死 OS 进程）
    async fn stop_scan(&self, scan_id: &str) {
        let mut scans = self.active_scans.lock().await;
        if let Some(token) = scans.remove(scan_id) {
            token.cancel();
            log_info!("[LynisService] Scan {} cancel signal sent", scan_id);
        }
    }
}

#[tonic::async_trait]
impl LynisScanService for LynisScanGrpcService {
    type StreamControlStream = Pin<Box<dyn Stream<Item = Result<LynisServerMessage, Status>> + Send>>;

    async fn stream_control(
        &self,
        request: Request<tonic::Streaming<LynisClientMessage>>,
    ) -> Result<Response<Self::StreamControlStream>, Status> {
        let mut stream = request.into_inner();
        let (tx, rx) = mpsc::channel::<Result<LynisServerMessage, Status>>(32);
        let active_scans = self.active_scans.clone();

        tokio::spawn(async move {
            while let Some(result) = stream.next().await {
                match result {
                    Ok(msg) => {
                        if let Some(cmd) = msg.cmd {
                            match cmd {
                                crate::proto::lynis_client_message::Cmd::StartScan(req) => {
                                    handle_start_scan(req, tx.clone(), active_scans.clone()).await;
                                }
                                crate::proto::lynis_client_message::Cmd::StopScan(req) => {
                                    handle_stop_scan(req, tx.clone(), active_scans.clone()).await;
                                }
                                crate::proto::lynis_client_message::Cmd::Ping(ping) => {
                                    handle_ping(ping, tx.clone()).await;
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        log_error!("[LynisService] gRPC stream error: {}", e);
                        break;
                    }
                }
            }
        });

        let rx_stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(rx_stream) as Self::StreamControlStream))
    }
}

/// 处理开始扫描请求
async fn handle_start_scan(
    req: StartLynisScanRequest,
    tx: mpsc::Sender<Result<LynisServerMessage, Status>>,
    active_scans: ScanTaskMap,
) {
    let scan_id = Uuid::new_v4().to_string();
    log_info!("[LynisService] Received start scan request, scan_id={}", scan_id);

    // 发送启动响应
    let _ = tx
        .send(Ok(LynisServerMessage {
            event: Some(crate::proto::lynis_server_message::Event::StartResponse(
                LynisStartResponse {
                    success: true,
                    scan_id: scan_id.clone(),
                    message: "Lynis scan started".to_string(),
                },
            )),
        }))
        .await;

    // 为此扫描创建取消令牌
    let cancel_token = CancellationToken::new();
    let cancel_child = cancel_token.clone();

    // 启动扫描任务
    let scan_id_clone = scan_id.clone();
    let tx_clone = tx.clone();

    tokio::spawn(async move {
        // 模拟进度更新（lynis 本身不提供实时进度）
        let progress_stages = vec![
            (10, "Initializing system audit..."),
            (25, "Checking system binaries..."),
            (40, "Analyzing authentication..."),
            (55, "Checking network configuration..."),
            (70, "Analyzing storage..."),
            (85, "Checking kernel parameters..."),
            (95, "Generating report..."),
        ];

        // 发送初始进度
        for (percent, status) in &progress_stages[..3] {
            let _ = tx_clone
                .send(Ok(LynisServerMessage {
                    event: Some(crate::proto::lynis_server_message::Event::Progress(
                        LynisScanProgress {
                            scan_id: scan_id_clone.clone(),
                            progress_percent: *percent,
                            current_test: "system_audit".to_string(),
                            status_text: status.to_string(),
                        },
                    )),
                }))
                .await;
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        }

        // 执行实际扫描，传入取消令牌
        match LynisScanner::scan(req.quick_mode, cancel_child).await {
            Ok(result) => {
                // 发送完成前的进度
                for (percent, status) in &progress_stages[3..] {
                    let _ = tx_clone
                        .send(Ok(LynisServerMessage {
                            event: Some(crate::proto::lynis_server_message::Event::Progress(
                                LynisScanProgress {
                                    scan_id: scan_id_clone.clone(),
                                    progress_percent: *percent,
                                    current_test: "system_audit".to_string(),
                                    status_text: status.to_string(),
                                },
                            )),
                        }))
                        .await;
                }

                // 发送完成消息
                let _ = tx_clone
                    .send(Ok(LynisServerMessage {
                        event: Some(crate::proto::lynis_server_message::Event::Completed(
                            convert_result_to_proto(result, scan_id_clone),
                        )),
                    }))
                    .await;
            }
            Err(e) => {
                log_error!("[LynisService] Scan failed: {}", e);
                let _ = tx_clone
                    .send(Ok(LynisServerMessage {
                        event: Some(crate::proto::lynis_server_message::Event::Error(
                            LynisScanError {
                                scan_id: scan_id_clone,
                                code: "SCAN_FAILED".to_string(),
                                message: e,
                            },
                        )),
                    }))
                    .await;
            }
        }
    });

    // 记录活跃扫描，保存取消令牌而非 JoinHandle
    active_scans.lock().await.insert(scan_id, cancel_token);
}

/// 处理停止扫描请求
async fn handle_stop_scan(
    req: StopLynisScanRequest,
    _tx: mpsc::Sender<Result<LynisServerMessage, Status>>,
    active_scans: ScanTaskMap,
) {
    log_info!("[LynisService] Received stop scan request, scan_id={}", req.scan_id);

    let mut scans = active_scans.lock().await;
    if let Some(token) = scans.remove(&req.scan_id) {
        token.cancel();
        log_info!("[LynisService] Scan {} cancel signal sent, lynis will be killed", req.scan_id);
    }
}

/// 处理心跳
async fn handle_ping(
    ping: LynisPing,
    tx: mpsc::Sender<Result<LynisServerMessage, Status>>,
) {
    let _ = tx
        .send(Ok(LynisServerMessage {
            event: Some(crate::proto::lynis_server_message::Event::Pong(
                LynisPong {
                    timestamp: ping.timestamp,
                },
            )),
        }))
        .await;
}

/// 将扫描结果转换为 proto 消息
fn convert_result_to_proto(result: LynisScanResult, scan_id: String) -> LynisScanCompleted {
    let warnings: Vec<LynisWarning> = result
        .warnings
        .into_iter()
        .map(|w| LynisWarning {
            test_id: w.test_id,
            message: w.message,
            detail: w.detail,
        })
        .collect();

    let suggestions: Vec<LynisSuggestion> = result
        .suggestions
        .into_iter()
        .map(|s| LynisSuggestion {
            test_id: s.test_id,
            message: s.message,
            remediation: s.remediation,
        })
        .collect();

    let details: Vec<LynisDetail> = result
        .details
        .into_iter()
        .map(|d| LynisDetail {
            test_id: d.test_id,
            service: d.service,
            field: d.field,
            current_value: d.current_value,
            recommended_value: d.recommended_value,
        })
        .collect();

    LynisScanCompleted {
        scan_id,
        hardening_index: result.hardening_index,
        warning_count: result.warning_count as i32,
        suggestion_count: result.suggestion_count as i32,
        warnings,
        suggestions,
        details,
        report_raw: result.raw_report,
        duration_ms: result.duration_ms as i64,
    }
}
