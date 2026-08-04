use grpc_gateway::virus_scan::{ClientMessage, Pong, ServerMessage};
use grpc_gateway::virus_scan::virus_scan_service_server::VirusScanService;
use crate::scan_task_mgr::ScanTaskManager;
use crate::STREAM_BUFFER_SIZE;
use futures::Stream;
use futures::StreamExt;
use logging::{log_error, log_info};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

type GrpcStream = Pin<Box<dyn Stream<Item = Result<ServerMessage, Status>> + Send>>;

pub struct VirusScanGrpcService {
    task_mgr: Arc<ScanTaskManager>,
}

impl VirusScanGrpcService {
    pub fn new(task_mgr: Arc<ScanTaskManager>) -> Self {
        Self { task_mgr }
    }
}

#[tonic::async_trait]
impl VirusScanService for VirusScanGrpcService {
    type StreamControlStream = GrpcStream;

    async fn stream_control(
        &self,
        request: Request<tonic::Streaming<ClientMessage>>,
    ) -> Result<Response<Self::StreamControlStream>, Status> {
        let mut stream = request.into_inner();
        let (tx, rx) = mpsc::channel::<Result<ServerMessage, Status>>(STREAM_BUFFER_SIZE);
        let rx = ReceiverStream::new(rx);
        let task_mgr = self.task_mgr.clone();

        tokio::spawn(async move {
            while let Some(result) = stream.next().await {
                match result {
                    Ok(msg) => {
                        if let Some(cmd) = msg.cmd {
                            match cmd {
                                grpc_gateway::virus_scan::client_message::Cmd::StartScan(req) => {
                                    log_info!("[gRPC] 收到扫描请求: target={}, excludes={:?}", req.target, req.exclude_dirs);
                                    let tx_clone = tx.clone();
                                    match task_mgr
                                        .start_scan(&req.target, &req.exclude_dirs, tx_clone)
                                        .await
                                    {
                                        Ok(scan_id) => {
                                            log_info!("[gRPC] 扫描启动成功, scan_id={}", scan_id);
                                            let _ = tx
                                                .send(Ok(ServerMessage {
                                                    event: Some(
                                                        grpc_gateway::virus_scan::server_message::Event::StartResponse(
                                                            grpc_gateway::virus_scan::StartScanResponse {
                                                                success: true,
                                                                scan_id,
                                                                message: "扫描已启动".to_string(),
                                                            },
                                                        ),
                                                    ),
                                                }))
                                                .await;
                                        }
                                        Err(e) => {
                                            log_error!("[gRPC] 扫描启动失败: {}", e);
                                            let _ = tx
                                                .send(Ok(ServerMessage {
                                                    event: Some(
                                                        grpc_gateway::virus_scan::server_message::Event::Error(
                                                            grpc_gateway::virus_scan::ScanError {
                                                                scan_id: String::new(),
                                                                code: "START_FAILED".to_string(),
                                                                message: e,
                                                            },
                                                        ),
                                                    ),
                                                }))
                                                .await;
                                        }
                                    }
                                }

                                grpc_gateway::virus_scan::client_message::Cmd::StopScan(req) => {
                                    log_info!("[gRPC] 收到停止扫描请求: scan_id={}", req.scan_id);
                                    task_mgr.stop_scan(&req.scan_id).await;
                                }

                                grpc_gateway::virus_scan::client_message::Cmd::Ping(ping) => {
                                    log_info!("[gRPC] 收到 PING, timestamp={}", ping.timestamp);
                                    let _ = tx
                                        .send(Ok(ServerMessage {
                                            event: Some(
                                                grpc_gateway::virus_scan::server_message::Event::Pong(Pong {
                                                    timestamp: ping.timestamp,
                                                }),
                                            ),
                                        }))
                                        .await;
                                }

                                grpc_gateway::virus_scan::client_message::Cmd::DisposeFile(req) => {
                                    log_info!("[gRPC] 收到处置请求: scan_id={}, file={}, action={:?}",
                                        req.scan_id, req.file_path, req.action);
                                    let scanner = task_mgr.vigilixav_scanner();
                                    match scanner {
                                        Some(scanner) => {
                                            // quarantine_dir 由 vigilixd.conf 控制，忽略客户端传入值
                                            let action = match req.action {
                                                1 => crate::vigilixav_scanner::DispositionAction::Move,
                                                2 => crate::vigilixav_scanner::DispositionAction::Remove,
                                                3 => crate::vigilixav_scanner::DispositionAction::Restore,
                                                unknown => {
                                                    log_error!("[gRPC] 未知处置动作: {}", unknown);
                                                    let _ = tx.send(Ok(ServerMessage {
                                                        event: Some(
                                                            grpc_gateway::virus_scan::server_message::Event::DisposeResult(
                                                                grpc_gateway::virus_scan::DisposeFileResponse {
                                                                    scan_id: req.scan_id,
                                                                    file_path: req.file_path,
                                                                    action: unknown,
                                                                    success: false,
                                                                    message: format!("未知动作: {}", unknown),
                                                                },
                                                            ),
                                                        ),
                                                    })).await;
                                                    continue;
                                                }
                                            };
                                            let result = scanner.dispose_file(&req.file_path, action, None).await;
                                            let (success, message) = match result {
                                                crate::vigilixav_scanner::DispositionResult::Success { message } => {
                                                    (true, message)
                                                }
                                                crate::vigilixav_scanner::DispositionResult::Error { message } => {
                                                    (false, message)
                                                }
                                            };
                                            let _ = tx.send(Ok(ServerMessage {
                                                event: Some(
                                                    grpc_gateway::virus_scan::server_message::Event::DisposeResult(
                                                        grpc_gateway::virus_scan::DisposeFileResponse {
                                                            scan_id: req.scan_id,
                                                            file_path: req.file_path,
                                                            action: req.action,
                                                            success,
                                                            message,
                                                        },
                                                    ),
                                                ),
                                            })).await;
                                        }
                                        None => {
                                            log_error!("[gRPC] VigilixAV 扫描器不可用，无法执行处置操作");
                                            let _ = tx.send(Ok(ServerMessage {
                                                event: Some(
                                                    grpc_gateway::virus_scan::server_message::Event::DisposeResult(
                                                        grpc_gateway::virus_scan::DisposeFileResponse {
                                                            scan_id: req.scan_id,
                                                            file_path: req.file_path,
                                                            action: req.action,
                                                            success: false,
                                                            message: "VigilixAV scanner not available".to_string(),
                                                        },
                                                    ),
                                                ),
                                            })).await;
                                        }
                                    }
                                }

                                grpc_gateway::virus_scan::client_message::Cmd::PauseScan(req) => {
                                    log_info!("[gRPC] 收到暂停扫描请求: scan_id={}", req.scan_id);
                                    let (success, message) = match task_mgr.pause_scan(&req.scan_id).await {
                                        Ok(msg) => (true, msg),
                                        Err(e) => (false, e),
                                    };
                                    let _ = tx.send(Ok(ServerMessage {
                                        event: Some(
                                            grpc_gateway::virus_scan::server_message::Event::PauseResponse(
                                                grpc_gateway::virus_scan::PauseScanResponse {
                                                    scan_id: req.scan_id,
                                                    success,
                                                    message,
                                                },
                                            ),
                                        ),
                                    })).await;
                                }

                                grpc_gateway::virus_scan::client_message::Cmd::ResumeScan(req) => {
                                    log_info!("[gRPC] 收到恢复扫描请求: scan_id={}", req.scan_id);
                                    let (success, message) = match task_mgr.resume_scan(&req.scan_id).await {
                                        Ok(msg) => (true, msg),
                                        Err(e) => (false, e),
                                    };
                                    let _ = tx.send(Ok(ServerMessage {
                                        event: Some(
                                            grpc_gateway::virus_scan::server_message::Event::ResumeResponse(
                                                grpc_gateway::virus_scan::ResumeScanResponse {
                                                    scan_id: req.scan_id,
                                                    success,
                                                    message,
                                                },
                                            ),
                                        ),
                                    })).await;
                                }

                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        log_error!("gRPC 流错误: {}", e);
                        break;
                    }
                }
            }
            // 连接断开，清理该连接的已完成任务，释放内存
            task_mgr.clear_completed_tasks().await;
        });

        Ok(Response::new(Box::pin(rx) as GrpcStream))
    }
}
