use std::pin::Pin;
use std::sync::Arc;
use std::future::Future;
use std::time::Duration;
use tonic::transport::Server;
use logging::{log_error, log_info,log_warn};
use common::manager::boot::BootManager;
use net_client::core::NetClient;
use crate::vigilixav_scanner::{VigilixAVConnectionPool, VigilixAVConnection};

pub trait StartVirusScanGrpcService {
    fn start_virus_scan_grpc_service(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>;
}

pub struct VirusScanServiceImpl;

impl VirusScanServiceImpl {
    pub fn new() -> Self {
        Self
    }
}

impl StartVirusScanGrpcService for BootManager {
    fn start_virus_scan_grpc_service(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {
            let (virus_scan_enabled, virus_scan_dev_mode, virus_scan_grpc_addr, virus_scan_dev_grpc_addr, vigilixav_enabled, vigilixav_host, vigilixav_port, vigilixav_timeout_secs, vigilixav_pool_size, vigilixav_connection_type, vigilixav_socket_path) = {
                let cfg = config::net_info::NETINFO_CONFIG.lock().unwrap();
                (
                    cfg.virus_scan_enabled,
                    cfg.virus_scan_dev_mode,
                    cfg.virus_scan_grpc_addr.clone(),
                    cfg.virus_scan_dev_grpc_addr.clone(),
                    cfg.vigilixav_enabled,
                    cfg.vigilixav_host.clone(),
                    cfg.vigilixav_port,
                    cfg.vigilixav_timeout_secs,
                    cfg.vigilixav_pool_size,
                    cfg.vigilixav_connection_type.clone(),
                    cfg.vigilixav_socket_path.clone(),
                )
            };
            
            if !virus_scan_enabled {
                return Ok("病毒扫描服务未启用".to_string());
            }

            let virus_scan_grpc_addr = if virus_scan_dev_mode {
                virus_scan_dev_grpc_addr
            } else {
                virus_scan_grpc_addr
            };
            
            // 检查 VigilixAV 是否启用
            let scanner = if vigilixav_enabled {
                let timeout = Duration::from_secs(vigilixav_timeout_secs);
                
                let connection = match vigilixav_connection_type.to_lowercase().as_str() {
                    "unix" | "socket" => {
                        log_info!("VigilixAV: 使用 Unix socket 连接, path={}", vigilixav_socket_path);
                        VigilixAVConnection::Unix { socket_path: vigilixav_socket_path.clone() }
                    }
                    _ => {
                        log_info!("VigilixAV: 使用 TCP socket 连接, host={}, port={}", vigilixav_host, vigilixav_port);
                        VigilixAVConnection::Tcp { host: vigilixav_host.clone(), port: vigilixav_port }
                    }
                };
                
                let pool = Arc::new(VigilixAVConnectionPool::new(connection, timeout, vigilixav_pool_size));
                
                match pool.ping().await {
                    Ok(_) => {
                        log_info!("VigilixAV 连接池创建成功，大小={}", vigilixav_pool_size);
                        Some(pool)
                    }
                    Err(e) => {
                        log_warn!("VigilixAV 连接失败: {}，病毒扫描功能不可用", e);
                        None
                    }
                }
            } else {
                log_warn!("VigilixAV 未启用，病毒扫描功能不可用");
                None
            };
            
            let base_url = self.get_base_url();
            let vuln_base_url = base_url.clone();
            let net_client = match NetClient::new(Some(base_url.clone()), true) {
                Ok(client) => client,
                Err(e) => {
                    log_error!("创建 NetClient 失败: {}", e);
                    return Err(format!("创建 NetClient 失败: {}", e));
                }
            };

            let task_mgr = Arc::new(crate::ScanTaskManager::new(
                Arc::new(net_client),
                base_url,
                scanner,
                Some(self.clone()),
            ));

            let grpc_service = crate::VirusScanGrpcService::new(task_mgr);

            let addr: std::net::SocketAddr = match virus_scan_grpc_addr.parse() {
                Ok(a) => a,
                Err(e) => {
                    log_error!("地址解析失败: {}", e);
                    return Err(format!("地址解析失败: {}", e));
                }
            };

            log_info!("病毒扫描 gRPC 服务正在启动: {}", addr);

            Server::builder()
                .http2_keepalive_interval(Some(Duration::from_secs(30)))
                .http2_keepalive_timeout(Some(Duration::from_secs(15)))
                .add_service(crate::proto::virus_scan_service_server::VirusScanServiceServer::new(grpc_service))
                // ============================================================
                // 漏洞扫描服务 (接收外部推送的漏洞数据)
                // ============================================================
                .add_service(crate::proto::vuln_scan_service_server::VulnScanServiceServer::new(
                    crate::VulnScanGrpcService::new(self.clone(), vuln_base_url),
                ))
                // ============================================================
                // Lynis 系统漏洞扫描服务 (触发 Lynis 执行并返回结果)
                // ============================================================
                .add_service(crate::proto::lynis_scan_service_server::LynisScanServiceServer::new(
                    crate::LynisScanGrpcService::new(),
                ))
                // ============================================================
                .serve(addr)
                .await
                .map_err(|e| {
                    log_error!("病毒扫描 gRPC 服务错误: {}", e);
                    format!("病毒扫描 gRPC 服务错误: {}", e)
                })?;

            Ok("病毒扫描 gRPC 服务已停止".to_string())
        })
    }
}
