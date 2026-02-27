use std::pin::Pin;
use std::sync::Arc;
use std::future::Future;
use std::time::Duration;
use tonic::transport::Server;
use logging::{log_error, log_info,log_warn};
use common::manager::boot::BootManager;
use net_client::core::NetClient;
use crate::clamav_scanner::{ClamAVConnectionPool, ClamAVConnection};

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
            let (virus_scan_enabled, virus_scan_dev_mode, virus_scan_grpc_addr, virus_scan_dev_grpc_addr, clamav_enabled, clamav_host, clamav_port, clamav_timeout_secs, clamav_pool_size) = {
                let cfg = config::net_info::NETINFO_CONFIG.lock().unwrap();
                (
                    cfg.virus_scan_enabled,
                    cfg.virus_scan_dev_mode,
                    cfg.virus_scan_grpc_addr.clone(),
                    cfg.virus_scan_dev_grpc_addr.clone(),
                    cfg.clamav_enabled,
                    cfg.clamav_host.clone(),
                    cfg.clamav_port,
                    cfg.clamav_timeout_secs,
                    cfg.clamav_pool_size,
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
            
            // 检查 ClamAV 是否启用
            let scanner = if clamav_enabled {
                let timeout = Duration::from_secs(clamav_timeout_secs);
                
                // 自动检测连接类型
                let connection = if clamav_host.starts_with('/') || clamav_host.contains(".sock") {
                    ClamAVConnection::Unix { socket_path: clamav_host.clone() }
                } else {
                    ClamAVConnection::Tcp { host: clamav_host.clone(), port: clamav_port }
                };
                
                let pool = Arc::new(ClamAVConnectionPool::new(connection, timeout, clamav_pool_size));
                
                match pool.ping().await {
                    Ok(_) => {
                        log_info!("ClamAV 连接池创建成功，大小={}", clamav_pool_size);
                        Some(pool)
                    }
                    Err(e) => {
                        log_warn!("ClamAV 连接失败: {}，病毒扫描功能不可用", e);
                        None
                    }
                }
            } else {
                log_warn!("ClamAV 未启用，病毒扫描功能不可用");
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
                .add_service(crate::proto::virus_scan_service_server::VirusScanServiceServer::new(grpc_service))
                // ============================================================
                // 漏洞扫描服务 (如需关闭，注释掉下面几行)
                // ============================================================
                .add_service(crate::proto::vuln_scan_service_server::VulnScanServiceServer::new(
                    crate::VulnScanGrpcService::new(self.clone(), vuln_base_url),
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
