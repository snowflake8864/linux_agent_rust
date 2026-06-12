use std::pin::Pin;
use std::sync::Arc;
use std::future::Future;
use std::time::Duration;
use tonic::transport::Server;
use logging::{log_error, log_info,log_warn};
use common::manager::boot::BootManager;
use net_client::core::NetClient;
use crate::clamav_scanner::{ClamAVConnectionPool, ClamAVConnection};
use agent_local_svc::{
    AgentDataHub,
    ConfigServiceImpl, ProcessPolicyServiceImpl, PeripheralPolicyServiceImpl,
    IpPolicyServiceImpl, DataQueryServiceImpl, OutreachDetectServiceImpl,
    AgentStatusServiceImpl, AlertServiceImpl, LocalTaskServiceImpl,
    PolicyWatchServiceImpl, ProcessDefenseServiceImpl, PeripheralDefenseServiceImpl,
};
use agent_local_svc::stub_handlers::{
    DirPolicyServiceImpl, ExtortPolicyServiceImpl, JumpServiceImpl,
    BackupServiceImpl, TrustDirServiceImpl, VirtualPortServiceImpl,
};

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
            let (virus_scan_enabled, virus_scan_dev_mode, virus_scan_grpc_addr, virus_scan_dev_grpc_addr, clamav_enabled, clamav_host, clamav_port, clamav_timeout_secs, clamav_pool_size, clamav_connection_type, clamav_socket_path) = {
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
                    cfg.clamav_connection_type.clone(),
                    cfg.clamav_socket_path.clone(),
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
                
                let connection = match clamav_connection_type.to_lowercase().as_str() {
                    "unix" | "socket" => {
                        log_info!("ClamAV: 使用 Unix socket 连接, path={}", clamav_socket_path);
                        ClamAVConnection::Unix { socket_path: clamav_socket_path.clone() }
                    }
                    _ => {
                        log_info!("ClamAV: 使用 TCP socket 连接, host={}, port={}", clamav_host, clamav_port);
                        ClamAVConnection::Tcp { host: clamav_host.clone(), port: clamav_port }
                    }
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

            // Shared data hub for all local gRPC services
            let data_hub = Arc::new(AgentDataHub::new());
            let pattern_mgr = self.pattern_mgr();

            let addr: std::net::SocketAddr = match virus_scan_grpc_addr.parse() {
                Ok(a) => a,
                Err(e) => {
                    log_error!("地址解析失败: {}", e);
                    return Err(format!("地址解析失败: {}", e));
                }
            };

            log_info!("病毒扫描 gRPC 服务正在启动: {}", addr);

            Server::builder()
                .add_service(grpc_gateway::virus_scan::virus_scan_service_server::VirusScanServiceServer::new(grpc_service))
                // ============================================================
                // 漏洞扫描服务 (如需关闭，注释掉下面几行)
                // ============================================================
                .add_service(grpc_gateway::vuln_scan::vuln_scan_service_server::VulnScanServiceServer::new(
                    crate::VulnScanGrpcService::new(self.clone(), vuln_base_url),
                ))
                // ============================================================
                // 新增：本地管理 gRPC 服务（在线只读，离线读写）
                // ============================================================
                .add_service(
                    grpc_gateway::agent_status::agent_status_service_server::AgentStatusServiceServer::new(
                        AgentStatusServiceImpl { data_hub: data_hub.clone() },
                    )
                )
                // ============================================================
                // 本地管理 gRPC 服务（在线只读，离线读写）
                // ============================================================
                .add_service(
                    grpc_gateway::alert::alert_service_server::AlertServiceServer::new(
                        AlertServiceImpl { data_hub: data_hub.clone() },
                    )
                )
                .add_service(
                    grpc_gateway::config::config_service_server::ConfigServiceServer::new(
                        ConfigServiceImpl { data_hub: data_hub.clone() },
                    )
                )
                .add_service(
                    grpc_gateway::task_local::local_task_service_server::LocalTaskServiceServer::new(
                        LocalTaskServiceImpl { data_hub: data_hub.clone() },
                    )
                )
                .add_service(
                    grpc_gateway::process_policy::process_policy_service_server::ProcessPolicyServiceServer::new(
                        ProcessPolicyServiceImpl { data_hub: data_hub.clone() },
                    )
                )
                .add_service(
                    grpc_gateway::peripheral_policy::peripheral_policy_service_server::PeripheralPolicyServiceServer::new(
                        PeripheralPolicyServiceImpl { data_hub: data_hub.clone() },
                    )
                )
                .add_service(
                    grpc_gateway::ip_policy::ip_policy_service_server::IpPolicyServiceServer::new(
                        IpPolicyServiceImpl { data_hub: data_hub.clone() },
                    )
                )
                .add_service(
                    grpc_gateway::data_query::data_query_service_server::DataQueryServiceServer::new(
                        DataQueryServiceImpl { data_hub: data_hub.clone() },
                    )
                )
                .add_service(
                    grpc_gateway::outreach_detect::outreach_detect_service_server::OutreachDetectServiceServer::new(
                        OutreachDetectServiceImpl { data_hub: data_hub.clone() },
                    )
                )
                .add_service(
                    grpc_gateway::policy_watch::policy_watch_service_server::PolicyWatchServiceServer::new(
                        PolicyWatchServiceImpl { data_hub: data_hub.clone() },
                    )
                )
                // Stub services
                .add_service(
                    grpc_gateway::dir_policy::dir_policy_service_server::DirPolicyServiceServer::new(
                        DirPolicyServiceImpl {
                            data_hub: data_hub.clone(),
                            pattern_mgr: pattern_mgr.clone(),
                        },
                    )
                )
                .add_service(
                    grpc_gateway::extort_policy::extort_policy_service_server::ExtortPolicyServiceServer::new(
                        ExtortPolicyServiceImpl {
                            data_hub: data_hub.clone(),
                            pattern_mgr: pattern_mgr.clone(),
                        },
                    )
                )
                .add_service(
                    grpc_gateway::jump::jump_service_server::JumpServiceServer::new(
                        JumpServiceImpl { data_hub: data_hub.clone() },
                    )
                )
                .add_service(
                    grpc_gateway::backup::backup_service_server::BackupServiceServer::new(
                        BackupServiceImpl { data_hub: data_hub.clone() },
                    )
                )
                .add_service(
                    grpc_gateway::trust_dir::trust_dir_service_server::TrustDirServiceServer::new(
                        TrustDirServiceImpl { data_hub: data_hub.clone() },
                    )
                )
                .add_service(
                    grpc_gateway::virtual_port::virtual_port_service_server::VirtualPortServiceServer::new(
                        VirtualPortServiceImpl { data_hub: data_hub.clone() },
                    )
                )
                .add_service(
                    grpc_gateway::protection_mode::process_defense_service_server::ProcessDefenseServiceServer::new(
                        ProcessDefenseServiceImpl { data_hub: data_hub.clone() },
                    )
                )
                .add_service(
                    grpc_gateway::protection_mode::peripheral_defense_service_server::PeripheralDefenseServiceServer::new(
                        PeripheralDefenseServiceImpl { data_hub: data_hub.clone() },
                    )
                )
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
