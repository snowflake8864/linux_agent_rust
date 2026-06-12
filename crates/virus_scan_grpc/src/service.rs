use std::pin::Pin;
use std::sync::Arc;
use std::future::Future;
use std::time::Duration;
use tonic::transport::Server;
use logging::{log_error, log_info,log_warn};
use common::manager::boot::BootManager;
use net_client::core::NetClient;
use crate::vigilixav_scanner::{VigilixAVConnectionPool, VigilixAVConnection};
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
            let (grpc_enabled, grpc_dev_mode, grpc_addr, grpc_dev_addr, vigilixav_enabled, vigilixav_host, vigilixav_port, vigilixav_timeout_secs, vigilixav_pool_size, vigilixav_connection_type, vigilixav_socket_path) = {
                let cfg = config::net_info::NETINFO_CONFIG.lock().unwrap();
                (
                    cfg.grpc_enabled,
                    cfg.grpc_dev_mode,
                    cfg.grpc_addr.clone(),
                    cfg.grpc_dev_addr.clone(),
                    cfg.vigilixav_enabled,
                    cfg.vigilixav_host.clone(),
                    cfg.vigilixav_port,
                    cfg.vigilixav_timeout_secs,
                    cfg.vigilixav_pool_size,
                    cfg.vigilixav_connection_type.clone(),
                    cfg.vigilixav_socket_path.clone(),
                )
            };

            if !grpc_enabled {
                return Ok("gRPC 服务未启用".to_string());
            }

            let grpc_listen_addr = if grpc_dev_mode {
                grpc_dev_addr
            } else {
                grpc_addr
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

            // Shared data hub for all local gRPC services
            let data_hub = Arc::new(AgentDataHub::new());
            let pattern_mgr = self.pattern_mgr();

            let addr: std::net::SocketAddr = match grpc_listen_addr.parse() {
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
