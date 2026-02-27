use crate::proto::{PutVulnScanRequest, PutVulnScanResponse};
use crate::proto::vuln_scan_service_server::VulnScanService;
use common::manager::boot::BootManager;
use logging::{log_error, log_info};
use serde::Serialize;
use std::sync::Arc;
use tokio::time::Duration;
use tonic::{Request, Response, Status};

pub struct VulnScanGrpcService {
    boot_manager: BootManager,
    base_url: String,
}

#[derive(Serialize)]
struct VulnReportItem {
    title: String,
    severity: String,
    file_dir: String,
}

impl VulnScanGrpcService {
    pub fn new(boot_manager: BootManager, base_url: String) -> Self {
        Self {
            boot_manager,
            base_url,
        }
    }
}

#[tonic::async_trait]
impl VulnScanService for VulnScanGrpcService {
    async fn put_vuln_scan(
        &self,
        request: Request<PutVulnScanRequest>,
    ) -> Result<Response<PutVulnScanResponse>, Status> {
        let req = request.into_inner();
        let start_at = req.start_at;
        let end_at = req.end_at;
        let vuln_total = req.vuln_total;
        let vulnerabilities = req.vuln_list;

        log_info!(
            "[VulnScan] 收到漏洞数据，数量: {}",
            vulnerabilities.len()
        );

        for v in &vulnerabilities {
            log_info!("[VulnScan] - {} (severity: {}, file: {})", v.title, v.severity, v.file_path);
        }

        if vulnerabilities.is_empty() {
            return Ok(Response::new(PutVulnScanResponse {
                success: true,
                message: "No vulnerabilities to report".to_string(),
            }));
        }

        let items: Vec<VulnReportItem> = vulnerabilities
            .iter()
            .map(|v| VulnReportItem {
                title: v.title.clone(),
                severity: v.severity.clone(),
                file_dir: v.file_path.clone(),
            })
            .collect();

        let data_str = match serde_json::to_string(&items) {
            Ok(s) => s,
            Err(e) => {
                log_error!("[VulnScan] 序列化失败: {}", e);
                return Ok(Response::new(PutVulnScanResponse {
                    success: false,
                    message: format!("序列化失败: {}", e),
                }));
            }
        };

        let json_obj = serde_json::json!({
            "start_at": start_at,
            "end_at": end_at,
            "vuln_total": vuln_total,
            "vuln_list": data_str
        });
        let json_str = match serde_json::to_string(&json_obj) {
            Ok(s) => s,
            Err(e) => {
                log_error!("[VulnScan] JSON 构建失败: {}", e);
                return Ok(Response::new(PutVulnScanResponse {
                    success: false,
                    message: format!("JSON 构建失败: {}", e),
                }));
            }
        };

        log_info!("[VulnScan] 上报内容: {}", json_str);

        let url = format!("{}/v1/putVulnScan", self.base_url);
        let net_client = match net_client::core::NetClient::new(Some(self.base_url.clone()), true) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                log_error!("[VulnScan] 创建 NetClient 失败: {}", e);
                return Ok(Response::new(PutVulnScanResponse {
                    success: false,
                    message: format!("创建网络客户端失败: {}", e),
                }));
            }
        };

        let token = self.boot_manager.get_token().await;

        match net_client
            .post_data_async(&url, &json_str, Duration::from_secs(10), token.as_deref())
            .await
        {
            Ok(response) => {
                log_info!("[VulnScan] 上报成功，响应: {}", response);
                Ok(Response::new(PutVulnScanResponse {
                    success: true,
                    message: response,
                }))
            }
            Err(e) => {
                log_error!("[VulnScan] 上报失败: {}", e);
                Ok(Response::new(PutVulnScanResponse {
                    success: false,
                    message: format!("上报失败: {}", e),
                }))
            }
        }
    }
}
