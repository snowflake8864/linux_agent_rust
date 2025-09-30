use std::pin::Pin;
use common::
    manager::boot::BootManager;
use std::future::Future;
use tokio::time::{interval, Duration};
use tokio::sync::mpsc;
use crate::AuditLogInfo;
use crate::{build_alert_log_json, serialize_alert_logs_to_json};
use logging::{log_info,log_error};
use net_client::core::NetClient;
use net_client::WriteMode;
use config::net_info::NETINFO_CONFIG;

pub trait StartBashLog {
    fn start_log_services(&mut self,  file_audit_log_rx: mpsc::Receiver<AuditLogInfo>) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>;
}

impl StartBashLog for BootManager {
    fn start_log_services(
        &mut self,
        mut file_audit_log_rx: mpsc::Receiver<AuditLogInfo>,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {

            let cfg = NETINFO_CONFIG.lock().unwrap(); // 这里使用 from_ini 解析配置
            let offline_mode = cfg.is_offline_mode;
            let app_path = Some(cfg.app_path.clone());
        Box::pin(async move {
            let mut log_buffer: Vec<AuditLogInfo> = Vec::new();
            let mut interval = interval(Duration::from_secs(30));
            let base_url = self.get_base_url();
            let net_client = match NetClient::new(base_url, true, offline_mode, app_path) {
                Ok(client) => client,
                Err(err) => {
                    eprintln!("创建 NetClient 失败: {}", err);
                    return Err("创建 NetClient 失败".to_string());
                }
            };

            let url = format!("{}/v1/alertupload", net_client.base_url);
            loop {
                tokio::select! {
                    result = file_audit_log_rx.recv() => {
                        match result {
                            Some(log) => {
                                //log_info!("收到 FileAuditLogInfo: {:?}", log);
                                log_buffer.push(log);
                            }
                            None => {
                                log_error!("file_audit_log_rx 通道已关闭，退出任务。");
                                break;
                            }
                        }
                    }

                    //serialize_alert_logs_to_json(log_info: &[AuditLogInfo], str_json: &mut String) -> Result<(), String> 
                    _ = interval.tick() => {
                        if !log_buffer.is_empty() {
                            let mut json_str = String::new();
                            if offline_mode {
                                match serialize_alert_logs_to_json(&log_buffer, &mut json_str) {
                                    Ok(()) => {
                                        log_info!("生成 JSON: {}", json_str);
                                        match net_client.post_data_write_async(
                                            &url,
                                            &json_str,
                                            Duration::from_secs(10),
                                            self.get_token().await.as_deref(),
                                            Some("alertupload.json"),
                                            Some(WriteMode::Append)
                                        ).await {
                                            Ok(response) => {log_info!("服务器响应: {}", response)},
                                            Err(err) => eprintln!("发送指标失败: {}", err),
                                        }

                                        log_buffer.clear(); // 清空缓冲区
                                    }
                                    Err(e) => {
                                        log_error!("构建 JSON 失败: {}", e);
                                    }
                                }
                            } else {
                                match build_alert_log_json(&log_buffer, &mut json_str) {
                                    Ok(()) => {
                                        //log_info!("生成 JSON: {}", json_str);
                                        match net_client.post_data_write_async(
                                            &url,
                                            &json_str,
                                            Duration::from_secs(10),
                                            self.get_token().await.as_deref(),
                                            Some("alertupload.json"),
                                            Some(WriteMode::Append)
                                        ).await {
                                            Ok(response) => {log_info!("服务器响应: {}", response)},
                                            Err(err) => eprintln!("发送指标失败: {}", err),
                                        }

                                        log_buffer.clear(); // 清空缓冲区
                                    }
                                    Err(e) => {
                                        log_error!("构建 JSON 失败: {}", e);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 处理剩余日志
            if !log_buffer.is_empty() {
                let mut json_str = String::new();
                match build_alert_log_json(&log_buffer, &mut json_str) {
                    Ok(()) => {
                        log_info!("生成 JSON: {}", json_str);
                        match net_client.post_data_write_async(
                            &url,
                            &json_str,
                            Duration::from_secs(10),
                            self.get_token().await.as_deref(),
                            Some("alertupload.json"),
                            Some(WriteMode::Append)
                        ).await {
                            //Ok(response) => println!("服务器响应: {}", response),
                            Ok(response) => {log_info!("服务器响应: {}", response)},
                            Err(err) => eprintln!("发送指标失败: {}", err),
                        }

                        log_buffer.clear(); // 清空缓冲区
                    }
                    Err(e) => {
                        log_error!("构建 JSON 失败: {}", e);
                    }
                }
            }

            Ok("后台日志任务正常退出".to_string())
        })
    }
}

