use std::pin::Pin;
use common::
    manager::boot::BootManager;
use std::future::Future;
use tokio::time::{interval, Duration};
use tokio::sync::mpsc;
use crate::AuditLogInfo;
use crate::build_alert_log_json;
use logging::{log_info,log_error};
use net_client::core::NetClient;


pub trait StartBashLog {
    fn start_log_services(&mut self,  file_audit_log_rx: mpsc::Receiver<AuditLogInfo>) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>;
}

impl StartBashLog for BootManager {
    fn start_log_services(
        &mut self,
        mut file_audit_log_rx: mpsc::Receiver<AuditLogInfo>,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {
            let mut log_buffer: Vec<AuditLogInfo> = Vec::new();
            let mut interval = interval(Duration::from_secs(30));
            let base_url = self.get_base_url();
            let net_client = match NetClient::new(Some(base_url), true) {
                Ok(client) => client,
                Err(err) => {
                    eprintln!("创建 NetClient 失败: {}", err);
                    return Err("创建 NetClient 失败".to_string());
                }
            };

            let url = format!("{}/v1/alertupload", net_client.get_base_url().unwrap_or_default());
            loop {
                tokio::select! {
                    result = file_audit_log_rx.recv() => {
                        match result {
                            Some(log) => {
                                //log_info!("收到 FileAuditLogInfo: {:?}", log);
                                /*         
                                // 检测是否为外设告警日志类型 (9003, 9004, 9005, 9006)
                                let is_peripheral_alert = matches!(log.n_type, 9003 | 9004 | 9005 | 9006);
                                
                                if is_peripheral_alert {
                                    log_info!("检测到外设告警，触发重新上传外设列表");
                                    upload_usb_devices_to_server(&net_client, &url, self).await;
                                }
                                */
                                log_buffer.push(log.clone());
                                /*log_info!("[上报] 📥 收到告警 n_type={} buffer={}/512",
                                    log.n_type, log_buffer.len());*/
                                crate::broadcast_audit_log(&log);
                            }
                            None => {
                                log_error!("file_audit_log_rx 通道已关闭，退出任务。");
                                break;
                            }
                        }
                    }
                    _ = interval.tick() => {
                        if !log_buffer.is_empty() {
                            let mut json_str = String::new();
                            match build_alert_log_json(&log_buffer, &mut json_str) {
                                Ok(()) => {
                                    /*log_info!("[上报] 📤 URL={} JSON({}条)={}",
                                        url, log_buffer.len(), json_str);*/
                                    match net_client.post_data_async(
                                        &url,
                                        &json_str,
                                        Duration::from_secs(10),
                                        self.get_token().await.as_deref(),
                                    ).await {
                                        Ok(response) => {
                                            log_info!("[上报] ✅ HTTP 200({}条) resp={}",
                                                log_buffer.len(), response);
                                        },
                                        Err(err) => log_error!("[上报] ❌ HTTP 失败: {}", err),
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

            // 处理剩余告警
            if !log_buffer.is_empty() {
                let mut json_str = String::new();
                match build_alert_log_json(&log_buffer, &mut json_str) {
                    Ok(()) => {
                        log_info!("[上报] 📤 (shutdown) URL={} JSON({}条)={}",
                            url, log_buffer.len(), json_str);
                        match net_client.post_data_async(
                            &url,
                            &json_str,
                            Duration::from_secs(10),
                            self.get_token().await.as_deref(),
                        ).await {
                            Ok(response) => {
                                log_info!("[上报] ✅ (shutdown) HTTP 200({}条) resp={}",
                                    log_buffer.len(), response);
                            },
                            Err(err) => log_error!("[上报] ❌ (shutdown) HTTP 失败: {}", err),
                        }

                        log_buffer.clear(); // 清空缓冲区
                    }
                    Err(e) => {
                        log_error!("构建 JSON 失败: {}", e);
                    }
                }
            }

            Ok("后台告警任务正常退出".to_string())
        })
    }
}

// 独立的USB设备上传函数
async fn upload_usb_devices_to_server(net_client: &NetClient, alert_url: &str, boot_mgr: &BootManager) {
    // 从alert_url构造USB上传URL
    let base_url = net_client.get_base_url().unwrap_or_default();
    let usb_url = format!("{}/v1/addperipherals", base_url);
    
    // 简单的USB设备扫描实现
    let mut devices = Vec::new();
    
    // 扫描 /sys/bus/usb/devices 目录
    if let Ok(entries) = std::fs::read_dir("/sys/bus/usb/devices") {
        for entry in entries.flatten() {
            let path = entry.path();
            
            // 读取 vid 和 pid
            let vendor = std::fs::read_to_string(path.join("idVendor")).unwrap_or_default();
            let product = std::fs::read_to_string(path.join("idProduct")).unwrap_or_default();
            
            if vendor.is_empty() || product.is_empty() {
                continue;
            }
            
            // 检查是否为存储设备
            let dev_class = std::fs::read_to_string(path.join("bDeviceClass")).unwrap_or_default();
            let is_storage = dev_class.trim() == "08" || path.join("bInterfaceClass").exists();
            
            if !is_storage {
                continue;
            }
            
            // 读取设备信息
            let manufacturer = std::fs::read_to_string(path.join("manufacturer"))
                .unwrap_or_else(|_| format!("vid{}_pid{}", vendor.trim(), product.trim()));
            let serial = std::fs::read_to_string(path.join("serial"))
                .unwrap_or_else(|_| format!("vid{}_pid{}", vendor.trim(), product.trim()));
            
            let name = manufacturer.trim().to_string();
            let eid = format!("{}_{}_{}", vendor.trim(), product.trim(), serial.trim());
            
            devices.push(serde_json::json!({
                "peripheral_eid": eid,
                "peripheral_name": name,
                "peripheral_intro": name,
                "peripheral_type": "usb_mass_storage"
            }));
        }
    }
    
    if !devices.is_empty() {
        let data_str = serde_json::to_string(&devices).unwrap_or_default();
        let json_obj = serde_json::json!({ "data": data_str });
        let json_str = serde_json::to_string(&json_obj).unwrap_or_default();
        
        log_info!("上传USB设备列表，设备数量: {}", devices.len());
        
        match net_client.post_data_async(
            &usb_url,
            &json_str,
            Duration::from_secs(10),
            boot_mgr.get_token().await.as_deref(),
        ).await {
            Ok(response) => log_info!("USB设备上传响应: {}", response),
            Err(err) => log_error!("USB设备上传失败: {}", err),
        }
    } else {
        log_info!("未发现USB存储设备");
    }
}

