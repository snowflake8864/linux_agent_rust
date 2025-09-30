// udisk/src/monitor.rs
use std::pin::Pin;
use common::
    manager::boot::BootManager;
use std::future::Future;

use net_client::core::NetClient;
use logging::{log_info,log_debug,log_error};

use crate::device::UsbInfo;
use crate::list::{SharedBlackWhiteList, SHARED_USB_LIST,DeviceListStatus};
use crate::utils::{disable_usb_device, has_mass_storage_interface, read_sysfs_string};
use rusb::{Context, Device, HotplugBuilder, UsbContext};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use config::net_info::NETINFO_CONFIG;
use std::io::{Read, Write};
use std::collections::HashMap;
use once_cell::sync::Lazy;
use std::sync::Mutex;
use tokio::sync::mpsc;
use reporter::AuditLogInfo;
// 缓存 eid 到设备信息的映射
static EID_TO_DEVICE_INFO: Lazy<Mutex<HashMap<String, UsbInfo>>> = Lazy::new(|| {
    Mutex::new(HashMap::new())
});

// 更新设备缓存
pub fn update_device_cache(devices: &[UsbInfo]) {
    let mut eid_map = EID_TO_DEVICE_INFO.lock().unwrap();
    eid_map.clear();
    
    for device in devices {
        eid_map.insert(device.perpheral_eid.clone(), device.clone());
    }
}
fn read_device_info_from_sysfs(vid: u16, pid: u16, serial_hint: &str) -> Option<(String, String)> {
    let sysfs_dir = Path::new("/sys/bus/usb/devices");
    let vendor_str = format!("{:04x}", vid);
    let product_str = format!("{:04x}", pid);

    if let Ok(entries) = std::fs::read_dir(sysfs_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let vendor = read_sysfs_string(&path.join("idVendor"));
            let product = read_sysfs_string(&path.join("idProduct"));

            if vendor != vendor_str || product != product_str {
                continue;
            }

            let manufacturer = read_sysfs_string(&path.join("manufacturer"));
            let serial = read_sysfs_string(&path.join("serial"));

            let name = if manufacturer.is_empty() {
                format!("vid{:04x}_pid{:04x}", vid, pid)
            } else {
                manufacturer
            };

            let actual_serial = if serial.is_empty() {
                format!("vid{:04x}_pid{:04x}", vid, pid)
            } else {
                serial
            };

            return Some((name, actual_serial));
        }
    }

    None
}
pub struct UsbMonitor {
    shared_list: SharedBlackWhiteList,
    seen_devices: Arc<std::sync::Mutex<Vec<String>>>,
    usb_audit_log_tx: mpsc::Sender<AuditLogInfo>,
}

impl UsbMonitor {
    pub fn new(shared_list: SharedBlackWhiteList, usb_audit_log_tx: mpsc::Sender<AuditLogInfo>) -> Result<Self, rusb::Error> {
        Ok(UsbMonitor {
            shared_list,
            seen_devices: Arc::new(std::sync::Mutex::new(Vec::new())),
            usb_audit_log_tx,
        })
    }

    pub fn run(self) -> Result<(), rusb::Error> {
        let context = Context::new()?;
        let callback = HotplugCallback {
            shared_list: self.shared_list,
            seen_devices: self.seen_devices,
            usb_audit_log_tx: self.usb_audit_log_tx,

        };

        let _registration = HotplugBuilder::new()
            .enumerate(true)
            .register(&context, Box::new(callback))?;

        log::info!("USB 监控已启动，等待设备事件...");

        loop {
            context.handle_events(Some(Duration::from_millis(100)))?;
        }
    }
}

struct HotplugCallback {
    shared_list: SharedBlackWhiteList,
    seen_devices: Arc<std::sync::Mutex<Vec<String>>>,
    usb_audit_log_tx: mpsc::Sender<AuditLogInfo>,
}

impl rusb::Hotplug<Context> for HotplugCallback {
    fn device_arrived(&mut self, device: Device<Context>) {
        let cfg = NETINFO_CONFIG.lock().unwrap();
         if !cfg.usb_switch {
             return;
         }
        let usb_protect = cfg.usb_protect;
        let desc = match device.device_descriptor() {
            Ok(d) => d,
            Err(e) => {
                log::error!("无法读取设备描述符: {:?}", e);
                return;
            }
        };

        let is_storage = is_usb_storage(&device, &desc);
        log::info!(
            "USB 设备插入: vid={:04x}, pid={:04x}, class={:02x}, is_storage={}",
            desc.vendor_id(),
            desc.product_id(),
            desc.class_code(),
            is_storage
        );

        if !is_storage {
            log::debug!("忽略非存储设备 class={:02x}", desc.class_code());
            return;
        }

        let vid = desc.vendor_id();
        let pid = desc.product_id();
        let vendor_str = format!("{:04x}", vid);
        let product_str = format!("{:04x}", pid);
        /*
        let serial = device
            .open()
            .and_then(|h| h.read_serial_number_string_ascii(&desc))
            .unwrap_or_else(|_| format!("vid{:04x}_pid{:04x}", vid, pid));
        let name = device
            .open()
            .and_then(|h| h.read_manufacturer_string_ascii(&desc))
            .unwrap_or_else(|_| format!("vid{:04x}_pid{:04x}", vid, pid));
*/
        let serial_from_usb = device
            .open()
            .and_then(|h| h.read_serial_number_string_ascii(&desc))
            .ok(); 
        let (name, serial) = read_device_info_from_sysfs(vid, pid, serial_from_usb.as_deref().unwrap_or(""))
            .unwrap_or_else(|| {
                // fallback：如果 sysfs 也失败，用 rusb 读 name
                let name = device
                    .open()
                    .and_then(|h| h.read_manufacturer_string_ascii(&desc))
                    .unwrap_or_else(|_| format!("vid{:04x}_pid{:04x}", vid, pid));
                let serial = serial_from_usb.unwrap_or_else(|| format!("vid{:04x}_pid{:04x}", vid, pid));
                (name, serial)
            });
         let eid = crate::utils::generate_eid(&vendor_str, &product_str, &serial);


        {
            let mut seen = self.seen_devices.lock().unwrap();
            if !seen.contains(&eid) {
                seen.push(eid.clone());
                log::debug!("新 USB 存储设备: eid={}, name={}", eid, name);
            }
        }

        let list = self.shared_list.lock().unwrap();
        let status = list.get_device_list_status(&eid);
        match status {
            DeviceListStatus::InWhitelist => {log::info!("已允许 USB 设备: {} (eid={})", name, eid);},
            DeviceListStatus::InBlacklist => {

                let mut log = AuditLogInfo {
                    file_path: None,
                    rename_dir: None,
                    exception_process: None,
                    md5: None,
                    n_type: 9004,
                    n_level: 3,
                    n_time: 1692760326, // 应替换为实际时间戳
                    notice_remark: None,
                    peripheral_name: Some(name.to_string()), 
                    peripheral_remark: Some(name.to_string()),
                    peripheral_eid: Some(eid.to_string()),
                    p_param: None,
                };


                if usb_protect {
                    log.n_type = 9006;
                    if disable_usb_device(&device).is_ok() {
                        log::error!("已阻止 USB 设备: {} (eid={})", name, eid);
                    } else {
                        log::error!("阻止失败 (无权限?): {} (eid={})", name, eid);
                    }

                }
                let tx = self.usb_audit_log_tx.clone();

                // 使用 spawn_blocking 将 send 操作交给 Tokio 运行时线程执行
                tokio::task::spawn_blocking(move || {
                    match tx.try_send(log) {
                        Ok(()) => {
                            log_info!("[USB-MONITOR] 审计日志已安全发送");
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            log_error!("[USB-MONITOR] 审计日志通道已满，请加快消费速度");
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            log_error!("[USB-MONITOR] 审计日志通道已关闭！接收方已退出");
                        }
                    }
                });

            },
            DeviceListStatus::NotInAnyList => {

                let mut log = AuditLogInfo {
                    file_path: None,
                    rename_dir: None,
                    exception_process: None,
                    md5: None,
                    n_type: 9003,
                    n_level: 3,
                    n_time: 1692760326, 
                    notice_remark: None,
                    peripheral_name: Some(name.to_string()), 
                    peripheral_remark: Some(name.to_string()),
                    peripheral_eid: Some(eid.to_string()),
                    p_param: None,
                };


                if usb_protect {
                    log.n_type = 9005;
                    if disable_usb_device(&device).is_ok() {
                        log::error!("已阻止 USB 设备: {} (eid={})", name, eid);
                    } else {
                        log::error!("阻止失败 (无权限?): {} (eid={})", name, eid);
                    }
                }

                let tx = self.usb_audit_log_tx.clone();

                // 使用 spawn_blocking 将 send 操作交给 Tokio 运行时线程执行
                tokio::task::spawn_blocking(move || {
                    match tx.try_send(log) {
                        Ok(()) => {
                            log_info!("[USB-MONITOR] 审计日志已安全发送");
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            log_error!("[USB-MONITOR] 审计日志通道已满，请加快消费速度");
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            log_error!("[USB-MONITOR] 审计日志通道已关闭！接收方已退出");
                        }
                    }
                });


            },
        }
    }

    fn device_left(&mut self, device: Device<Context>) {
        let desc = match device.device_descriptor() {
            Ok(d) => d,
            Err(_) => return,
        };
        let vid = desc.vendor_id();
        let pid = desc.product_id();
        let vendor_str = format!("{:04x}", vid);
        let product_str = format!("{:04x}", pid);
        let serial = device
            .open()
            .and_then(|h| h.read_serial_number_string_ascii(&desc))
            .unwrap_or_default();

        let eid = crate::utils::generate_eid(&vendor_str, &product_str, &serial);
        let mut seen = self.seen_devices.lock().unwrap();
        seen.retain(|e| e != &eid);
        log::debug!("USB 设备拔出: eid={}", eid);
    }
}

fn is_usb_storage(device: &Device<Context>, desc: &rusb::DeviceDescriptor) -> bool {
    let device_class = desc.class_code();
    if device_class == 0x08 {
        return true;
    }

    match device.active_config_descriptor() {
        Ok(config) => {
            config.interfaces().flat_map(|i| i.descriptors()).any(|d| d.class_code() == 0x08)
        }
        Err(_) => false,
    }
}

pub fn get_all_local_usb_devices() -> Vec<UsbInfo> {
    let mut devices = Vec::new();
    let sysfs_dir = Path::new("/sys/bus/usb/devices");

    let entries = match std::fs::read_dir(sysfs_dir) {
        Ok(e) => e,
        Err(e) => {
            log::error!("无法读取 /sys/bus/usb/devices: {:?}", e);
            return devices;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let vendor = read_sysfs_string(&path.join("idVendor"));
        let product = read_sysfs_string(&path.join("idProduct"));
        if vendor.is_empty() || product.is_empty() {
            continue;
        }

        let dev_class = read_sysfs_string(&path.join("bDeviceClass"));
        let is_storage = dev_class.trim() == "08" || has_mass_storage_interface(&path);
        if !is_storage {
            continue;
        }

        let manufacturer = read_sysfs_string(&path.join("manufacturer"));
        let serial = read_sysfs_string(&path.join("serial"));
        let name = if manufacturer.is_empty() {
            format!("vid{}_pid{}", vendor, product)
        } else {
            manufacturer.clone()
        };
        let serial_id = if serial.is_empty() {
            format!("vid{}_pid{}", vendor, product)
        } else {
            serial
        };
        let eid = crate::utils::generate_eid(&vendor, &product, &serial_id);

        let authorized = read_sysfs_string(&path.join("authorized")).trim() == "1";

        devices.push(UsbInfo::new(
            eid,
            name.clone(),
            name,
            "usb_mass_storage".to_string(),
            authorized,
        ));
    }
    
    update_device_cache(&devices);

    devices
}
fn disable_device_via_sysfs(target_eid: &str) -> bool {
    let sysfs_dir = Path::new("/sys/bus/usb/devices");
    
    if let Ok(entries) = std::fs::read_dir(sysfs_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let vendor = read_sysfs_string(&path.join("idVendor"));
            let product = read_sysfs_string(&path.join("idProduct"));
            
            if vendor.is_empty() || product.is_empty() {
                continue;
            }
            
            let serial = read_sysfs_string(&path.join("serial"));
            let serial_id = if serial.is_empty() {
                format!("vid{}_pid{}", vendor, product)
            } else {
                serial
            };
            
            let eid = crate::utils::generate_eid(&vendor, &product, &serial_id);
            
            if eid == target_eid {
                let auth_path = path.join("authorized");
                if auth_path.exists() {
                    // 重试几次确保写入成功
                    for _ in 0..3 {
                        if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(&auth_path) {
                            if file.write_all(b"0").is_ok() {
                                log_info!("通过 sysfs 成功禁用设备: eid={}", target_eid);
                                return true;
                            }
                        }
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
                log_error!("无法写入 authorized 文件: {}", auth_path.display());
                break;
            }
        }
    }
    
    false
}

pub fn handle_blacklist_update(blacklist_eids: &[String]) -> Vec<String> {
    let mut disabled_devices = Vec::new();
    
    for eid in blacklist_eids {
        log_info!("检查是否需要禁用设备: eid={}", eid);
        if disable_device_via_sysfs(eid) {
            disabled_devices.push(eid.clone());
            log_info!("已禁用设备: eid={}", eid);
        }
    }
    
    if !disabled_devices.is_empty() {
        log_info!("总共禁用了 {} 个设备", disabled_devices.len());
    }
    
    disabled_devices
}
pub fn build_usb_json(devices: &[UsbInfo], output: &mut String) -> Result<(), String> {
    #[derive(serde::Serialize)]
    struct JsonItem<'a> {
        peripheral_eid: &'a str,
        peripheral_name: &'a str,
        peripheral_intro: &'a str,
        peripheral_type: &'a str,
    }

    let items: Vec<JsonItem> = devices
        .iter()
        .map(|d| JsonItem {
            peripheral_eid: &d.perpheral_eid,
            peripheral_name: &d.perpheral_name,
            peripheral_intro: &d.intro,
            peripheral_type: &d.type_,
        })
        .collect();

    let data_str = if items.is_empty() {
        "[]".to_string()
    } else {
        serde_json::to_string(&items).map_err(|e| format!("序列化失败: {}", e))?
    };

    let json_obj = serde_json::json!({ "data": data_str });
    *output = serde_json::to_string(&json_obj).map_err(|e| format!("最终序列化失败: {}", e))?;
    Ok(())
}


pub async fn upload_usb_info(
    devices: &[UsbInfo],
    net_client: &NetClient,
    url: &str,
    boot_mgr: &BootManager
) {

//    if devices.is_empty() {
//        log_info!("未发现可上传的 USB 设备");
//        return;
 //   }
    log_info!("发现 {} 台可上传的 USB 设备", devices.len());
    let mut json_str = String::new();

    match build_usb_json(&devices,  &mut json_str) {

        Ok(()) => {
            match net_client.post_data_async(
                &url,
                &json_str,
                Duration::from_secs(10),
                boot_mgr.get_token().await.as_deref(),
                None
            ).await {
                Ok(response) => {log_info!("服务器响应: {}", response)},
                Err(err) => eprintln!("发送指标失败: {}", err),
            }

            log_info!("========================生成 JSON: {}", json_str);
        }
        Err(e) => {
            log_error!("构建 JSON 失败: {}", e);
        }
    }

}


pub trait StartUsbService {
    fn start_usb_services(&mut self, usb_audit_log_tx: mpsc::Sender<AuditLogInfo>
        ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>;
}
impl StartUsbService for BootManager {
    fn start_usb_services(
        &mut self, usb_audit_log_tx: mpsc::Sender<AuditLogInfo>
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        let cfg = NETINFO_CONFIG.lock().unwrap();
        let app_path = Some(cfg.app_path.clone());
        Box::pin(async move {
            let base_url = self.get_base_url();
            let net_client = match NetClient::new(base_url, true,false, app_path) {
                Ok(client) => client,
                Err(err) => {
                    eprintln!("创建 NetClient 失败: {}", err);
                    return Err("创建 NetClient 失败".to_string());
                }
            };
            let url = format!("{}/v1/addperipherals", net_client.base_url);

            let current_devices = get_all_local_usb_devices();
            loop {

                if let Some(_) = self.get_token().await {
                    let devices = current_devices.clone();
                    upload_usb_info(&devices, &net_client, &url, self).await;
                    break;
                } else {
                    log_error!("token 尚未准备好，等待中...");
                    sleep(Duration::from_secs(2)).await;
                }
            }

            let monitor = UsbMonitor::new(SHARED_USB_LIST.clone(), usb_audit_log_tx)
                .map_err(|e| format!("创建监控器失败: {:?}", e))?;

            tokio::spawn(async move {
                if let Err(e) = monitor.run() {
                    log::error!("USB 监控运行失败: {:?}", e);
                }
            });
            Ok("USB服务正常退出".to_string())
        })
    }
}

