// udisk/src/utils.rs
//use std::collections::HashMap;
//use once_cell::sync::Lazy;
//use std::sync::Mutex;
use crate::device::UsbInfo;
use logging::log_info;
use md5;
use std::io::{Read, Write};
use std::path::Path;


pub fn md5sum(input: &str) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
}

pub fn read_sysfs_string(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .trim()
        .to_string()
}

pub fn has_mass_storage_interface(dev_path: &Path) -> bool {
    if let Ok(entries) = std::fs::read_dir(dev_path) {
        for entry in entries.flatten() {
            let sub = entry.path();
            if sub.is_dir() {
                let class_path = sub.join("bInterfaceClass");
                if class_path.exists() && read_sysfs_string(&class_path).trim() == "08" {
                    return true;
                }
            }
        }
    }
    false
}

pub fn sysfs_device_name(device: &rusb::Device<rusb::Context>) -> String {
    let bus = device.bus_number();
    let ports = device.port_numbers().unwrap_or_default();
    if ports.is_empty() {
        return format!("{}", bus);
    }
    let ports_str = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(".");
    format!("{}-{}", bus, ports_str)
}

pub fn disable_usb_device(device: &rusb::Device<rusb::Context>) -> rusb::Result<()> {
    let sysfs_name = sysfs_device_name(device);
    let auth_path = format!("/sys/bus/usb/devices/{}/authorized", sysfs_name);
    let path = std::path::Path::new(&auth_path);

    for _ in 0..5 {
        if path.exists() {
            if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(&path) {
                if file.write_all(b"0").is_ok() {
                    log::info!("USB device disabled via {}", auth_path);
                    return Ok(());
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(rusb::Error::Other)
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
            manufacturer
        };
        let serial_id = if serial.is_empty() {
            format!("vid{}_pid{}", vendor, product)
        } else {
            serial
        };
        log_info!("get all=========={}_{}_{}", serial_id, product, vendor);
        let eid = crate::utils::generate_eid(&vendor, &product, &serial_id);
        let authorized = read_sysfs_string(&path.join("authorized")).trim() == "1";

        devices.push(UsbInfo {
            perpheral_eid: eid,
            perpheral_name: name.clone(),
            intro: name,
            type_: "usb_mass_storage".to_string(),
            allow: authorized,
        });
    }

    devices
}

/*
// 全局设备缓存
static DEVICE_CACHE: Lazy<Mutex<HashMap<String, UsbInfo>>> = Lazy::new(|| {
    Mutex::new(HashMap::new())
});

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

    let mut current_device_eids = Vec::new();

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
            manufacturer
        };

        let serial_id = if serial.is_empty() {
            format!("vid{}_pid{}", vendor, product)
        } else {
            serial
        };

        let eid = crate::utils::generate_eid(&vendor, &product, &serial_id);
        current_device_eids.push(eid.clone());

        let authorized_str = read_sysfs_string(&path.join("authorized"));
        let authorized = authorized_str.trim() == "1";

        let usb_info = UsbInfo {
            perpheral_eid: eid.clone(),
            perpheral_name: name.clone(),
            intro: name,
            type_: "usb_mass_storage".to_string(),
            allow: authorized,
        };

        // 更新缓存
        {
            let mut cache = DEVICE_CACHE.lock().unwrap();
            cache.insert(eid.clone(), usb_info.clone());
        }

        devices.push(usb_info);
    }

    // 🔥 从缓存中获取之前见过但当前不可见的设备（可能是被阻断的）
    {
        let cache = DEVICE_CACHE.lock().unwrap();
        for (eid, usb_info) in cache.iter() {
            if !current_device_eids.contains(eid) && !devices.iter().any(|d| d.perpheral_eid == *eid) {
                // 设备在缓存中但当前不可见，可能是被阻断了
                let mut blocked_device = usb_info.clone();
                blocked_device.allow = false;  // 标记为未授权
                devices.push(blocked_device);
            }
        }
    }

    devices
}
*/
// 在 utils.rs 中
pub fn generate_eid(vendor: &str, product: &str, serial: &str) -> String {
    let serial_id = if serial.is_empty() {
        format!("vid{}_pid{}", vendor, product)
    } else {
        serial.to_string()
    };
    //md5sum(&format!("{}_{}_{}", serial_id, product, vendor))
    md5sum(&format!("{}_{}",  product, vendor))
}
