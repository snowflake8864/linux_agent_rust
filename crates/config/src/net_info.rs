use configparser::ini::Ini;
use std::fs::File;
use std::io::{self, Write};

#[derive(Debug, Default, Clone)]
pub struct NetInfoConfig {
    pub mid: String,  // MID 字段
    pub com_time: u32,
    pub cron_time: u32,
    pub extortion_protect: u32,
    pub extortion_switch: u32,
    pub fast_time: u32,
    pub file_protect: u32,
    pub file_switch: u32,
    pub log_ip_port: Option<String>,
    pub log_proto: u32,
    pub log_sent: u32,
    pub module_switch: u32,
    pub open_port_switch: u32,
    pub proc_protect: u32,
    pub proc_switch: u32,
    pub scan_file_time: u32,
    pub scan_proc_time: u32,
    pub server_ip_port: String,
    pub server_ip: String,
    pub server_port: u32,
    pub usb_protect: u32,
    pub usb_switch: u32,
    pub user_id: String,  // USER_ID 字段
}

impl NetInfoConfig {
    pub fn from_ini(ini: &Ini) -> Self {
        let mut config = NetInfoConfig::default();

        if let Some(mid) = ini.get("CLIENTINFO", "MID") {
            config.mid = mid; // MID 存储到 mid 字段
        }

        if let Some(user_id) = ini.get("SERVERINFO", "USER_ID") {
            config.user_id = user_id; // USER_ID 存储到 user_id 字段
        }

        if let Some(value) = ini.get("SERVERINFO", "COMTIME") {
            config.com_time = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "CRONTIME") {
            config.cron_time = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "EXTORTION_PROTECT") {
            config.extortion_protect = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "EXTORTION_SWITCH") {
            config.extortion_switch = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "FASTTIME") {
            config.fast_time = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "FILE_PROTECT") {
            config.file_protect = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "FILE_SWITCH") {
            config.file_switch = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "LOGIPPORT") {
            config.log_ip_port = Some(value);
        }
        if let Some(value) = ini.get("SERVERINFO", "LOGPROTO") {
            config.log_proto = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "LOGSENT") {
            config.log_sent = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "MODULE_SWITCH") {
            config.module_switch = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "OPEN_PORT_SWITCH") {
            config.open_port_switch = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "PROC_PROTECT") {
            config.proc_protect = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "PROC_SWITCH") {
            config.proc_switch = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "SCANFILETIME") {
            config.scan_file_time = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "SCANPROCTIME") {
            config.scan_proc_time = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "SERVERIPPORT") {
            config.server_ip_port = value;
        }
        if let Some(value) = ini.get("SERVERINFO", "SERVER_IP") {
            config.server_ip = value;
        }
        if let Some(value) = ini.get("SERVERINFO", "SERVER_PORT") {
            config.server_port = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "USB_PROTECT") {
            config.usb_protect = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "USB_SWITCH") {
            config.usb_switch = value.parse().unwrap_or_default();
        }

        config
    }
    pub fn to_ini(&self, file_name: &str) -> Result<(), io::Error> {
        let mut file = File::create(file_name)?;

        writeln!(file, "[CLIENTINFO]")?;
        writeln!(file, "MID={}", self.mid)?;
        writeln!(file, "[SERVERINFO]")?;
        writeln!(file, "USER_ID={}", self.user_id)?;
        writeln!(file, "COMTIME={}", self.com_time)?;
        writeln!(file, "CRONTIME={}", self.cron_time)?;
        writeln!(file, "EXTORTION_PROTECT={}", self.extortion_protect)?;
        writeln!(file, "EXTORTION_SWITCH={}", self.extortion_switch)?;
        writeln!(file, "FASTTIME={}", self.fast_time)?;
        writeln!(file, "FILE_PROTECT={}", self.file_protect)?;
        writeln!(file, "FILE_SWITCH={}", self.file_switch)?;
        writeln!(file, "LOGIPPORT={}", self.log_ip_port.clone().unwrap_or_default())?;
        writeln!(file, "LOGPROTO={}", self.log_proto)?;
        writeln!(file, "LOGSENT={}", self.log_sent)?;
        writeln!(file, "MODULE_SWITCH={}", self.module_switch)?;
        writeln!(file, "OPEN_PORT_SWITCH={}", self.open_port_switch)?;
        writeln!(file, "PROC_PROTECT={}", self.proc_protect)?;
        writeln!(file, "PROC_SWITCH={}", self.proc_switch)?;
        writeln!(file, "SCANFILETIME={}", self.scan_file_time)?;
        writeln!(file, "SCANPROCTIME={}", self.scan_proc_time)?;
        writeln!(file, "SERVERIPPORT={}", self.server_ip_port)?;
        writeln!(file, "SERVER_IP={}", self.server_ip)?;
        writeln!(file, "SERVER_PORT={}", self.server_port)?;
        writeln!(file, "USB_PROTECT={}", self.usb_protect)?;
        writeln!(file, "USB_SWITCH={}", self.usb_switch)?;

        Ok(())
    }

}

