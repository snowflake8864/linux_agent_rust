//crates/config/src/net_info.rs
use configparser::ini::Ini;

use std::fs;
use std::fs::File;
use std::io::{self, Write};
use hostinfo::system_info::SystemInfo;
use hostinfo::{ip_mac, agent_uid};
#[derive(Debug, Default, Clone)]
pub struct NetInfoConfig {
    pub mid: String,  // MID 字段
    pub ver: String,  
    pub com_time: u32,
    pub cron_time: u32,
    pub extortion_protect: bool,
    pub extortion_switch: bool,
    pub self_protect_switch: u32,
    pub fast_time: u32,
    pub file_protect: bool,
    pub file_switch: bool,
    pub dynamic_switch: bool,
    pub log_ip_port: Option<String>,
    pub log_proto: u32,
    pub log_sent: u32,
    pub cli_port: u32,
    pub module_switch: u32,
    pub open_port_switch: bool,
    pub proc_protect: bool,
    pub proc_switch: bool,
    pub scan_file_time: u32,
    pub scan_proc_time: u32,
    pub server_ip_port: String,
    pub server_ip: String,
    pub server_port: u32,
    pub usb_protect: bool,
    pub usb_switch: bool,
    pub syslog_dns_switch: bool,
    pub syslog_outer_switch: bool,
    pub syslog_inner_switch: bool,
    pub syslog_process_switch:bool,
    pub internet_switch: bool,
    pub user_id: String,  // USER_ID 字段
//=====host info
    pub dev_uid: String,  
    pub macid: String,  
    pub ips: String,  
    //pub _type: u32,  
    pub os: String,  
    pub memsize: String,  
    pub cpu: String,  
    pub hdsize: String,  
    pub auth: String,  
    pub host_name: String,  
    pub mod_ver: String,
    pub arch_type: String,
}
enum NetRule<'a> {
    ServerIpV4(&'a str),
    ServerPort(u32),
    LogIpPort(&'a str),
    VirtualOpenPort(bool),
}
fn ip_str_to_u32(ip: &str) -> Result<u32, String> {
    let parsed = ip.parse::<std::net::Ipv4Addr>().map_err(|e| e.to_string())?;
    Ok(u32::from_be_bytes(parsed.octets()))
}
impl NetInfoConfig {

    fn write_net_rule(&self, rule: NetRule) -> Result<(), String> {
        match rule {
            NetRule::ServerIpV4(ip) => {
                let ip_u32 = match ip_str_to_u32(ip) {
                    Ok(ip) => ip,
                    Err(e) => return Err(e),
                };
                self.write_raw("server_ipv4 ", &ip_u32.to_string())
            }
            NetRule::ServerPort(port) => {
                self.write_raw("server_port ", &port.to_string())
            }
            NetRule::LogIpPort(log_ip_port) => {
                self.write_raw("log_ip_port ", log_ip_port)
            }
            NetRule::VirtualOpenPort(open_port_state) => {
                self.write_raw("vir_open_port_switch ", if open_port_state { "1" } else { "0" })
            }
        }
    }

    fn write_raw(&self, rule_type: &str, value: &str) -> Result<(), String> {
        let content = format!("{} {}\n", rule_type, value);
        fs::write("/proc/osec/net_rules", content)
            .map_err(|e| format!("Failed to write to /proc/osec/net_rules: {}", e))
    }
    pub fn from_ini(ini: &Ini) -> Self {
        let mut config = NetInfoConfig::default();

        if let Some(mid) = ini.get("CLIENTINFO", "MID") {
            config.mid = mid; // MID 存储到 mid 字段
        }
        /*
        if let Some(value) = ini.get("SERVERINFO", "VERSION") {
            config.ver = value.parse().unwrap_or_default();
        }
        */
        config.ver = ini.get("SERVERINFO", "VERSION")
            .unwrap_or_else(|| "3.0.1_T9".to_string());

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
        if let Some(value) = ini.get("SERVERINFO", "DYNAMIC_SWITCH") {
            config.dynamic_switch = value.parse().unwrap_or_default();
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
            let _ = config.write_net_rule(NetRule::VirtualOpenPort(config.open_port_switch));
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

        if let Some(value) = ini.get("SERVERINFO", "DNS_SWITCH") {
            config.syslog_dns_switch = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "INTERNAL_COMMUNICATION_SWITCH") {
            config.syslog_inner_switch = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "EXTERNAL_COMMUNICATION_SWITCH") {
            config.syslog_outer_switch = value.parse().unwrap_or_default();
        }

        if let Some(value) = ini.get("SERVERINFO", "INTERNET_SWITCH") {
            config.internet_switch = value.parse().unwrap_or_default();
        }

        if let Some(value) = ini.get("SERVERINFO", "SYSLOG_PROCESS_SWITCH") {
            config.syslog_process_switch = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("HOSTINFO", "DEV_UID") {
            config.dev_uid = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("HOSTINFO", "MACID") {
            config.macid = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("HOSTINFO", "IPS") {
            config.ips = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("HOSTINFO", "OS") {
            config.os = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("HOSTINFO", "MEMSIZE") {
            config.memsize = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("HOSTINFO", "CPU") {
            config.cpu = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("HOSTINFO", "HDSIZE") {
            config.hdsize = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("HOSTINFO", "AUTH") {
            config.auth = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("HOSTINFO", "HOSTNAME") {
            config.host_name = value.parse().unwrap_or_default();
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
        writeln!(file, "EXTORTION_PROTECT={}", self.extortion_protect as u8)?;
        writeln!(file, "EXTORTION_SWITCH={}", self.extortion_switch as u8)?;
        writeln!(file, "FASTTIME={}", self.fast_time)?;
        writeln!(file, "FILE_PROTECT={}", self.file_protect as u8)?;
        writeln!(file, "FILE_SWITCH={}", self.file_switch as u8)?;
        writeln!(file, "LOGIPPORT={}", self.log_ip_port.clone().unwrap_or_default())?;
        writeln!(file, "LOGPROTO={}", self.log_proto)?;
        writeln!(file, "LOGSENT={}", self.log_sent)?;
        writeln!(file, "MODULE_SWITCH={}", self.module_switch)?;
        writeln!(file, "OPEN_PORT_SWITCH={}", self.open_port_switch as u8)?;
        writeln!(file, "PROC_PROTECT={}", self.proc_protect as u8)?;
        writeln!(file, "PROC_SWITCH={}", self.proc_switch as u8)?;
        writeln!(file, "DYNAMIC_SWITCH={}", self.dynamic_switch as u8)?;
        writeln!(file, "SCANFILETIME={}", self.scan_file_time)?;
        writeln!(file, "SCANPROCTIME={}", self.scan_proc_time)?;
        writeln!(file, "SERVERIPPORT={}", self.server_ip_port)?;
        writeln!(file, "SERVER_IP={}", self.server_ip)?;
        writeln!(file, "SERVER_PORT={}", self.server_port)?;
        writeln!(file, "USB_PROTECT={}", self.usb_protect as u8)?;
        writeln!(file, "USB_SWITCH={}", self.usb_switch as u8)?;
        writeln!(file, "DNS_SWITCH={}", self.syslog_dns_switch as u8)?;
        writeln!(file, "INTERNAL_COMMUNICATION_SWITCH={}", self.syslog_outer_switch as u8)?;
        writeln!(file, "EXTERNAL_COMMUNICATION_SWITCH={}", self.syslog_inner_switch as u8)?;
        writeln!(file, "SYSLOG_PROCESS_SWITCH={}", self.syslog_process_switch as u8)?;
        writeln!(file, "PROC_SWITCH={}", self.proc_switch as u8)?;

        writeln!(file, "INTERNET_SWITCH={}", self.internet_switch as u8)?;
        writeln!(file, "VERSION={}", self.ver)?;
        writeln!(file, "[HOSTINFO]")?;
        writeln!(file, "DEV_UID={}", self.dev_uid)?;
        writeln!(file, "MACID={}", self.macid)?;
        /*
        writeln!(file, "IPS={}", self.ips)?;
        writeln!(file, "VERSION={}", self.ver)?;
        writeln!(file, "OS={}", self.os)?;
        writeln!(file, "MEMSIZE={}", self.memsize)?;
        writeln!(file, "CPU={}", self.cpu)?;
        writeln!(file, "HDSIZE={}", self.hdsize)?;
        writeln!(file, "AUTH={}", self.auth)?;
        writeln!(file, "HOSTNAME={}", self.host_name)?;
        */
        Ok(())
    }

    /// 获取系统主机信息以填充 HOSTINFO 字段
    pub fn acquire_host_info(&mut self) -> io::Result<()> {
        if self.dev_uid.is_empty() {
             self.dev_uid = agent_uid::ensure_and_get_mgs_guid(".vedasystem").unwrap_or_else(|_| "unknown".to_string());
        }
        if self.macid.is_empty() {
             self.macid = ip_mac::get_mac().unwrap_or("unknown".to_string());
        }

        // HOSTNAME
        if self.host_name.is_empty() {
            //let computer_name = system_info::SystemInfo::get_computer_name().unwrap_or_else(|_| "Unknown".to_string());
            self.host_name = SystemInfo::get_computer_name().unwrap_or_else(|_| "Unknown".to_string());
        }
        // auth
        if self.auth.is_empty() {
;
            self.auth = "123123".to_string();
        }

        // OS
        if self.os.is_empty() {
;
            self.os = SystemInfo::get_computer_version().unwrap_or_else(|_| "Unknown".to_string());
        }


        // CPU
        if self.cpu.is_empty() {
            self.cpu = SystemInfo::get_cpu_cores().unwrap_or_else(|_| "Unknown".to_string());
        }

        // MEMSIZE (以 GB 为单位)
        if self.memsize.is_empty() {
            self.memsize = SystemInfo::get_memory_size().unwrap_or_else(|_| "Unknown".to_string());
        }

        // HDSIZE (以 GB 为单位)
        if self.hdsize.is_empty() {
            self.hdsize = SystemInfo::get_disk_size().unwrap_or_else(|_| "Unknown".to_string());
        }

        // IPS
        if self.ips.is_empty() {
             self.ips = ip_mac::get_ip().unwrap_or("unknown".to_string());
        }
        // IPS
        Ok(())
    }
}

use once_cell::sync::Lazy;
use std::path::Path;
use std::sync::Mutex;
// 全局配置
pub static NETINFO_CONFIG: Lazy<Mutex<NetInfoConfig>> = Lazy::new(|| {
    let config_path = std::env::var("CONFIG_PATH")
        .ok()
        .or_else(|| Some("/opt/osec/net_info.ini".to_string()));
    let mut ini = Ini::new();
    if let Some(path) = config_path {
        if Path::new(&path).exists() {
            ini.load(&path).unwrap_or_else(|err| {
                eprintln!("Failed to load configuration file from '{}': {}", path, err);
                std::process::exit(1);
            });
        } else {
            eprintln!("Configuration file '{}' does not exist", path);
            std::process::exit(1);
        }
    }
    Mutex::new(NetInfoConfig::from_ini(&ini))
});
