//crates/config/src/net_info.rs
use configparser::ini::Ini;
use std::fs;
use std::fs::File;
use std::io::{self, Write};
use std::process::Command;
use hostinfo::system_info::SystemInfo;
use hostinfo::{ip_mac, agent_uid};
use logging::{log_info, log_error};

#[derive(Debug, Default, Clone)]
pub struct NetInfoConfig {
    pub app_path: String,
    pub mid: String,
    pub ver: String,
    pub com_time: u32,
    pub cron_time: u32,
    pub extortion_protect: bool,
    pub extortion_switch: bool,
    pub self_protect_switch: bool,
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
    pub syslog_process_switch: bool,
    pub internet_switch: bool,
    pub baseline_switch: bool,
    pub baseline_time: u32,
    pub user_id: String,
    //=====host info
    pub dev_uid: String,
    pub macid: String,
    pub ips: String,
    pub ifcfg: String,
    pub os: String,
    pub memsize: String,
    pub cpu: String,
    pub hdsize: String,
    pub auth: String,
    pub host_name: String,
    pub mod_ver: String,
    pub arch_type: u8,
    pub is_offline_mode: bool,
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

fn run_cmd_capture(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to execute {}: {}", cmd, e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Command {} failed with status {}: {}", cmd, output.status, stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.trim().to_string())
}

impl NetInfoConfig {
    /// 获取主接口（基于 server_ip）
    fn get_main_interface(server_ip: &str) -> Result<String, String> {
        let out = run_cmd_capture("ip", &["route", "get", server_ip])
            .map_err(|e| format!("ip route get {} failed: {}", server_ip, e))?;
        let re = regex::Regex::new(r"dev\s+(\S+)").map_err(|e| format!("Regex error: {}", e))?;
        for line in out.lines() {
            if let Some(cap) = re.captures(line) {
                let iface = cap.get(1).unwrap().as_str();
                if iface != "lo" {
                    return Ok(iface.to_string());
                }
            }
        }
        Err(format!("No valid interface found for server_ip {}", server_ip))
    }

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
            config.mid = mid;
        }

        config.ver = ini.get("SERVERINFO", "VERSION")
            .unwrap_or_else(|| "3.0.1_T9".to_string());

        if let Some(user_id) = ini.get("SERVERINFO", "USER_ID") {
            config.user_id = user_id;
        }

        if let Some(value) = ini.get("SERVERINFO", "COMTIME") {
            config.com_time = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "CRONTIME") {
            config.cron_time = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "EXTORTION_PROTECT") {
            config.extortion_protect = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "EXTORTION_SWITCH") {
            config.extortion_switch = matches!(value.trim(), "1");
            log_info!("===extortion_switch: {}", config.extortion_switch);
        }
        if let Some(value) = ini.get("SERVERINFO", "SELF_PROTECT_SWITCH") {
            config.self_protect_switch = matches!(value.trim(), "1");
            log_info!("===self_protect_switch: {}", config.self_protect_switch);
        }
        if let Some(value) = ini.get("SERVERINFO", "FASTTIME") {
            config.fast_time = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "FILE_PROTECT") {
            config.file_protect = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "FILE_SWITCH") {
            config.file_switch = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "DYNAMIC_SWITCH") {
            config.dynamic_switch = matches!(value.trim(), "1");
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
        if let Some(value) = ini.get("SERVERINFO", "CLI_SERVER_PORT") {
            config.cli_port = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "MODULE_SWITCH") {
            config.module_switch = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "OPEN_PORT_SWITCH") {
            config.open_port_switch = matches!(value.trim(), "1");
            let _ = config.write_net_rule(NetRule::VirtualOpenPort(config.open_port_switch));
        }
        if let Some(value) = ini.get("SERVERINFO", "PROC_PROTECT") {
            config.proc_protect = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "PROC_SWITCH") {
            config.proc_switch = matches!(value.trim(), "1");
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

            if !config.server_ip.is_empty() {
                let ip_for_route = match Self::extract_ip(&config.server_ip) {
                    Some(ip) => ip,
                    None => {
                        log_error!(
                            "Failed to extract IP from server_ip: '{}', using raw value (may fail)",
                            config.server_ip
                        );
                        config.server_ip.clone()
                    }
                };

                config.ifcfg = Self::get_main_interface(&ip_for_route)
                    .unwrap_or_else(|e| {
                        log_error!(
                            "Failed to get main interface for IP '{}': {}, using default 'eth0'",
                            ip_for_route,
                            e
                        );
                        "eth0".to_string()
                    });

                log_info!("Main interface set to: {}", config.ifcfg);
            }
        }


        if let Some(value) = ini.get("SERVERINFO", "SERVER_PORT") {
            config.server_port = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "USB_PROTECT") {
            config.usb_protect = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "USB_SWITCH") {
            config.usb_switch = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "DNS_SWITCH") {
            config.syslog_dns_switch = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "INTERNAL_COMMUNICATION_SWITCH") {
            config.syslog_inner_switch = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "EXTERNAL_COMMUNICATION_SWITCH") {
            config.syslog_outer_switch = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "INTERNET_SWITCH") {
            config.internet_switch = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "OFFLINE_MODE") {
            config.is_offline_mode = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "SYSLOG_PROCESS_SWITCH") {
            config.syslog_process_switch = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "BASELINE_SWITCH") {
            config.baseline_switch = matches!(value.trim(), "1");
        }

        if let Some(value) = ini.get("SERVERINFO", "BASELINE_TIME") {
            config.baseline_time = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("HOSTINFO", "DEV_UID") {
            config.dev_uid = value;
        }
        if let Some(value) = ini.get("HOSTINFO", "MACID") {
            config.macid = value;
        }
        if let Some(value) = ini.get("HOSTINFO", "IPS") {
            config.ips = value;
        }
        if let Some(value) = ini.get("HOSTINFO", "OS") {
            config.os = value;
        }
        if let Some(value) = ini.get("HOSTINFO", "MEMSIZE") {
            config.memsize = value;
        }
        if let Some(value) = ini.get("HOSTINFO", "CPU") {
            config.cpu = value;
        }
        if let Some(value) = ini.get("HOSTINFO", "HDSIZE") {
            config.hdsize = value;
        }
        if let Some(value) = ini.get("HOSTINFO", "AUTH") {
            config.auth = value;
        }
        if let Some(value) = ini.get("HOSTINFO", "HOSTNAME") {
            config.host_name = value;
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
        writeln!(file, "SELF_PROTECT_SWITCH={}", self.self_protect_switch as u8)?;
        writeln!(file, "FASTTIME={}", self.fast_time)?;
        writeln!(file, "FILE_PROTECT={}", self.file_protect as u8)?;
        writeln!(file, "FILE_SWITCH={}", self.file_switch as u8)?;
        writeln!(file, "LOGIPPORT={}", self.log_ip_port.clone().unwrap_or_default())?;
        writeln!(file, "LOGPROTO={}", self.log_proto)?;
        writeln!(file, "LOGSENT={}", self.log_sent)?;
        writeln!(file, "CLI_SERVER_PORT={}", self.cli_port)?;
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
        writeln!(file, "INTERNAL_COMMUNICATION_SWITCH={}", self.syslog_inner_switch as u8)?;
        writeln!(file, "EXTERNAL_COMMUNICATION_SWITCH={}", self.syslog_outer_switch as u8)?;
        writeln!(file, "SYSLOG_PROCESS_SWITCH={}", self.syslog_process_switch as u8)?;
        writeln!(file, "INTERNET_SWITCH={}", self.internet_switch as u8)?;
        writeln!(file, "OFFLINE_MODE={}", self.is_offline_mode as u8)?;
        writeln!(file, "BASELINE_SWITCH={}", self.baseline_switch as u8)?;
        writeln!(file, "BASELINE_TIME={}", self.baseline_time)?;
        writeln!(file, "VERSION={}", self.ver)?;
        writeln!(file, "[HOSTINFO]")?;
        writeln!(file, "DEV_UID={}", self.dev_uid)?;
        writeln!(file, "MACID={}", self.macid)?;
        //writeln!(file, "IPS={}", self.ips)?;
        //writeln!(file, "IFCFG={}", self.ifcfg)?;
        //writeln!(file, "OS={}", self.os)?;
        //writeln!(file, "MEMSIZE={}", self.memsize)?;
        //writeln!(file, "CPU={}", self.cpu)?;
        //writeln!(file, "HDSIZE={}", self.hdsize)?;
        writeln!(file, "AUTH={}", self.auth)?;
        writeln!(file, "HOSTNAME={}", self.host_name)?;
        Ok(())
    }

    pub fn acquire_host_info(&mut self) -> io::Result<()> {
        log_info!("========dev_id:{}", self.dev_uid);
        //if self.dev_uid.is_empty() 
        {
            self.dev_uid = agent_uid::ensure_and_get_mgs_guid(&("/etc/.vedasystem"))
                .unwrap_or_else(|_| "unknown".to_string());
        }
        log_info!("=====dev_id:{}", self.dev_uid);
        if self.macid.is_empty() {
            self.macid = ip_mac::get_mac().unwrap_or("unknown".to_string());
        }
        if self.host_name.is_empty() {
            self.host_name = SystemInfo::get_computer_name().unwrap_or_else(|_| "Unknown".to_string());
        }
        if self.auth.is_empty() {
            self.auth = "123123".to_string();
        }
        if self.os.is_empty() {
            self.os = SystemInfo::get_computer_version().unwrap_or_else(|_| "Unknown".to_string());
        }
        if self.cpu.is_empty() {
            self.cpu = SystemInfo::get_cpu_cores().unwrap_or_else(|_| "Unknown".to_string());
        }
        if self.memsize.is_empty() {
            self.memsize = SystemInfo::get_memory_size().unwrap_or_else(|_| "Unknown".to_string());
        }
        if self.hdsize.is_empty() {
            self.hdsize = SystemInfo::get_disk_size().unwrap_or_else(|_| "Unknown".to_string());
        }
        if self.ips.is_empty() {
            self.ips = ip_mac::get_ip().unwrap_or("unknown".to_string());
        }
        Ok(())
    }
    fn extract_ip(input: &str) -> Option<String> {
        use std::net::IpAddr;

        // 1. 去掉协议头
        let without_scheme = input
            .strip_prefix("http://")
            .or_else(|| input.strip_prefix("https://"))
            .unwrap_or(input);

        let host_part = if without_scheme.starts_with('[') {
            // 找到第一个 ']'
            if let Some(idx) = without_scheme.find(']') {
                &without_scheme[1..idx] // 提取 ::1
            } else {
                without_scheme // 格式错误，但继续尝试
            }
        } else {
            without_scheme.split(':').next().unwrap_or(without_scheme)
        };

        if host_part.parse::<IpAddr>().is_ok() {
            Some(host_part.to_string())
        } else {
            None
        }
    }
}

use once_cell::sync::Lazy;
use std::path::Path;
use std::sync::Mutex;

pub static NETINFO_CONFIG: Lazy<Mutex<NetInfoConfig>> = Lazy::new(|| {
    let base_path = std::env::var("CONFIG_PATH")
        .ok()
        .unwrap_or_else(|| "/opt/osec".to_string());
    let path = format!("{}/net_info.ini", base_path);
    let mut ini = Ini::new();
    if Path::new(&path).exists() {
        ini.load(&path).unwrap_or_else(|err| {
            eprintln!("Failed to load configuration file from '{}': {}", path, err);
            std::process::exit(1);
        });
    } else {
        eprintln!("Configuration file '{}' does not exist", path);
        std::process::exit(1);
    }
    Mutex::new(NetInfoConfig::from_ini(&ini))
});
