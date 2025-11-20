// crates/agent_manager/src/common.rs
use std::fs;
use std::path::Path;
use std::io::{Seek, Write};
use fs2::FileExt;
use logging::log_info;

pub const PID_FILE: &str = "/tmp/.osec_cli.pid";
pub const INI_FILE: &str = "/opt/osec/net_info.ini";
pub const BUFFER_SIZE: usize = 4096;

pub const FILE_START_MARKER: &str = "\x01FILE_START\x01";
pub const FILE_END_MARKER: &str = "\x02FILE_END\x02";

#[derive(Clone, Debug, Default)]
pub struct ClientConfigData {
    pub port: u16,
    pub dev_uid: String,
    pub server_ip: String,
}

pub fn trim_and_check_non_empty(s: &str) -> Option<&str> {
    let t = s.trim();
    if t.is_empty() { None } else { Some(t) }
}

pub fn parse_ini_file<P: AsRef<Path>>(filename: P) -> Result<ClientConfigData, String> {
    let text = fs::read_to_string(&filename)
        .map_err(|e| format!("读取 INI 文件失败: {}", e))?;

    let mut cfg = ClientConfigData::default();
    let mut current_section = String::new();

    for raw_line in text.lines() {
        let line = match trim_and_check_non_empty(raw_line) {
            Some(l) => l,
            None => continue,
        };

        // 检测段落名 [SECTION]
        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].trim().to_string();
            continue;
        }

        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim();
            let value = line[eq_pos + 1..].trim();

            match current_section.as_str() {
                "SERVERINFO" => {
                    match key {
                        "CLI_SERVER_PORT" => {
                            cfg.port = value
                                .parse()
                                .map_err(|_| format!("CLI_SERVER_PORT 无效: {}", value))?;
                        }
                        "SERVER_IP" => {
                            let ip = value.strip_prefix("https://").unwrap_or(value);
                            if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                                cfg.server_ip = ip.to_string();
                            } else {
                                return Err(format!("SERVER_IP 不是有效 IPv4: {}", value));
                            }
                        }
                        "DEV_UID" => {
                            cfg.dev_uid = value.to_string();
                        }
                        _ => {}
                    }
                }
                "HOSTINFO" => {
                    if key == "DEV_UID" {
                        cfg.dev_uid = value.to_string();
                    }
                }
                _ => {}
            }
        }
    }
//    if cfg.port == 0 {
//        return Err("CLI_SERVER_PORT 未配置或为 0".to_string());
//    }
    if cfg.dev_uid.is_empty() {
        return Err("DEV_UID 未配置".to_string());
    }
    if cfg.server_ip.is_empty() {
        return Err("SERVER_IP 未配置或无效".to_string());
    }

    Ok(cfg)
}

pub fn acquire_lock() -> Result<fs::File, String> {
    let mut file = fs::OpenOptions::new()
        .read(true).write(true).create(true)
        .open(PID_FILE)
        .map_err(|e| format!("打开 PID 文件失败: {}", e))?;
    file.try_lock_exclusive().map_err(|e| format!("无法锁定 PID 文件: {}", e))?;
    let pid = std::process::id();
    file.set_len(0).ok();
    file.rewind().ok();
    writeln!(file, "{}", pid).map_err(|e| format!("写 PID 失败: {}", e))?;
    Ok(file)
}
