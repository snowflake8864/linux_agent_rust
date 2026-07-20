use log::{info, warn};
use std::fs;
use std::io::Write;

use common::backend::SecurityBackend;

/// 驱动后端 — 通过 /proc/osec/* 与内核驱动通信（现有逻辑封装）
pub struct DriverBackend;

impl DriverBackend {
    pub fn new() -> Self {
        Self
    }
}

impl SecurityBackend for DriverBackend {
    fn is_active(&self) -> bool {
        // 检查驱动是否加载
        if let Ok(content) = fs::read_to_string("/proc/modules") {
            content.lines().any(|l| l.starts_with("osec_base "))
        } else {
            false
        }
    }

    fn name(&self) -> &str {
        "driver"
    }

    // ── 进程管控 ──

    fn add_md5_rules(&self, data: &str) -> Result<(), String> {
        let path = "/proc/osec/md5_rt";
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| format!("Failed to open {}: {}", path, e))?;
        file.write_all(data.as_bytes())
            .map_err(|e| format!("Failed to write {}: {}", path, e))
    }

    fn notify_process_update(&self) -> Result<(), String> {
        let path = "/proc/osec/process_rt";
        fs::write(path, "update\n")
            .map_err(|e| format!("Failed to write {}: {}", path, e))
    }

    fn get_process_whitelist(&self) -> Vec<String> {
        Vec::new()
    }

    fn get_process_blacklist(&self) -> Vec<String> {
        Vec::new()
    }

    // ── 网络 / 准入 ──

    fn write_tcp_force_ecn(&self, enable: bool) -> Result<(), String> {
        let path = "/proc/osec/tcp_force_ecn";
        if std::path::Path::new(path).exists() {
            let val = if enable { "1" } else { "0" };
            fs::write(path, val)
                .map_err(|e| format!("Failed to write {}: {}", path, e))
        } else {
            warn!("{} not found, skip", path);
            Ok(())
        }
    }

    fn write_ipv4_block_policies(&self, ips: &[String]) -> Result<(), String> {
        let path = "/proc/osec/osec_conn/block_saddr_rt";
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| format!("Failed to open {}: {}", path, e))?;
        // 清空 + 逐行写入
        file.write_all(b"c\n")
            .map_err(|e| format!("Failed to write {}: {}", path, e))?;
        for ip in ips {
            file.write_all(format!("{}\n", ip).as_bytes())
                .map_err(|e| format!("Failed to write {}: {}", path, e))?;
        }
        Ok(())
    }

    fn write_ipv6_block_policies(&self, ips: &[String]) -> Result<(), String> {
        let path = "/proc/osec/osec_conn/block_saddr_rt_v6";
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| format!("Failed to open {}: {}", path, e))?;
        file.write_all(b"c\n")
            .map_err(|e| format!("Failed to write {}: {}", path, e))?;
        for ip in ips {
            file.write_all(format!("{}\n", ip).as_bytes())
                .map_err(|e| format!("Failed to write {}: {}", path, e))?;
        }
        Ok(())
    }

    fn write_net_rules(&self, rules: &str) -> Result<(), String> {
        let path = "/proc/osec/net_rules";
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| format!("Failed to open {}: {}", path, e))?;
        file.write_all(rules.as_bytes())
            .map_err(|e| format!("Failed to write {}: {}", path, e))
    }

    fn write_netblock_switch(&self, value: &str) -> Result<(), String> {
        let path = "/proc/osec/osec_conn/block_switch";
        fs::write(path, format!("{}\n", value))
            .map_err(|e| format!("Failed to write {}: {}", path, e))
    }

    fn write_defense_switch(&self, rule_type: &str, value: &str) -> Result<(), String> {
        let path = "/proc/osec/defense_switch";
        let data = format!("{} {}\n", rule_type, value);
        fs::write(path, data)
            .map_err(|e| format!("Failed to write {}: {}", path, e))
    }

    // ── DPI / 模式匹配 ──

    fn write_dpi_file_patterns(&self, data: &str, clear: bool, build: bool) -> Result<(), String> {
        let path = "/proc/osec/dpi/file_patterns";
        if clear {
            fs::write(path, "c\n").map_err(|e| format!("{}: {}", path, e))?;
        }
        if !data.is_empty() {
            let mut file = std::fs::OpenOptions::new()
                .read(true).write(true).open(path)
                .map_err(|e| format!("{}: {}", path, e))?;
            file.write_all(data.as_bytes())
                .map_err(|e| format!("{}: {}", path, e))?;
        }
        if build {
            let mut file = std::fs::OpenOptions::new()
                .read(true).write(true).open(path)
                .map_err(|e| format!("{}: {}", path, e))?;
            file.write_all(b"b\n")
                .map_err(|e| format!("{}: {}", path, e))?;
        }
        Ok(())
    }

    fn write_dpi_rules(&self, data: &str, clear: bool) -> Result<(), String> {
        let path = "/proc/osec/dpi/rules";
        if clear {
            fs::write(path, "c\n").map_err(|e| format!("{}: {}", path, e))?;
        }
        if !data.is_empty() {
            fs::write(path, data).map_err(|e| format!("{}: {}", path, e))?;
        }
        Ok(())
    }

    fn write_process_dpi_patterns(&self, data: &str, clear: bool, build: bool) -> Result<(), String> {
        let path = "/proc/osec/process_dpi/file_patterns";
        if clear {
            fs::write(path, "c\n").map_err(|e| format!("{}: {}", path, e))?;
        }
        if !data.is_empty() {
            let mut file = std::fs::OpenOptions::new()
                .read(true).write(true).open(path)
                .map_err(|e| format!("{}: {}", path, e))?;
            file.write_all(data.as_bytes())
                .map_err(|e| format!("{}: {}", path, e))?;
        }
        if build {
            let mut file = std::fs::OpenOptions::new()
                .read(true).write(true).open(path)
                .map_err(|e| format!("{}: {}", path, e))?;
            file.write_all(b"b\n")
                .map_err(|e| format!("{}: {}", path, e))?;
        }
        Ok(())
    }

    fn write_process_dpi_rules(&self, data: &str, clear: bool) -> Result<(), String> {
        let path = "/proc/osec/process_dpi/rules";
        if clear {
            fs::write(path, "c\n").map_err(|e| format!("{}: {}", path, e))?;
        }
        if !data.is_empty() {
            fs::write(path, data).map_err(|e| format!("{}: {}", path, e))?;
        }
        Ok(())
    }

    fn write_dpi_true_process(&self, data: &str, clear: bool) -> Result<(), String> {
        let path = "/proc/osec/dpi/true_process_rt";
        if clear {
            fs::write(path, "c\n").map_err(|e| format!("{}: {}", path, e))?;
        }
        if !data.is_empty() {
            fs::write(path, data).map_err(|e| format!("{}: {}", path, e))?;
        }
        Ok(())
    }

    // ── 其他 /proc/osec ──

    fn emit_docker_event(&self, kind: u8, flag: u8, pid: i32) -> Result<(), String> {
        let path = "/proc/osec/docker_rt";
        let data = format!("{},{},{}\n", kind, flag, pid);
        fs::write(path, data).map_err(|e| format!("{}: {}", path, e))
    }

    fn clear_docker_rt(&self) -> Result<(), String> {
        let path = "/proc/osec/docker_rt";
        fs::write(path, "c\n").map_err(|e| format!("{}: {}", path, e))
    }

    fn write_business_ports(&self, ports: &[u16]) -> Result<(), String> {
        let path = "/proc/osec/business_ports";
        let data: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        let content = data.join(",");
        fs::write(path, &content).map_err(|e| format!("{}: {}", path, e))
    }

    fn write_self_protection(&self, num: u32) -> Result<(), String> {
        let path = "/proc/osec/self";
        let data = format!("veda {} 0\n", num);
        fs::write(path, data).map_err(|e| format!("{}: {}", path, e))
    }
}
