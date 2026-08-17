use log::{info, warn};
use std::io::Write;
use std::os::fd::AsRawFd;

use common::backend::SecurityBackend;

/// 驱动后端 — 通过 /proc/osec/* 与内核驱动通信
pub struct DriverBackend;

/// Helper: 以 write-only 模式打开 proc 文件并写入数据
fn proc_write(path: &str, data: &str) -> Result<(), String> {
    let trimmed = data.trim_end_matches('\n');
    let exists = std::path::Path::new(path).exists();
    log::info!("[DriverBackend] >>> path={} exists={} flags=O_WRONLY data='{}' len={}",
        path, exists, trimmed, data.len());

    // open
    let mut file = match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(f) => f,
        Err(e) => {
            log::error!("[DriverBackend] ❌ open({}) errno={} {}", path,
                e.raw_os_error().unwrap_or(-1), e);
            return Err(format!("open {}: {}", path, e));
        }
    };
    let fd = file.as_raw_fd();
    log::info!("[DriverBackend] fd={} open_ok", fd);

    // write（write_all 保证大批量多行规则不被内核 proc 缓冲截断）
    match file.write_all(data.as_bytes()) {
        Ok(()) => log::info!("[DriverBackend] fd={} write_ok {}bytes", fd, data.len()),
        Err(e) => {
            log::error!("[DriverBackend] ❌ fd={} write_err errno={} {}",
                fd, e.raw_os_error().unwrap_or(-1), e);
            return Err(format!("write {}: {}", path, e));
        }
    }

    // close
    drop(file);
    log::info!("[DriverBackend] fd={} close_ok", fd);
    Ok(())
}

impl DriverBackend {
    pub fn new() -> Self {
        Self
    }
}

impl SecurityBackend for DriverBackend {
    fn is_active(&self) -> bool {
        if let Ok(content) = std::fs::read_to_string("/proc/modules") {
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
        proc_write("/proc/osec/md5_rt", data)
    }

    fn notify_process_update(&self) -> Result<(), String> {
        proc_write("/proc/osec/process_rt", "update\n")
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
            proc_write(path, val)
        } else {
            warn!("{} not found, skip", path);
            Ok(())
        }
    }

    fn write_ipv4_block_policies(&self, ips: &[String]) -> Result<(), String> {
        let path = "/proc/osec/osec_conn/block_saddr_rt";
        let mut file = std::fs::OpenOptions::new()
            .write(true).open(path)
            .map_err(|e| format!("Failed to open {}: {}", path, e))?;
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
            .write(true).open(path)
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
        proc_write("/proc/osec/net_rules", rules)
    }

    fn write_netblock_switch(&self, value: &str) -> Result<(), String> {
        proc_write("/proc/osec/osec_conn/block_switch", &format!("{}\n", value))
    }

    fn write_defense_switch(&self, rule_type: &str, value: &str) -> Result<(), String> {
        proc_write("/proc/osec/defense_switch", &format!("{} {}\n", rule_type, value))
    }

    // ── DPI / 模式匹配 ──

    fn write_dpi_file_patterns(&self, data: &str, clear: bool, build: bool) -> Result<(), String> {
        let path = "/proc/osec/dpi/file_patterns";
        if clear { proc_write(path, "c\n")?; }
        if !data.is_empty() { proc_write(path, data)?; }
        if build { proc_write(path, "b\n")?; }
        Ok(())
    }

    fn write_dpi_rules(&self, data: &str, clear: bool) -> Result<(), String> {
        let path = "/proc/osec/dpi/rules";
        if clear { proc_write(path, "c\n")?; }
        if !data.is_empty() { proc_write(path, data)?; }
        Ok(())
    }

    fn write_process_dpi_patterns(&self, data: &str, clear: bool, build: bool) -> Result<(), String> {
        let path = "/proc/osec/process_dpi/file_patterns";
        if clear { proc_write(path, "c\n")?; }
        if !data.is_empty() { proc_write(path, data)?; }
        if build { proc_write(path, "b\n")?; }
        Ok(())
    }

    fn write_process_dpi_rules(&self, data: &str, clear: bool) -> Result<(), String> {
        let path = "/proc/osec/process_dpi/rules";
        if clear { proc_write(path, "c\n")?; }
        if !data.is_empty() { proc_write(path, data)?; }
        Ok(())
    }

    fn write_dpi_true_process(&self, data: &str, clear: bool) -> Result<(), String> {
        let path = "/proc/osec/dpi/true_process_rt";
        if clear { proc_write(path, "c\n")?; }
        if !data.is_empty() { proc_write(path, data)?; }
        Ok(())
    }

    // ── 其他 /proc/osec ──

    fn emit_docker_event(&self, kind: u8, flag: u8, pid: i32) -> Result<(), String> {
        proc_write("/proc/osec/docker_rt", &format!("{},{},{}\n", kind, flag, pid))
    }

    fn clear_docker_rt(&self) -> Result<(), String> {
        proc_write("/proc/osec/docker_rt", "c\n")
    }

    fn write_business_ports(&self, ports: &[u16]) -> Result<(), String> {
        let data: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        proc_write("/proc/osec/business_ports", &data.join(","))
    }

    fn write_self_protection(&self, num: u32) -> Result<(), String> {
        proc_write("/proc/osec/self", &format!("veda {} 0\n", num))
    }
}
