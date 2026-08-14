use std::sync::{Arc, OnceLock};

/// DpiWriter adapter: bridges `pattern::DpiWriter` → `SecurityBackend`.
/// Registered at startup so `PatternRulesMgr` can route through the active backend.
struct BackendDpiWriter;

impl pattern::DpiWriter for BackendDpiWriter {
    fn clear_all(&self) {
        if let Some(b) = super::backend::get_backend() {
            let _ = b.write_dpi_file_patterns("", true, false);
            let _ = b.write_dpi_rules("", true);
            let _ = b.write_dpi_true_process("", true);
        }
    }

    fn write_pair(&self, pat: &str, rule: &str) {
        if let Some(b) = super::backend::get_backend() {
            if !pat.is_empty() {
                let _ = b.write_dpi_file_patterns(pat, false, false);
            }
            if !rule.is_empty() {
                let _ = b.write_dpi_rules(rule, false);
            }
        }
    }

    fn write_true_process(&self, data: &str) {
        if !data.is_empty() {
            if let Some(b) = super::backend::get_backend() {
                let _ = b.write_dpi_true_process(data, false);
            }
        }
    }

    fn build(&self) {
        if let Some(b) = super::backend::get_backend() {
            let _ = b.write_dpi_file_patterns("", false, true);
        }
    }

    fn clear_process(&self) {
        if let Some(b) = super::backend::get_backend() {
            let _ = b.write_process_dpi_patterns("", true, false);
            let _ = b.write_process_dpi_rules("", true);
        }
    }

    fn write_process_pair(&self, pat: &str, rule: &str) {
        if let Some(b) = super::backend::get_backend() {
            if !pat.is_empty() {
                let _ = b.write_process_dpi_patterns(pat, false, false);
            }
            if !rule.is_empty() {
                let _ = b.write_process_dpi_rules(rule, false);
            }
        }
    }

    fn build_process(&self) {
        if let Some(b) = super::backend::get_backend() {
            let _ = b.write_process_dpi_patterns("", false, true);
        }
    }
}

/// Register the DPI writer adapter (call after `set_backend`).
pub fn init_dpi_writer() {
    pattern::set_dpi_writer(Arc::new(BackendDpiWriter));
}

/// 安全后端抽象 — 驱动模式写 /proc/osec ，eBPF 模式写 BPF maps
pub trait SecurityBackend: Send + Sync {
    /// 后端是否已初始化可用
    fn is_active(&self) -> bool;
    /// 后端名称: "driver" / "ebpf"
    fn name(&self) -> &str;

    // ── 进程管控 ──
    fn add_md5_rules(&self, data: &str) -> Result<(), String>;
    fn notify_process_update(&self) -> Result<(), String>;
    fn get_process_whitelist(&self) -> Vec<String>;
    fn get_process_blacklist(&self) -> Vec<String>;
    /// 查询 hash 对应的文件路径（从 md5_map 中获取，eBPF 模式有效）
    fn lookup_hash_paths(&self, _hash: &str) -> Vec<String> { Vec::new() }

    // ── 网络 / 准入 ──
    fn write_tcp_force_ecn(&self, enable: bool) -> Result<(), String>;
    fn write_ipv4_block_policies(&self, ips: &[String]) -> Result<(), String>;
    fn write_ipv6_block_policies(&self, ips: &[String]) -> Result<(), String>;
    fn write_net_rules(&self, rules: &str) -> Result<(), String>;
    fn write_netblock_switch(&self, value: &str) -> Result<(), String>;
    fn write_defense_switch(&self, rule_type: &str, value: &str) -> Result<(), String>;

    // ── DPI / 模式匹配 ──
    fn write_dpi_file_patterns(&self, data: &str, clear: bool, build: bool) -> Result<(), String>;
    fn write_dpi_rules(&self, data: &str, clear: bool) -> Result<(), String>;
    fn write_process_dpi_patterns(&self, data: &str, clear: bool, build: bool) -> Result<(), String>;
    fn write_process_dpi_rules(&self, data: &str, clear: bool) -> Result<(), String>;
    fn write_dpi_true_process(&self, data: &str, clear: bool) -> Result<(), String>;

    // ── 运行时开关同步 ──
    /// eBPF模式：将file/proc的switch和protect写入BPF maps；driver模式：空操作
    fn sync_switches(&self, _file_switch: bool, _proc_switch: bool,
                     _file_protect: bool, _proc_protect: bool) -> Result<(), String> {
        Ok(())
    }

    // ── 其他 /proc/osec ──
    fn emit_docker_event(&self, kind: u8, flag: u8, pid: i32) -> Result<(), String>;
    fn clear_docker_rt(&self) -> Result<(), String>;
    fn write_business_ports(&self, ports: &[u16]) -> Result<(), String>;
    fn write_self_protection(&self, num: u32) -> Result<(), String>;
}

/// 全局后端单例
static BACKEND: OnceLock<Arc<dyn SecurityBackend>> = OnceLock::new();

pub fn set_backend(b: Arc<dyn SecurityBackend>) {
    let _ = BACKEND.set(b);
}

pub fn get_backend() -> Option<Arc<dyn SecurityBackend>> {
    BACKEND.get().cloned()
}

/// 便捷：对后端执行操作
pub fn with_backend<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce(&dyn SecurityBackend) -> Result<R, String>,
{
    match BACKEND.get() {
        Some(b) => {
            //log::info!("[with_backend] backend={} calling...", b.name());
            f(b.as_ref())
        }
        None => {
            log::error!("[with_backend] ❌ BACKEND not initialized!");
            Err("SecurityBackend not initialized".to_string())
        }
    }
}

/// 空后端 — 当驱动和 eBPF 都不可用时使用，所有安全操作均为空操作，
/// 程序仍然可以正常运行（策略下发、心跳上报等非内核功能不受影响）
pub struct NoopBackend;

impl SecurityBackend for NoopBackend {
    fn is_active(&self) -> bool {
        false
    }
    fn name(&self) -> &str {
        "noop"
    }

    fn add_md5_rules(&self, _data: &str) -> Result<(), String> {
        Ok(())
    }
    fn notify_process_update(&self) -> Result<(), String> {
        Ok(())
    }
    fn get_process_whitelist(&self) -> Vec<String> {
        Vec::new()
    }
    fn get_process_blacklist(&self) -> Vec<String> {
        Vec::new()
    }

    fn write_tcp_force_ecn(&self, _enable: bool) -> Result<(), String> {
        Ok(())
    }
    fn write_ipv4_block_policies(&self, _ips: &[String]) -> Result<(), String> {
        Ok(())
    }
    fn write_ipv6_block_policies(&self, _ips: &[String]) -> Result<(), String> {
        Ok(())
    }
    fn write_net_rules(&self, _rules: &str) -> Result<(), String> {
        Ok(())
    }
    fn write_netblock_switch(&self, _value: &str) -> Result<(), String> {
        Ok(())
    }
    fn write_defense_switch(&self, _rule_type: &str, _value: &str) -> Result<(), String> {
        Ok(())
    }

    fn write_dpi_file_patterns(&self, _data: &str, _clear: bool, _build: bool) -> Result<(), String> {
        Ok(())
    }
    fn write_dpi_rules(&self, _data: &str, _clear: bool) -> Result<(), String> {
        Ok(())
    }
    fn write_process_dpi_patterns(&self, _data: &str, _clear: bool, _build: bool) -> Result<(), String> {
        Ok(())
    }
    fn write_process_dpi_rules(&self, _data: &str, _clear: bool) -> Result<(), String> {
        Ok(())
    }
    fn write_dpi_true_process(&self, _data: &str, _clear: bool) -> Result<(), String> {
        Ok(())
    }

    fn emit_docker_event(&self, _kind: u8, _flag: u8, _pid: i32) -> Result<(), String> {
        Ok(())
    }
    fn clear_docker_rt(&self) -> Result<(), String> {
        Ok(())
    }
    fn write_business_ports(&self, _ports: &[u16]) -> Result<(), String> {
        Ok(())
    }
    fn write_self_protection(&self, _num: u32) -> Result<(), String> {
        Ok(())
    }
}
