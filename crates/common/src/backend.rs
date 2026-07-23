use std::sync::{Arc, RwLock, OnceLock};

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
        Some(b) => f(b.as_ref()),
        None => Err("SecurityBackend not initialized".to_string()),
    }
}
