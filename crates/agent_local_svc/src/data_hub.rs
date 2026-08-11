use std::collections::HashSet;
use std::sync::{Mutex, LazyLock, atomic::{AtomicBool, AtomicU8, Ordering}};

use logging::{log_info, log_error};
use common::backend;
use grpc_gateway::policy_watch::PolicyChangeType;
use task;
use grpc_gateway::dir_policy::DirectionScanRule;
use grpc_gateway::extort_policy::ExtortProtectRule;
use grpc_gateway::jump::JumpStatus;

// Re-export from grpc_gateway so downstream code keeps working
pub use grpc_gateway::agent_mode::{AgentMode, AGENT_MODE, ADMISSION_NETWORK_ANOMALY, require_offline, set_online, set_offline};

/// 启动时自动注册网络故障回调，供 task_fetcher 等 crate 通过 grpc_gateway 间接触发。
static REGISTER_CALLBACK: std::sync::OnceLock<()> = std::sync::OnceLock::new();
fn ensure_callback_registered() {
    REGISTER_CALLBACK.get_or_init(|| {
        grpc_gateway::agent_mode::register_network_failure_callback(
            set_offline_and_check_admission as fn()
        );
    });
}

/// 全局 token 缓存，token 获取时由 online 模块更新，check_server_reachable 读取。
static CURRENT_TOKEN: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

/// 由 online 模块在获取到 token 时调用，供 check_server_reachable 使用。
/// 同时触发一次 newestJumpInfo 拉取：这是启动后有效 token 的第一个时机。
pub fn update_token(token: String) {
    *CURRENT_TOKEN.lock().unwrap() = Some(token);
    // token 就绪后异步拉取最新跳变信息（受 [JUMP] ENABLED 控制）
    let hub = AgentDataHub::new();
    tokio::spawn(async move { hub.fetch_newest_jump_info().await; });
}

/// 准入修复：根据当前模式设置 /proc/osec/tcp_force_ecn。
/// 调用方不需要再重复写 proc——这里已经按模式处理。
fn run_admission_repair() {
    log_info!("[admission] >>> run_admission_repair() 被调用（调用栈回溯请查看上面的 >>> 箭头链）");
    let admission_enabled = {
        let cfg = config::net_info::NETINFO_CONFIG.lock().unwrap();
        cfg.admission.enabled
    };
    if !admission_enabled {
        log_info!("[admission] 准入功能未启用，跳过修复");
        return;
    }

    let hub = AgentDataHub::new();
    let mode = ADMISSION_MODE.load(Ordering::Relaxed);
    let effective = ADMISSION_EFFECTIVE.load(Ordering::Relaxed);
    let detecting = ADMISSION_DETECTING.load(Ordering::Relaxed);
    log_info!("[admission] >>> 准入修复: mode={}, effective={}, detecting={}", mode, effective, detecting);

    match mode {
        0 => {
            log_info!("[admission] OFF 模式，固定关准入，跳过 repair（无需修复）");
        }
        1 => {
            log_info!("[admission] ON 模式，固定开准入，跳过 repair（无需修复）");
        }
        2 => {
            if !detecting {
                log_info!("[admission] AUTO 模式 → 启动自动检测（OFF→测→ON→测）");
                hub.start_auto_detect();
            } else {
                log_info!("[admission] AUTO 模式 → 自动检测已在运行，跳过");
            }
        }
        _ => {
            log_error!("[admission] 未知的准入模式: {}", mode);
        }
    }
}

/// 断线时调用：累计失败次数，仅在首次切离线时执行准入修复。
/// 已离线后不再重复触发——由 auto-detection 自身循环负责后续重试。
pub fn set_offline_and_check_admission() {
    log_info!("[admission] >>> set_offline_and_check_admission() 被调用");
    ensure_callback_registered();

    // OFF/ON 模式是固定设置，不需要 repair，直接返回
    let mode = ADMISSION_MODE.load(Ordering::Relaxed);
    if mode == 0 || mode == 1 {
        log_info!("[admission] >>> set_offline_and_check_admission: OFF/ON 固定模式，跳过 repair");
        return;
    }

    if !set_offline() {
        log_info!("[admission] >>> set_offline_and_check_admission: 已经离线，跳过");
        return;
    }
    log_info!("[admission] >>> 切离线，触发准入修复");
    run_admission_repair();
}

/// 检测服务器是否可达：向 /v1/getinfo 发送空请求，验证返回 code=="000000"。
/// 统一的连通性探测，被 gRPC handler 和 admission 自动检测共用。
pub async fn check_server_reachable() -> bool {
    let base_url = {
        let cfg = config::net_info::NETINFO_CONFIG.lock().unwrap();
        format!("https://{}:{}", cfg.server_ip, cfg.server_port)
    };

    let net_client = match net_client::core::NetClient::new(Some(base_url.clone()), true) {
        Ok(c) => c,
        Err(e) => {
            log_info!("[connectivity] 创建 NetClient 失败: {}", e);
            return false;
        }
    };

    let token = CURRENT_TOKEN.lock().unwrap().clone();
    let token_str = token.as_deref();

    let url = format!("{}/v1/getinfo", base_url);

    match net_client.post_data_async(&url, "", tokio::time::Duration::from_secs(10), token_str).await {
        Ok(resp) => {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&resp) {
                let reachable = parsed["code"].as_str() == Some("000000");
                if !reachable {
                    log_info!("[connectivity] 探测不可达 (code={})",
                        parsed["code"].as_str().unwrap_or("?"));
                }
                reachable
            } else {
                log_info!("[connectivity] /v1/getinfo 响应解析失败: {}", &resp[..resp.len().min(200)]);
                false
            }
        }
        Err(e) => {
            if AGENT_MODE.load(Ordering::Relaxed) == AgentMode::Online as u8 {
                log_info!("[connectivity] {} 不可达: {}", url, e);
            }
            false
        }
    }
}

/// 后台探测防重入标记：确保同一时刻只有一个探测任务在跑。
static PROBE_RUNNING: AtomicBool = AtomicBool::new(false);

/// 由 gRPC handler 调用：触发后台连通性探测（不阻塞，立即返回）。
/// 探测到不可达时，写入 /proc/osec/tcp_force_ecn 尝试修复准入状态。
pub fn trigger_connectivity_probe() {
    //log_info!("[admission] >>> trigger_connectivity_probe() 被调用");
    if PROBE_RUNNING.swap(true, Ordering::Relaxed) {
        //log_info!("[admission] >>> trigger_connectivity_probe: 已有探测在跑，跳过");
        return;
    }
    //log_info!("[admission] >>> trigger_connectivity_probe: spawn 异步探测任务");
    tokio::spawn(async move {
        //log_info!("[admission] >>> 异步探测: 开始 check_server_reachable()...");
        if check_server_reachable().await {
            //log_info!("[admission] >>> 异步探测: 服务器可达 → set_online()，不触发 repair");
            set_online();
        } else {
            log_info!("[admission] >>> 异步探测: 服务器不可达 → set_offline()");
            let _ = set_offline();
            let admission_enabled = config::net_info::NETINFO_CONFIG
                .lock()
                .map(|c| c.admission.enabled)
                .unwrap_or(false);
            if admission_enabled {
                run_admission_repair();
            } else {
                log_info!("[admission] >>> 准入功能未启用，跳过 repair");
            }
        }
        PROBE_RUNNING.store(false, Ordering::Relaxed);
    });
}

// ── 准入检测全局状态 ──
/// 当前准入模式: 0=OFF, 1=ON, 2=AUTO
pub static ADMISSION_MODE: AtomicU8 = AtomicU8::new(0);
/// 当前准入生效值: 0=关准入(tcp_force_ecn=0), 1=开准入(tcp_force_ecn=1)
/// 仅当 ADMISSION_MODE=2(AUTO) 时才有意义
pub static ADMISSION_EFFECTIVE: AtomicU8 = AtomicU8::new(0);
/// 是否正在自动检测中
pub static ADMISSION_DETECTING: AtomicBool = AtomicBool::new(false);
/// 网络是否异常 — 由 grpc_gateway::agent_mode::ADMISSION_NETWORK_ANOMALY 统一管理，这里 re-export

/// Global jump status — updated by execute_ip_jump / execute_pw_jump.
/// On first access, attempts to restore from local_store (if DB is enabled).
pub static JUMP_STATUS: LazyLock<Mutex<JumpStatus>> = LazyLock::new(|| {
    // 尝试从 SQLite 恢复（需要 [SQLITE_DB] && [DB_POLICY] JUMP_STATUS && [JUMP] ENABLED）
    if let Ok(db_ok) = config::net_info::NETINFO_CONFIG.lock()
        .map(|c| c.sqlite_db.enabled && c.db_policy.jump_status && c.jump.enabled)
    {
        if db_ok {
            if let Ok(Some(row)) = local_store::jump_status::load() {
                let js = JumpStatus {
                    current_ip: row.current_ip,
                    source_ip: row.source_ip,
                    target_ip: row.target_ip,
                    gateway: row.gateway,
                    mode: row.mode,
                    current_password: row.current_password,
                    last_ip_jump_time: row.last_ip_jump_time,
                    last_pw_jump_time: row.last_pw_jump_time,
                    last_pw_jump_user: row.last_pw_jump_user,
                    ip_scheme: row.ip_scheme,
                    ip_cycle_label: row.ip_cycle_label,
                    ip_timing_label: row.ip_timing_label,
                    ip_way_label: row.ip_way_label,
                    pw_scheme: row.pw_scheme,
                    pw_cycle_label: row.pw_cycle_label,
                    pw_timing_label: row.pw_timing_label,
                    ..Default::default()
                };
                log::info!("[JUMP_STATUS] 从 SQLite 恢复跳变状态");
                return Mutex::new(js);
            }
        }
    }
    Mutex::new(JumpStatus::default())
});

/// Central data access hub for gRPC handlers.
/// Wraps existing global variables and provides change notification.
/// Uses the global broadcast channel from grpc_gateway::notify.
#[derive(Clone)]
pub struct AgentDataHub;

impl AgentDataHub {
    pub fn new() -> Self { Self }

    /// Notify all gRPC subscribers that a policy type has changed.
    pub fn notify(&self, change: PolicyChangeType) {
        grpc_gateway::notify::notify_policy_change(change);
    }

    /// Subscribe to policy change notifications (for PolicyWatchService).
    pub fn subscribe_changes(&self) -> tokio::sync::broadcast::Receiver<PolicyChangeType> {
        grpc_gateway::notify::subscribe_policy_changes()
    }

    // ========================================================================
    // Read methods — always available
    // ========================================================================

    /// Get current configuration.
    pub fn get_config(&self) -> config::net_info::NetInfoConfig {
        config::net_info::NETINFO_CONFIG.lock().unwrap().clone()
    }

    /// Get process whitelist or blacklist hashes.
    pub fn get_process_policy(&self, is_white: bool) -> Vec<String> {
        let mgr = process_mgr::POLICY_MANAGER.lock().unwrap();
        if is_white {
            mgr.get_white_list()
        } else {
            mgr.get_black_list()
        }
    }

    /// Get peripheral (USB) whitelist or blacklist.
    pub fn get_peripheral_policy(
        &self,
        is_white: bool,
    ) -> Vec<udisk::device::UsbInfo> {
        let guard = udisk::list::SHARED_USB_LIST.lock().unwrap();
        if is_white {
            guard.get_whitelist().clone()
        } else {
            guard.get_blacklist().clone()
        }
    }

    /// Get IP block policies (async due to tokio::sync::RwLock in netblock).
    pub async fn get_ip_block_policy(&self) -> Vec<netblock::ip_policy::IpPolicy> {
        let guard = netblock::ip_policy::IP_POLICIES.read().await;
        guard.values().cloned().collect()
    }

    /// Get IP blacklist policies.
    pub async fn get_ip_black_policy(&self) -> Vec<netblock::ip_policy::IpPolicy> {
        let guard = netblock::ip_policy::IP_POLICIES.read().await;
        guard.values().cloned().collect()
    }

    /// Get outreach detection rules.
    pub fn get_outreach_rules(&self) -> Vec<task::net_reach_rule::OutreachDetectRule> {
        task::net_reach_rule::get_global_outreach_rules()
    }

    /// Get running process list.
    pub fn get_process_list(
        &self,
    ) -> Result<Vec<procinfo::ProcessInfo>, String> {
        procinfo::get_running_process_infos().map_err(|e| e.to_string())
    }

    /// Get combined process policy — returns both whitelist and blacklist hashes.
    pub fn get_combined_process_policy(&self) -> (Vec<String>, Vec<String>) {
        let mgr = process_mgr::POLICY_MANAGER.lock().unwrap();
        (mgr.get_white_list(), mgr.get_black_list())
    }

    /// Get combined peripheral policy with status annotation.
    /// Returns (UsbInfo, policy_status) where 1=whitelist, 2=blacklist.
    pub fn get_combined_peripheral_policy(
        &self,
    ) -> Vec<(udisk::device::UsbInfo, u8)> {
        let guard = udisk::list::SHARED_USB_LIST.lock().unwrap();
        let white = guard.get_whitelist().clone();
        let black = guard.get_blacklist().clone();

        let mut result = Vec::new();
        for d in &white {
            result.push((d.clone(), 1u8));
        }
        let white_eids: std::collections::HashSet<&str> =
            white.iter().map(|d| d.perpheral_eid.as_str()).collect();
        for d in &black {
            if !white_eids.contains(d.perpheral_eid.as_str()) {
                result.push((d.clone(), 2u8));
            }
        }
        result
    }

    // ========================================================================
    // Write methods — offline only (caller must check require_offline first)
    // ========================================================================

    /// Update config and persist to ini. Only fields present (Some) in the proto are updated.
    /// Fields left as None keep their current values — true partial update.
    pub fn update_config(
        &self,
        updates: &grpc_gateway::config::ConfigData,
    ) -> Result<(), String> {
        let mut guard = config::net_info::NETINFO_CONFIG.lock().unwrap();
        let old_cfg = guard.clone();
        let mut new_cfg = old_cfg.clone();

        // ── macro: only update if field is Some ──
        macro_rules! try_update {
            (@bool $field:ident, $v:expr) => {
                if let Some(val) = $v { new_cfg.$field = val; }
            };
            (@u32 $field:ident, $v:expr) => {
                if let Some(val) = $v { new_cfg.$field = val; }
            };
        }

        try_update!(@u32  cron_time,              updates.crontime);
        try_update!(@bool file_switch,            updates.file_switch);
        try_update!(@bool proc_switch,            updates.proc_switch);
        try_update!(@bool extortion_protect,      updates.extortion_protect);
        try_update!(@bool extortion_switch,       updates.extortion_switch);
        try_update!(@bool file_protect,           updates.file_protect);
        try_update!(@bool self_protect_switch,    updates.self_protect_switch);
        try_update!(@bool open_port_switch,       updates.open_port_switch);
        try_update!(@bool dynamic_switch,         updates.dynamic_switch);
        try_update!(@bool proc_protect,           updates.proc_protect);
        try_update!(@bool usb_protect,            updates.usb_protect);
        try_update!(@bool usb_switch,             updates.usb_switch);
        try_update!(@bool syslog_inner_switch,    updates.syslog_inner_switch);
        try_update!(@bool syslog_outer_switch,    updates.syslog_outer_switch);
        try_update!(@bool syslog_dns_switch,      updates.syslog_dns_switch);
        try_update!(@bool internet_switch,        updates.internet_switch);
        try_update!(@bool syslog_process_switch,  updates.syslog_process_switch);
        try_update!(@bool syslog_login_switch,    updates.syslog_login_switch);
        try_update!(@bool outreach_switch,        updates.outreach_switch);
        try_update!(@bool baseline_switch,        updates.baseline_switch);
        try_update!(@bool hardware_switch,        updates.hardware_switch);
        try_update!(@u32  log_proto,              updates.logproto);
        try_update!(@u32  log_sent,               updates.logsent);
        try_update!(@u32  cli_port,               updates.debug_switch);
        try_update!(@u32  module_switch,          updates.module_switch);
        try_update!(@u32  outreach_time,          updates.outreach_time);
        try_update!(@u32  baseline_time,          updates.baseline_time);
        try_update!(@u32  hardware_time,          updates.hardware_time);

        try_update!(@bool grpc_alert_push, updates.alert_push);

        if let Some(ref s) = updates.logipport {
            if !s.is_empty() {
                new_cfg.log_ip_port = Some(s.clone());
            }
        }

        *guard = new_cfg.clone();
        let ini_path = format!("{}/net_info.ini", guard.app_path);
        guard.to_ini(&ini_path)
            .map_err(|e| format!("写入 {} 失败: {}", ini_path, e))?;

        // 下发配置变更到内核（driver走netlink+procfs，eBPF走BPF maps）
        task::apply_config_diff(&old_cfg, &new_cfg)?;

        self.notify(PolicyChangeType::ConfigChanged);
        Ok(())
    }

    /// Update only two protection-related config fields (proc/usb switch + protect).
    pub fn update_config_fields_protection(
        &self,
        switch_key: &str,
        switch_val: bool,
        protect_key: &str,
        protect_val: bool,
    ) -> Result<(), String> {
        let mut guard = config::net_info::NETINFO_CONFIG.lock().unwrap();
        match switch_key {
            "proc_switch" => guard.proc_switch = switch_val,
            "usb_switch" => guard.usb_switch = switch_val,
            _ => {}
        }
        match protect_key {
            "proc_protect" => guard.proc_protect = protect_val,
            "usb_protect" => guard.usb_protect = protect_val,
            _ => {}
        }
        let ini_path = format!("{}/net_info.ini", guard.app_path);
        guard.to_ini(&ini_path)
            .map_err(|e| format!("写入 {} 失败: {}", ini_path, e))?;
        self.notify(PolicyChangeType::ConfigChanged);
        Ok(())
    }

    /// Update admission mode and persist to ini.
    /// Also writes to /proc/osec/tcp_force_ecn if the driver is loaded.
    /// mode: 0=OFF, 1=ON, 2=AUTO
    pub fn update_admission_mode(
        &self,
        mode: u8,
    ) -> Result<(), String> {
        // 检查功能是否启用
        let enabled = {
            let cfg = config::net_info::NETINFO_CONFIG.lock().unwrap();
            cfg.admission.enabled
        };
        if !enabled {
            return Err("准入功能未启用".to_string());
        }

        // 停止自动检测（如果正在运行）
        ADMISSION_DETECTING.store(false, Ordering::Relaxed);
        ADMISSION_NETWORK_ANOMALY.store(false, Ordering::Relaxed);

        match mode {
            0 => { // OFF — 固定关准入，直接写 proc，不探测网络
                log_info!("[admission] 设置 OFF 模式，写 tcp_force_ecn=0");
                ADMISSION_MODE.store(0, Ordering::Relaxed);
                ADMISSION_EFFECTIVE.store(0, Ordering::Relaxed);
                self.write_admission_proc(false)?;
                self.persist_admission_mode(0, false)?;
            }
            1 => { // ON — 固定开准入，直接写 proc，不探测网络
                log_info!("[admission] 设置 ON 模式，写 tcp_force_ecn=1");
                ADMISSION_MODE.store(1, Ordering::Relaxed);
                ADMISSION_EFFECTIVE.store(1, Ordering::Relaxed);
                self.write_admission_proc(true)?;
                self.persist_admission_mode(1, true)?;
            }
            2 => { // AUTO — 启动自动检测，按网络连通性自动决定
                log_info!("[admission] 设置 AUTO 模式，启动自动检测");
                ADMISSION_MODE.store(2, Ordering::Relaxed);
                self.persist_admission_mode(2, false)?;
                self.start_auto_detect();
            }
            _ => return Err(format!("无效的准入模式: {}", mode)),
        }

        self.notify(PolicyChangeType::ConfigChanged);
        Ok(())
    }

    /// 写入 /proc/osec/tcp_force_ecn（通过 SecurityBackend，驱动/ebpf 自适应）
    pub(crate) fn write_admission_proc(&self, enable: bool) -> Result<(), String> {
        // 优先走 backend 抽象（ebpf 写 BPF maps，driver 写 proc）
        if let Ok(()) = common::backend::with_backend(|b| b.write_tcp_force_ecn(enable)) {
            return Ok(());
        }
        // fallback: 直接写 proc（驱动已加载但 backend 未初始化时可用）
        let proc_path = "/proc/osec/tcp_force_ecn";
        if std::path::Path::new(proc_path).exists() {
            let val = if enable { "1" } else { "0" };
            std::fs::write(proc_path, val)
                .map_err(|e| format!("写入 {} 失败: {}", proc_path, e))?;
            log_info!("[admission] 已写入 {} = {}", proc_path, val);
        } else {
            log_info!("[admission] {} 不存在，跳过写入（驱动未加载）", proc_path);
        }
        Ok(())
    }

    /// 持久化准入模式到 ini
    /// mode: 0=OFF, 1=ON, 2=AUTO
    /// effective: 当前 tcp_force_ecn 的生效值 (true=1, false=0)
    fn persist_admission_mode(&self, mode: u8, effective: bool) -> Result<(), String> {
        let mut guard = config::net_info::NETINFO_CONFIG.lock().unwrap();
        guard.admission.mode = mode;
        guard.admission_switch = effective;
        let ini_path = format!("{}/net_info.ini", guard.app_path);
        guard.to_ini(&ini_path)
            .map_err(|e| format!("写入 {} 失败: {}", ini_path, e))?;
        Ok(())
    }

    /// 启动自动检测（spawn 异步任务）
    pub fn start_auto_detect(&self) {
        ADMISSION_DETECTING.store(true, Ordering::Relaxed);
        ADMISSION_NETWORK_ANOMALY.store(false, Ordering::Relaxed);
        log_info!("[admission] 启动自动检测");

        let data_hub = AgentDataHub::new();
        tokio::spawn(async move {
            let (retry_interval, max_retries) = {
                let cfg = config::net_info::NETINFO_CONFIG.lock().unwrap();
                (cfg.admission.retry_interval, cfg.admission.max_retries)
            }; // cfg dropped here

            let mut round = 0u32;
            loop {
                if !ADMISSION_DETECTING.load(Ordering::Relaxed) {
                    log_info!("[admission] 自动检测已停止");
                    return;
                }

                round += 1;
                log_info!("[admission] 第 {} 轮自动检测", round);

                // 1. 尝试关准入
                let _ = data_hub.write_admission_proc(false);
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                if !ADMISSION_DETECTING.load(Ordering::Relaxed) {
                    log_info!("[admission] 自动检测已被取消（切到固定模式），停止");
                    return;
                }
                if check_server_reachable().await {
                    log_info!("[admission] 关准入可上线，设置 effective=OFF，恢复在线");
                    if !ADMISSION_DETECTING.load(Ordering::Relaxed) {
                        log_info!("[admission] 自动检测已被取消，放弃持久化");
                        return;
                    }
                    ADMISSION_EFFECTIVE.store(0, Ordering::Relaxed);
                    let _ = data_hub.persist_admission_mode(2, false);
                    ADMISSION_DETECTING.store(false, Ordering::Relaxed);
                    ADMISSION_NETWORK_ANOMALY.store(false, Ordering::Relaxed);
                    set_online();
                    data_hub.notify(PolicyChangeType::ConfigChanged);
                    return;
                }

                if !ADMISSION_DETECTING.load(Ordering::Relaxed) { return; }

                // 2. 尝试开准入
                let _ = data_hub.write_admission_proc(true);
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                if !ADMISSION_DETECTING.load(Ordering::Relaxed) {
                    log_info!("[admission] 自动检测已被取消（切到固定模式），停止");
                    return;
                }
                if check_server_reachable().await {
                    log_info!("[admission] 开准入可上线，设置 effective=ON，恢复在线");
                    if !ADMISSION_DETECTING.load(Ordering::Relaxed) {
                        log_info!("[admission] 自动检测已被取消，放弃持久化");
                        return;
                    }
                    ADMISSION_EFFECTIVE.store(1, Ordering::Relaxed);
                    let _ = data_hub.persist_admission_mode(2, true);
                    ADMISSION_DETECTING.store(false, Ordering::Relaxed);
                    ADMISSION_NETWORK_ANOMALY.store(false, Ordering::Relaxed);
                    set_online();
                    data_hub.notify(PolicyChangeType::ConfigChanged);
                    return;
                }

                if !ADMISSION_DETECTING.load(Ordering::Relaxed) { return; }

                // 3. 两种都不行
                if round < max_retries {
                    log_info!("[admission] 第 {} 轮检测失败，{} 秒后重试", round, retry_interval);
                    ADMISSION_NETWORK_ANOMALY.store(true, Ordering::Relaxed);
                    tokio::time::sleep(tokio::time::Duration::from_secs(retry_interval)).await;
                } else {
                    log_error!("[admission] {} 轮检测均失败，网络异常", max_retries);
                    ADMISSION_NETWORK_ANOMALY.store(true, Ordering::Relaxed);
                    // 继续循环，无限重试直到网络恢复或被手动停止
                    tokio::time::sleep(tokio::time::Duration::from_secs(retry_interval)).await;
                    round = 0; // 重置轮次，继续无限重试
                }
            }
        });
    }

    /// Update process policy (white/black list). action: 0=移除, 1=白名单, 2=黑名单
    pub fn update_process_policy(
        &self,
        hashes: &[String],
        action: i32,
    ) -> Result<(), String> {
        let mut mgr = process_mgr::POLICY_MANAGER.lock().unwrap();
        match action {
            0 => {
                // 移除：从两个名单中都删除这些 hash
                let whitelist: Vec<String> = mgr.get_white_list().into_iter()
                    .filter(|h| !hashes.contains(h)).collect();
                let blacklist: Vec<String> = mgr.get_black_list().into_iter()
                    .filter(|h| !hashes.contains(h)).collect();
                mgr.set_policy_process(&whitelist, true, Some(true));
                mgr.set_policy_process(&blacklist, false, Some(true));
                drop(mgr);
                self.notify(PolicyChangeType::ProcessPolicyChanged);
                return Ok(());
            }
            1 | 2 => {
                let is_white = action == 1;
                // gRPC 本地调用时合并而非替换：先取现有名单，追加新 hash 后再下发
                let existing = if is_white { mgr.get_white_list() } else { mgr.get_black_list() };
                let mut merged: Vec<String> = existing;
                for h in hashes {
                    if !merged.contains(h) {
                        merged.push(h.clone());
                    }
                }
                mgr.set_policy_process(&merged, is_white, Some(true));
                drop(mgr);
                self.notify(PolicyChangeType::ProcessPolicyChanged);
                Ok(())
            }
            _ => Err(format!("无效 action: {}", action)),
        }
    }

    /// Update peripheral (USB) policy. action: 0=移除, 1=白名单, 2=黑名单
    pub fn update_peripheral_policy(
        &self,
        devices: &[udisk::device::UsbInfo],
        action: i32,
    ) -> Result<(), String> {
        let usb_protect = config::net_info::NETINFO_CONFIG.lock().unwrap().usb_protect;
        {
            let mut guard = udisk::list::SHARED_USB_LIST.lock().unwrap();
            match action {
                0 => {
                    let eids: Vec<String> = devices.iter().map(|d| d.perpheral_eid.clone()).collect();
                    guard.remove_from_both(&eids);
                }
                1 => guard.update_whitelist(devices.to_vec()),
                2 => guard.update_blacklist(devices.to_vec(), usb_protect),
                _ => return Err(format!("无效 action: {}", action)),
            }
        } // SHARED_USB_LIST 锁在此释放，避免 save_peripheral_policy_to_db 内部再次加锁死锁
        self.notify(PolicyChangeType::PeripheralPolicyChanged);
        // 持久化外设黑白名单到离线本地表（受开关控制）
        save_peripheral_policy_to_db();

        // 黑名单 + usb_protect 开启时，物理禁用设备（锁已释放，不会死锁）
        if action == 2 && usb_protect {
            let eids: Vec<String> = devices.iter().map(|d| d.perpheral_eid.clone()).collect();
            log_info!("[peripheral_policy] usb_protect 开启，禁用 {} 个黑名单设备", eids.len());
            std::thread::spawn(move || {
                udisk::monitor::handle_blacklist_update(&eids);
            });
        }

        Ok(())
    }

    /// Update IP block policies (async — writes to kernel via netblock).
    pub async fn update_ip_block_policy(
        &self,
        items: &[netblock::ip_policy::IpPolicy],
    ) -> Result<(), String> {
        netblock::ip_policy::update_and_write_policies(items.to_vec()).await?;
        self.notify(PolicyChangeType::IpBlockPolicyChanged);
        Ok(())
    }

    /// Update outreach detection rules.
    pub fn update_outreach_rules(
        &self,
        rules: Vec<task::net_reach_rule::OutreachDetectRule>,
    ) -> Result<(), String> {
        task::net_reach_rule::update_global_outreach_rules(rules);
        self.notify(PolicyChangeType::OutreachRulesChanged);
        Ok(())
    }

    // ========================================================================
    // Jump operations (offline only)
    // ========================================================================

    /// Execute IP jump. Returns (source_ip, target_ip, gateway, status, reason).
    pub async fn execute_ip_jump(
        &self,
        gateway: &str,
        source_ip: &str,
        target_ip: &str,
        mode: u32,
    ) -> Result<(String, String, String, u8, String), String> {
        // 检查跳变开关：[JUMP] ENABLED=0 → 整个功能不可用
        if !jump_enabled() {
            return Err("IP跳变功能未启用 ([JUMP] ENABLED=0)".to_string());
        }
        if !jump_ip_enabled() {
            return Err("IP跳变功能未启用 ([JUMP] IP_JUMP=0)".to_string());
        }
        let ifcfg = {
            config::net_info::NETINFO_CONFIG.lock().unwrap().ifcfg.clone()
        };
        let manager = rules_jump_mgr::IpJumpManager::new(&ifcfg);
        let config = rules_jump_mgr::IpJumpConfig {
            source_ip: source_ip.to_string(),
            target_ip: target_ip.to_string(),
            gateway: gateway.to_string(),
        };
        let mut info = rules_jump_mgr::PutIpJumpInfo {
            source_ip: String::new(),
            target_ip: String::new(),
            gateway: String::new(),
            agent_ip: String::new(),
            status: 0,
            reason: String::new(),
        };
        match manager.do_ip_jump_async(config, &mut info, mode).await {
            Ok(_) => {
                info.status = 1;
            }
            Err(e) => {
                info.status = 2;
                info.reason = e.to_string();
            }
        }

        // Update global jump status
        if info.status == 1 {
            let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            let mut js = JUMP_STATUS.lock().unwrap();
            js.current_ip = info.target_ip.clone();
            js.source_ip = info.source_ip.clone();
            js.target_ip = info.target_ip.clone();
            js.gateway = info.gateway.clone();
            js.mode = mode;
            js.last_ip_jump_time = now;
        }

        self.notify(PolicyChangeType::JumpStatusChanged);
        save_jump_status_to_db();

        // 在线模式下，IP 跳变成功后异步更新服务器最新跳变信息并持久化
        if info.status == 1 {
            let hub = self.clone();
            tokio::spawn(async move { hub.fetch_newest_jump_info().await; });
        }

        Ok((info.source_ip, info.target_ip, info.gateway, info.status, info.reason))
    }

    // ========================================================================
    // TrustDir operations
    // ========================================================================

    /// Get global trust directories from cache.
    pub fn get_trust_dir(&self) -> Vec<pattern::GlobalTrustDir> {
        grpc_gateway::notify::TRUST_DIR_CACHE.lock().unwrap()
            .iter()
            .map(|d| pattern::GlobalTrustDir {
                dir: d.dir.clone(),
                typ: d.r#type as u8,
                is_extend: d.is_extend as u8,
            })
            .collect()
    }

    /// Update global trust directories and push to kernel + cache.
    pub fn update_trust_dir(&self, dirs: Vec<pattern::GlobalTrustDir>) -> Result<(), String> {
        // Update cache (proto types)
        *grpc_gateway::notify::TRUST_DIR_CACHE.lock().unwrap() = dirs
            .iter()
            .map(|d| grpc_gateway::trust_dir::GlobalTrustDir {
                dir: d.dir.clone(),
                r#type: d.typ as u32,
                is_extend: d.is_extend as u32,
            })
            .collect();
        // Push to kernel
        pattern::process_pattern_rules_mgr::PROCESS_PATTERN_RULES_MGR
            .lock()
            .set_global_trust_dir(dirs);
        self.notify(PolicyChangeType::TrustDirChanged);
        Ok(())
    }

    // ========================================================================
    // VirtualPort operations
    // ========================================================================

    /// Write virtual port rules to /proc/osec/net_rules + cache.
    pub async fn update_virtual_port(
        &self,
        rules: Vec<task::virtual_port_rule::VirtualPortRule>,
    ) -> Result<(), String> {
        // Update cache (proto types)
        let proto_rules: Vec<grpc_gateway::virtual_port::VirtualPortRule> = rules
            .iter()
            .map(|r| grpc_gateway::virtual_port::VirtualPortRule {
                alarm_level: r.alarm_level,
                dest_ip: r.dest_ip.clone(),
                dest_port: r.dest_port.clone(),
                dest_port_type: r.dest_port_type,
                id: r.id,
                protocol: r.protocol.clone(),
                source_ip: r.source_ip.clone(),
                source_port_start: r.source_port_range.0 as u32,
                source_port_end: r.source_port_range.1 as u32,
                r#type: r.r#type.clone(),
            })
            .collect();
        *grpc_gateway::notify::VIRTUAL_PORT_CACHE.lock().unwrap() = proto_rules;
        let valid_rules: Vec<_> = rules.into_iter()
            .filter(|r| !r.source_ip.is_empty())
            .collect();

        if valid_rules.is_empty() {
            return Ok(());
        }

        let total = valid_rules.len();
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open("/proc/osec/net_rules")
            .await
            .map_err(|e| format!("Failed to open /proc/osec/net_rules: {}", e))?;

        use tokio::io::AsyncWriteExt;
        for (index, rule) in valid_rules.iter().enumerate() {
            let protocol_num = match rule.protocol.to_lowercase().as_str() {
                "tcp" => 1,
                "udp" => 2,
                _ => 0,
            };
            let is_ipv4 = if rule.dest_ip.contains(':') { 0u8 } else { 1u8 };
            let addr_type = (rule.alarm_level & 0x1f) as u8;

            let rule_str = format!(
                "VIR_OPEN_PORT index={} total={} id={} protocol={} type={} is_ipv4={} source_ip={} start_port={} end_port={} dest_ip={} dest_port_type={} redirectPort={} addr_type={}\n",
                index, total, rule.id, protocol_num, rule.r#type, is_ipv4,
                rule.source_ip, rule.source_port_range.0, rule.source_port_range.1,
                if rule.dest_ip.trim().is_empty() { "\"\"" } else { &rule.dest_ip },
                rule.dest_port_type,
                if rule.dest_port_type == 0 { rule.dest_port.parse::<u16>().unwrap_or(0) } else { 0 },
                addr_type,
            );
            file.write_all(rule_str.as_bytes()).await
                .map_err(|e| format!("Failed to write rule: {}", e))?;
        }
        file.flush().await.map_err(|e| format!("Flush failed: {}", e))?;
        drop(file);

        self.notify(PolicyChangeType::VirtualPortChanged);
        Ok(())
    }

    // ========================================================================
    // Backup operations
    // ========================================================================

    /// Create a system snapshot.
    pub async fn create_backup(&self, name: &str) -> Result<String, String> {
        let id = snapman::create_snapshot(name, "").await.map_err(|e| format!("{:?}", e))?;
        self.notify(PolicyChangeType::BackupListChanged);
        Ok(id)
    }

    /// Restore a system snapshot.
    pub async fn restore_backup(&self, backup_id: &str) -> Result<(), String> {
        snapman::restore_snapshot(backup_id).await.map_err(|e| format!("{:?}", e))?;
        self.notify(PolicyChangeType::BackupListChanged);
        Ok(())
    }

    // ========================================================================
    // DirPolicy cache operations
    // ========================================================================

    pub fn get_cached_dir_policy(&self) -> Vec<DirectionScanRule> {
        grpc_gateway::notify::DIR_POLICY_CACHE.lock().unwrap().clone()
    }

    pub fn set_cached_dir_policy(&self, rules: Vec<DirectionScanRule>) {
        *grpc_gateway::notify::DIR_POLICY_CACHE.lock().unwrap() = rules;
        self.notify(PolicyChangeType::DirPolicyChanged);
    }

    // ========================================================================
    // ExtortPolicy cache operations
    // ========================================================================

    pub fn get_cached_extort_policy(&self) -> Vec<ExtortProtectRule> {
        grpc_gateway::notify::EXTORT_POLICY_CACHE.lock().unwrap().clone()
    }

    pub fn set_cached_extort_policy(&self, rules: Vec<ExtortProtectRule>) {
        *grpc_gateway::notify::EXTORT_POLICY_CACHE.lock().unwrap() = rules;
        self.notify(PolicyChangeType::ExtortPolicyChanged);
    }

    /// Execute password jump. Returns (status, reason).
    pub async fn execute_pw_jump(
        &self,
        new_password: &str,
    ) -> Result<(u8, String), String> {
        // 检查跳变开关：[JUMP] ENABLED=0 → 整个功能不可用
        if !jump_enabled() {
            return Err("口令跳变功能未启用 ([JUMP] ENABLED=0)".to_string());
        }
        if !jump_pw_enabled() {
            return Err("口令跳变功能未启用 ([JUMP] PW_JUMP=0)".to_string());
        }
        let mgr = rules_jump_mgr::PasswordManager::new();
        let mut info = rules_jump_mgr::PutPwJumpInfo {
            user: String::new(),
            pw: String::new(),
            status: 0,
            reason: String::new(),
        };
        match mgr.do_pw_jump_async("", new_password, &mut info).await {
            Ok(_) => {
                info.pw = new_password.to_string();
                info.status = 1;
            }
            Err(e) => {
                info.pw = new_password.to_string();
                info.status = 2;
                info.reason = e.to_string();
            }
        }

        // Update global jump status
        if info.status == 1 {
            let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            let mut js = JUMP_STATUS.lock().unwrap();
            js.current_password = new_password.to_string();
            js.last_pw_jump_user = info.user.clone();
            js.last_pw_jump_time = now;
        }

        self.notify(PolicyChangeType::JumpStatusChanged);
        save_jump_status_to_db();

        // 在线模式下，口令跳变成功后异步更新服务器最新跳变信息并持久化
        if info.status == 1 {
            let hub = self.clone();
            tokio::spawn(async move { hub.fetch_newest_jump_info().await; });
        }

        Ok((info.status, info.reason))
    }

    // ========================================================================
    // Jump — 从服务器拉取最新跳变信息
    // ========================================================================

    /// 调用服务器 /v1/newestJumpInfo，将结果合并到全局 JUMP_STATUS 并持久化到 jump.db。
    ///
    /// 触发时机：
    ///   1. 程序启动且处于在线模式（token 就绪后）
    ///   2. execute_ip_jump 成功后
    ///   3. execute_pw_jump 成功后
    ///
    /// 安全规则：
    ///   - [JUMP] ENABLED=0 直接返回，不请求服务器
    ///   - 离线模式直接返回
    ///   - 请求失败/超时/非 000000 → 不更新内存缓存，不写数据库
    pub async fn fetch_newest_jump_info(&self) {
        let jump_enabled = config::net_info::NETINFO_CONFIG
            .lock()
            .map(|c| c.jump.enabled)
            .unwrap_or(false);
        if !jump_enabled {
            log::debug!("[newestJumpInfo] [JUMP] ENABLED=0，跳过");
            return;
        }

        if AGENT_MODE.load(Ordering::Relaxed) != AgentMode::Online as u8 {
            log::debug!("[newestJumpInfo] 当前离线模式，跳过");
            return;
        }

        let base_url = {
            let cfg = config::net_info::NETINFO_CONFIG.lock().unwrap();
            format!("https://{}:{}", cfg.server_ip, cfg.server_port)
        };
        let token_ref = CURRENT_TOKEN.lock().unwrap().clone();
        let token_str = token_ref.as_deref();

        let net_client = match net_client::core::NetClient::new(Some(base_url.clone()), true) {
            Ok(c) => c,
            Err(e) => {
                log::error!("[newestJumpInfo] 创建 NetClient 失败: {}", e);
                return;
            }
        };

        let url = format!("{}/v1/newestJumpInfo", base_url);
        match net_client.get_data_async(&url, tokio::time::Duration::from_secs(5), token_str).await {
            Ok(resp) => {
                match serde_json::from_str::<serde_json::Value>(&resp) {
                    Ok(v) if v["code"].as_str() == Some("000000") => {
                        let data = &v["data"];
                        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

                        // 更新内存缓存
                        let row = {
                            let mut js = JUMP_STATUS.lock().unwrap();
                            // IP 跳变信息
                            if let Some(ip_jump) = data["ip_jump"].as_object() {
                                if let Some(ip) = ip_jump.get("ip").and_then(|v| v.as_str()) {
                                    js.current_ip = ip.to_string();
                                }
                                if let Some(scheme) = ip_jump.get("scheme").and_then(|v| v.as_u64()) {
                                    js.ip_scheme = scheme as u32;
                                }
                                if let Some(s) = ip_jump.get("cycle_label").and_then(|v| v.as_str()) {
                                    js.ip_cycle_label = s.to_string();
                                }
                                if let Some(s) = ip_jump.get("timing_label").and_then(|v| v.as_str()) {
                                    js.ip_timing_label = s.to_string();
                                }
                                if let Some(s) = ip_jump.get("way_label").and_then(|v| v.as_str()) {
                                    js.ip_way_label = s.to_string();
                                }
                            }
                            // 口令跳变信息
                            if let Some(pw_jump) = data["pw_jump"].as_object() {
                                if let Some(pw) = pw_jump.get("pw").and_then(|v| v.as_str()) {
                                    js.current_password = pw.to_string();
                                }
                                if let Some(scheme) = pw_jump.get("scheme").and_then(|v| v.as_u64()) {
                                    js.pw_scheme = scheme as u32;
                                }
                                if let Some(s) = pw_jump.get("cycle_label").and_then(|v| v.as_str()) {
                                    js.pw_cycle_label = s.to_string();
                                }
                                if let Some(s) = pw_jump.get("timing_label").and_then(|v| v.as_str()) {
                                    js.pw_timing_label = s.to_string();
                                }
                            }
                            // 构造持久化行
                            local_store::jump_status::JumpStatusRow {
                                current_ip:        js.current_ip.clone(),
                                source_ip:         js.source_ip.clone(),
                                target_ip:         js.target_ip.clone(),
                                gateway:           js.gateway.clone(),
                                mode:              js.mode,
                                current_password:  js.current_password.clone(),
                                last_ip_jump_time: js.last_ip_jump_time.clone(),
                                last_pw_jump_time: js.last_pw_jump_time.clone(),
                                last_pw_jump_user: js.last_pw_jump_user.clone(),
                                ip_scheme:         js.ip_scheme,
                                ip_cycle_label:    js.ip_cycle_label.clone(),
                                ip_timing_label:   js.ip_timing_label.clone(),
                                ip_way_label:      js.ip_way_label.clone(),
                                pw_scheme:         js.pw_scheme,
                                pw_cycle_label:    js.pw_cycle_label.clone(),
                                pw_timing_label:   js.pw_timing_label.clone(),
                                updated_at:        now,
                            }
                        };

                        // 持久化（在锁外执行）
                        if let Err(e) = local_store::jump_status::upsert(&row) {
                            log::error!("[newestJumpInfo] 写入 jump.db 失败: {}", e);
                        }
                        log::info!("[newestJumpInfo] 同步并持久化成功");
                    }
                    Ok(v) => {
                        log::error!("[newestJumpInfo] 服务器返回非成功 code: {}", v["code"]);
                    }
                    Err(e) => {
                        log::error!("[newestJumpInfo] 响应解析失败: {}", e);
                    }
                }
            }
            Err(e) => {
                log::error!("[newestJumpInfo] 请求失败: {}", e);
            }
        }
    }

    // ── 后端模式查询/设置 ──

    /// 获取当前后端模式 (配置值, 生效值, 网口)
    pub fn get_backend_mode(&self) -> (String, String, String) {
        let cfg = config::net_info::NETINFO_CONFIG.lock().unwrap();
        let configured = cfg.backend_mode.clone();
        let effective = match common::backend::get_backend() {
            Some(ref b) => b.name().to_string(),
            None => configured.clone(),
        };
        let interface = if effective == "ebpf" {
            cfg.ifcfg.clone()
        } else {
            String::new()
        };
        (configured, effective, interface)
    }

    /// 更新后端模式，同步到 net_info.ini，返回是否需要重启
    pub fn update_backend_mode(&self, new_mode: &str) -> Result<bool, String> {
        let effective = match common::backend::get_backend() {
            Some(b) => b.name().to_string(),
            None => String::new(),
        };

        let need_restart = effective != new_mode;

        // 写入 ini
        let mut cfg = config::net_info::NETINFO_CONFIG.lock().unwrap();
        cfg.backend_mode = new_mode.to_string();
        let app_path = cfg.app_path.clone();
        let ini_path = format!("{}/net_info.ini", app_path);
        cfg.to_ini(&ini_path)
            .map_err(|e| format!("写入 {} 失败: {}", ini_path, e))?;

        log_info!("[backend] 模式已更新: {} -> {} (重启={})", effective, new_mode, need_restart);
        Ok(need_restart)
    }

    // ── 外设策略 DB 持久化 ──

    /// 从 SQLite 在线基线表加载外设黑白名单到内存
    pub fn load_peripheral_policy_from_db() {
        Self::load_peripheral_policy_from(false)
    }

    /// 从 SQLite 离线本地表加载外设黑白名单到内存
    pub fn load_peripheral_policy_from_db_local() {
        Self::load_peripheral_policy_from(true)
    }

    /// 合并加载在线表和离线本地表，确保用户本地修改不丢失
    pub fn load_peripheral_policy_merged() {
        // 先加载在线表（服务器策略），再加载本地表（用户修改）覆盖同名 eid
        Self::load_peripheral_policy_from(false);
        Self::merge_peripheral_policy_from_local();
    }

    fn merge_peripheral_policy_from_local() {
        if !local_store::sqlite_db_enabled() {
            return;
        }
        let db_ok = config::net_info::NETINFO_CONFIG
            .lock()
            .map(|c| c.db_policy.peripheral_policy)
            .unwrap_or(false);
        if !db_ok {
            return;
        }
        let result = local_store::peripheral_policy::load_all_local();
        match result {
            Ok(rows) => {
                let mut guard = udisk::list::SHARED_USB_LIST.lock().unwrap();
                let online_eids: HashSet<String> = guard
                    .get_whitelist().iter()
                    .chain(guard.get_blacklist().iter())
                    .map(|d| d.perpheral_eid.clone())
                    .collect();
                for row in rows {
                    // 只合并在线表中不存在的设备，避免本地过期数据覆盖服务器权威策略
                    if online_eids.contains(&row.peripheral_eid) {
                        continue;
                    }
                    let info = udisk::device::UsbInfo::new(
                        row.peripheral_eid, row.peripheral_name,
                        row.intro, row.type_, false,
                    );
                    if row.is_white {
                        guard.update_whitelist_single(info);
                    } else {
                        guard.update_blacklist_single(info);
                    }
                }
                log::info!(
                    "[peripheral_policy] 从 DB(local) 合并: {} 白, {} 黑",
                    guard.get_whitelist().len(), guard.get_blacklist().len()
                );
            }
            Err(e) => {
                logging::log_error!("[peripheral_policy] 从 DB(local) 合并失败: {}", e);
            }
        }
    }

    fn load_peripheral_policy_from(local: bool) {
        if !local_store::sqlite_db_enabled() {
            return;
        }
        let db_ok = config::net_info::NETINFO_CONFIG
            .lock()
            .map(|c| c.db_policy.peripheral_policy)
            .unwrap_or(false);
        if !db_ok {
            return;
        }
        let result = if local {
            local_store::peripheral_policy::load_all_local()
        } else {
            local_store::peripheral_policy::load_all()
        };
        match result {
            Ok(rows) => {
                let mut white = vec![];
                let mut black = vec![];
                for row in rows {
                    let info = udisk::device::UsbInfo::new(
                        row.peripheral_eid, row.peripheral_name,
                        row.intro, row.type_, false,
                    );
                    if row.is_white { white.push(info); } else { black.push(info); }
                }
                let mut guard = udisk::list::SHARED_USB_LIST.lock().unwrap();
                *guard = udisk::list::BlackWhiteList::from_vecs(black, white);
                log::info!(
                    "[peripheral_policy] 从 DB({}) 加载: {} 白, {} 黑",
                    if local { "local" } else { "online" },
                    guard.get_whitelist().len(), guard.get_blacklist().len()
                );
            }
            Err(e) => {
                logging::log_error!("[peripheral_policy] 从 DB 加载失败: {}", e);
            }
        }
    }
}

/// 将当前外设黑白名单持久化到 SQLite 离线本地表
fn save_peripheral_policy_to_db() {
    // 只要 SQLite 已启用就保存；不再受 db_policy.peripheral_policy 开关限制
    // （该开关只控制启动时是否"加载"，用户显式修改策略后必须持久化）
    let db_ok = config::net_info::NETINFO_CONFIG
        .lock()
        .map(|c| c.sqlite_db.enabled)
        .unwrap_or(false);
    if !db_ok {
        return;
    }
    let guard = udisk::list::SHARED_USB_LIST.lock().unwrap();
    let white: Vec<local_store::peripheral_policy::PeripheralPolicyRow> = guard
        .get_whitelist().iter()
        .map(|d| local_store::peripheral_policy::PeripheralPolicyRow {
            peripheral_eid: d.perpheral_eid.clone(),
            peripheral_name: d.perpheral_name.clone(),
            intro: d.intro.clone(),
            type_: d.type_.clone(),
            is_white: true,
        }).collect();
    let black: Vec<local_store::peripheral_policy::PeripheralPolicyRow> = guard
        .get_blacklist().iter()
        .map(|d| local_store::peripheral_policy::PeripheralPolicyRow {
            peripheral_eid: d.perpheral_eid.clone(),
            peripheral_name: d.perpheral_name.clone(),
            intro: d.intro.clone(),
            type_: d.type_.clone(),
            is_white: false,
        }).collect();
    // 同时写在线表和离线表，避免在线重启后 load_all 读不到 save_all_local 写入的数据
    if let Err(e) = local_store::peripheral_policy::save_all(&white, &black) {
        logging::log_error!("[peripheral_policy] 持久化到在线表失败: {}", e);
    }
    if let Err(e) = local_store::peripheral_policy::save_all_local(&white, &black) {
        logging::log_error!("[peripheral_policy] 持久化到离线本地表失败: {}", e);
    }
}

impl Default for AgentDataHub {
    fn default() -> Self {
        Self::new()
    }
}

/// 跳变总闸：[JUMP] ENABLED
fn jump_enabled() -> bool {
    config::net_info::NETINFO_CONFIG
        .lock()
        .map(|c| c.jump.enabled)
        .unwrap_or(false)
}

/// IP 跳变：[JUMP] ENABLED && IP_JUMP
fn jump_ip_enabled() -> bool {
    config::net_info::NETINFO_CONFIG
        .lock()
        .map(|c| c.jump.enabled && c.jump.ip_jump)
        .unwrap_or(false)
}

/// 口令跳变：[JUMP] ENABLED && PW_JUMP
fn jump_pw_enabled() -> bool {
    config::net_info::NETINFO_CONFIG
        .lock()
        .map(|c| c.jump.enabled && c.jump.pw_jump)
        .unwrap_or(false)
}

/// 将当前 JUMP_STATUS 持久化到 SQLite（如果 DB 和 JUMP 开关已开启）
fn save_jump_status_to_db() {
    // 依赖链：[SQLITE_DB] && [DB_POLICY] JUMP_STATUS && [JUMP] ENABLED
    let db_ok = config::net_info::NETINFO_CONFIG
        .lock()
        .map(|c| c.sqlite_db.enabled && c.db_policy.jump_status && c.jump.enabled)
        .unwrap_or(false);
    if !db_ok {
        return;
    }
    let js = JUMP_STATUS.lock().unwrap();
    let row = local_store::jump_status::JumpStatusRow {
        current_ip: js.current_ip.clone(),
        source_ip: js.source_ip.clone(),
        target_ip: js.target_ip.clone(),
        gateway: js.gateway.clone(),
        mode: js.mode,
        current_password: js.current_password.clone(),
        last_ip_jump_time: js.last_ip_jump_time.clone(),
        last_pw_jump_time: js.last_pw_jump_time.clone(),
        last_pw_jump_user: js.last_pw_jump_user.clone(),
        ip_scheme: js.ip_scheme,
        ip_cycle_label: js.ip_cycle_label.clone(),
        ip_timing_label: js.ip_timing_label.clone(),
        ip_way_label: js.ip_way_label.clone(),
        pw_scheme: js.pw_scheme,
        pw_cycle_label: js.pw_cycle_label.clone(),
        pw_timing_label: js.pw_timing_label.clone(),
        ..Default::default()
    };
    if let Err(e) = local_store::jump_status::upsert(&row) {
        logging::log_error!("[jump_status] 持久化失败: {}", e);
    }
}

// Helper functions — same as in task_fetcher.rs
pub fn get_u32(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u32, String> {
    map.get(key)
        .and_then(|v| v.as_number().and_then(|n| n.as_u64()))
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| format!("Missing or invalid field: {}", key))
}

pub fn get_bool(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<bool, String> {
    map.get(key)
        .and_then(|v| {
            // proto bool → JSON true/false
            if let Some(b) = v.as_bool() {
                return Some(b);
            }
            // server HTTP JSON → 0/1
            if let Some(n) = v.as_number().and_then(|n| n.as_u64()) {
                return Some(n != 0);
            }
            None
        })
        .ok_or_else(|| format!("Missing or invalid field: {}", key))
}
