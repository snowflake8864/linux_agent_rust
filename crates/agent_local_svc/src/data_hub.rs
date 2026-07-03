use std::sync::{Mutex, LazyLock, atomic::{AtomicBool, AtomicU8, Ordering}};

use logging::{log_info, log_error};
use grpc_gateway::policy_watch::PolicyChangeType;
use grpc_gateway::dir_policy::DirectionScanRule;
use grpc_gateway::extort_policy::ExtortProtectRule;
use grpc_gateway::jump::JumpStatus;

// Re-export from grpc_gateway so downstream code keeps working
pub use grpc_gateway::agent_mode::{AgentMode, AGENT_MODE, ADMISSION_NETWORK_ANOMALY, require_offline, set_online, set_offline};

/// 全局 token 缓存，token 获取时由 online 模块更新，check_server_reachable 读取。
static CURRENT_TOKEN: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

/// 由 online 模块在获取到 token 时调用，供 check_server_reachable 使用。
/// 同时触发一次 newestJumpInfo 拉取：这是启动后有效 token 的第一个时机。
pub fn update_token(token: String) {
    *CURRENT_TOKEN.lock().unwrap() = Some(token);
    // token 就绪后立即异步担发一次 fetch，更新跳变状态缓存并持久化
    tokio::spawn(async move {
        AgentDataHub::new().fetch_newest_jump_info().await;
    });
}

/// 断线时调用：尝试切离线 + 如果真正切了且准入模式是 AUTO 则重新触发自动检测。
/// 调用方不需要关心阈值——set_offline 内部会累计失败次数。
/// 是否启用 DB 策略持久化
fn db_policy_enabled() -> bool {
    config::net_info::NETINFO_CONFIG.lock().unwrap().db_policy.enabled
}

/// 切在线时，若 DB_POLICY 启用，从在线表恢复策略
fn restore_online_policies_from_db() {
    let cfg = config::net_info::NETINFO_CONFIG.lock().unwrap();
    if !cfg.db_policy.enabled {
        return;
    }
    drop(cfg);
    AgentDataHub::load_peripheral_policy_from(false);
    process_mgr::POLICY_MANAGER.lock().unwrap().load_policy_from_db(false);
}

/// 切离线时从 DB 本地表恢复离线策略（仅 DB_POLICY 启用时）
fn reload_local_policies_on_offline() {
    let db_enabled = config::net_info::NETINFO_CONFIG.lock().unwrap().db_policy.enabled;
    if db_enabled {
        AgentDataHub::load_peripheral_policy_from_db_local();
        process_mgr::POLICY_MANAGER.lock().unwrap().load_policy_from_db(true);
    }
}

pub fn set_offline_and_check_admission() {
    if !set_offline() {
        return; // 还没到阈值，未真正切离线
    }

    reload_local_policies_on_offline();

    let admission_enabled = {
        let cfg = config::net_info::NETINFO_CONFIG.lock().unwrap();
        cfg.admission.enabled
    };
    if admission_enabled && ADMISSION_MODE.load(Ordering::Relaxed) == 2 && !ADMISSION_DETECTING.load(Ordering::Relaxed) {
        log_info!("[admission] 断线且 AUTO 模式，重新启动自动检测");
        let hub = AgentDataHub::new();
        hub.start_auto_detect();
    }
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
/// handler 读 AGENT_MODE / ADMISSION_NETWORK_ANOMALY 缓存值，响应零延迟。
pub fn trigger_connectivity_probe() {
    if PROBE_RUNNING.swap(true, Ordering::Relaxed) {
        return; // 已有探测在跑，跳过
    }
    tokio::spawn(async move {
        if check_server_reachable().await {
            let was_offline = AGENT_MODE.load(Ordering::Relaxed) == AgentMode::Offline as u8;
            set_online();
            if was_offline {
                restore_online_policies_from_db();
            }
        } else {
            let switched = set_offline();
            if switched {
                reload_local_policies_on_offline();
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
pub static JUMP_STATUS: LazyLock<Mutex<JumpStatus>> = LazyLock::new(|| Mutex::new(JumpStatus::default()));

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
    // Jump status — event-driven fetch (startup / after jump)
    // ========================================================================

    /// 调用服务器 /v1/newestJumpInfo，将结果合并到全局 JUMP_STATUS 并持久化到 jump.db。
    ///
    /// 触发时机（不在 gRPC handler 里每次调用）：
    ///   1. 程序启动且处于在线模式
    ///   2. execute_ip_jump 成功后
    ///   3. execute_pw_jump 成功后
    ///
    /// 安全规则：
    ///   - 离线模式直接返回，不请求服务器
    ///   - 请求失败/超时/非 000000 → 不更新内存缓存，不写数据库
    pub async fn fetch_newest_jump_info(&self) {
        // 离线模式不请求服务器
        if AGENT_MODE.load(Ordering::Relaxed) != AgentMode::Online as u8 {
            log_info!("[newestJumpInfo] 当前离线模式，跳过");
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
                log_error!("[newestJumpInfo] 创建 NetClient 失败: {}", e);
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
                            // 构造持久化行（在持有锁期间复制字段）
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

                        // 持久化到 jump.db（在锁外执行，避免长时间持锁）
                        if let Err(e) = local_store::jump_status::upsert(&row) {
                            log_error!("[newestJumpInfo] 写入 jump.db 失败: {}", e);
                        }
                        log_info!("[newestJumpInfo] 同步并持久化成功");
                    }
                    Ok(v) => {
                        log_error!("[newestJumpInfo] 服务器返回非成功 code: {}", v["code"]);
                    }
                    Err(e) => {
                        log_error!("[newestJumpInfo] 响应解析失败: {}", e);
                    }
                }
            }
            Err(e) => {
                log_error!("[newestJumpInfo] 请求失败: {}", e);
            }
        }
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

    /// 启动时从 DB 在线表恢复外设黑白名单到内存。
    pub fn load_peripheral_policy_from_db() {
        Self::load_peripheral_policy_from(false)
    }

    /// 切离线时从 DB 本地表恢复外设黑白名单到内存。
    pub fn load_peripheral_policy_from_db_local() {
        Self::load_peripheral_policy_from(true)
    }

    fn load_peripheral_policy_from(local: bool) {
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
                        row.peripheral_eid.clone(),
                        row.peripheral_name,
                        row.intro,
                        row.type_,
                        false,
                    );
                    if row.is_white {
                        white.push(info);
                    } else {
                        black.push(info);
                    }
                }
                let mut guard = udisk::list::SHARED_USB_LIST.lock().unwrap();
                *guard = udisk::list::BlackWhiteList::from_vecs(black, white);
                log_info!(
                    "[peripheral_policy] 从 DB({}) 加载: {} 白名单, {} 黑名单",
                    if local { "local" } else { "online" },
                    guard.get_whitelist().len(),
                    guard.get_blacklist().len()
                );
            }
            Err(e) => log_error!("[peripheral_policy] 从 DB 加载失败: {}", e),
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

    // ========================================================================
    // Write methods — offline only (caller must check require_offline first)
    // ========================================================================

    /// Update config and persist to ini.
    pub fn update_config(
        &self,
        updates: &grpc_gateway::config::ConfigData,
    ) -> Result<(), String> {
        let mut map = serde_json::Map::new();
        let v = updates.clone();

        // Build JSON map from proto fields (only non-default values)
        if v.crontime != 0 { map.insert("crontime".into(), serde_json::Value::from(v.crontime)); }
        map.insert("file_switch".into(), v.file_switch.into());
        map.insert("proc_switch".into(), v.proc_switch.into());
        map.insert("extortion_protect".into(), v.extortion_protect.into());
        map.insert("extortion_switch".into(), v.extortion_switch.into());
        map.insert("file_protect".into(), v.file_protect.into());
        map.insert("self_protect_switch".into(), v.self_protect_switch.into());
        map.insert("open_port_switch".into(), v.open_port_switch.into());
        map.insert("dynamic_switch".into(), v.dynamic_switch.into());
        map.insert("proc_protect".into(), v.proc_protect.into());
        map.insert("usb_protect".into(), v.usb_protect.into());
        map.insert("usb_switch".into(), v.usb_switch.into());
        map.insert("syslog_inner_switch".into(), v.syslog_inner_switch.into());
        map.insert("syslog_outer_switch".into(), v.syslog_outer_switch.into());
        map.insert("syslog_dns_switch".into(), v.syslog_dns_switch.into());
        map.insert("internet_switch".into(), v.internet_switch.into());
        map.insert("syslog_process_switch".into(), v.syslog_process_switch.into());
        map.insert("syslog_login_switch".into(), v.syslog_login_switch.into());
        map.insert("outreach_switch".into(), v.outreach_switch.into());
        map.insert("baseline_switch".into(), v.baseline_switch.into());
        map.insert("hardware_switch".into(), v.hardware_switch.into());
        if v.logproto != 0 { map.insert("logproto".into(), serde_json::Value::from(v.logproto)); }
        if v.logsent != 0 { map.insert("logsent".into(), serde_json::Value::from(v.logsent)); }
        if v.debug_switch != 0 { map.insert("debug_switch".into(), serde_json::Value::from(v.debug_switch)); }
        if v.module_switch != 0 { map.insert("module_switch".into(), serde_json::Value::from(v.module_switch)); }
        if v.outreach_time != 0 { map.insert("outreach_time".into(), serde_json::Value::from(v.outreach_time)); }
        if v.baseline_time != 0 { map.insert("baseline_time".into(), serde_json::Value::from(v.baseline_time)); }
        if v.hardware_time != 0 { map.insert("hardware_time".into(), serde_json::Value::from(v.hardware_time)); }
        if !v.logipport.is_empty() {
            map.insert("logipport".into(), serde_json::Value::from(v.logipport.as_str()));
        }

        // Apply to NETINFO_CONFIG
        let mut guard = config::net_info::NETINFO_CONFIG.lock().unwrap();
        let mut new_cfg = guard.clone();

        if let Ok(val) = get_u32(&map, "crontime") { new_cfg.cron_time = val; }
        if let Ok(val) = get_bool(&map, "file_switch") { new_cfg.file_switch = val; }
        if let Ok(val) = get_bool(&map, "proc_switch") { new_cfg.proc_switch = val; }
        if let Ok(val) = get_bool(&map, "extortion_protect") { new_cfg.extortion_protect = val; }
        if let Ok(val) = get_bool(&map, "extortion_switch") { new_cfg.extortion_switch = val; }
        if let Ok(val) = get_bool(&map, "file_protect") { new_cfg.file_protect = val; }
        if let Ok(val) = get_bool(&map, "self_protect_switch") { new_cfg.self_protect_switch = val; }
        if let Ok(val) = get_bool(&map, "open_port_switch") { new_cfg.open_port_switch = val; }
        if let Ok(val) = get_bool(&map, "dynamic_switch") { new_cfg.dynamic_switch = val; }
        if let Ok(val) = get_bool(&map, "proc_protect") { new_cfg.proc_protect = val; }
        if let Ok(val) = get_bool(&map, "usb_protect") { new_cfg.usb_protect = val; }
        if let Ok(val) = get_bool(&map, "usb_switch") { new_cfg.usb_switch = val; }
        if let Ok(val) = get_bool(&map, "syslog_inner_switch") { new_cfg.syslog_inner_switch = val; }
        if let Ok(val) = get_bool(&map, "syslog_outer_switch") { new_cfg.syslog_outer_switch = val; }
        if let Ok(val) = get_bool(&map, "syslog_dns_switch") { new_cfg.syslog_dns_switch = val; }
        if let Ok(val) = get_bool(&map, "internet_switch") { new_cfg.internet_switch = val; }
        if let Ok(val) = get_bool(&map, "syslog_process_switch") { new_cfg.syslog_process_switch = val; }
        if let Ok(val) = get_bool(&map, "syslog_login_switch") { new_cfg.syslog_login_switch = val; }
        if let Ok(val) = get_bool(&map, "outreach_switch") { new_cfg.outreach_switch = val; }
        if let Ok(val) = get_bool(&map, "baseline_switch") { new_cfg.baseline_switch = val; }
        if let Ok(val) = get_bool(&map, "hardware_switch") { new_cfg.hardware_switch = val; }
        if let Ok(val) = get_u32(&map, "logproto") { new_cfg.log_proto = val; }
        if let Ok(val) = get_u32(&map, "logsent") { new_cfg.log_sent = val; }
        if let Ok(val) = get_u32(&map, "debug_switch") { new_cfg.cli_port = val; }
        if let Ok(val) = get_u32(&map, "module_switch") { new_cfg.module_switch = val; }
        if let Ok(val) = get_u32(&map, "outreach_time") { new_cfg.outreach_time = val; }
        if let Ok(val) = get_u32(&map, "baseline_time") { new_cfg.baseline_time = val; }
        if let Ok(val) = get_u32(&map, "hardware_time") { new_cfg.hardware_time = val; }
        if let Some(s) = map.get("logipport").and_then(|v| v.as_str()) {
            if !s.is_empty() { new_cfg.log_ip_port = Some(s.to_string()); }
        }

        *guard = new_cfg.clone();
        let _ = guard.to_ini(&format!("{}/net_info.ini", guard.app_path));

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
        let _ = guard.to_ini(&format!("{}/net_info.ini", guard.app_path));
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
            0 => { // OFF
                ADMISSION_MODE.store(0, Ordering::Relaxed);
                ADMISSION_EFFECTIVE.store(0, Ordering::Relaxed);
                self.write_admission_proc(false)?;
                self.persist_admission_mode(0, false)?;
            }
            1 => { // ON
                ADMISSION_MODE.store(1, Ordering::Relaxed);
                ADMISSION_EFFECTIVE.store(1, Ordering::Relaxed);
                self.write_admission_proc(true)?;
                self.persist_admission_mode(1, true)?;
            }
            2 => { // AUTO
                ADMISSION_MODE.store(2, Ordering::Relaxed);
                self.persist_admission_mode(2, false)?;
                // 启动自动检测（异步）
                self.start_auto_detect();
            }
            _ => return Err(format!("无效的准入模式: {}", mode)),
        }

        self.notify(PolicyChangeType::ConfigChanged);
        Ok(())
    }

    /// 写入 /proc/osec/tcp_force_ecn
    fn write_admission_proc(&self, enable: bool) -> Result<(), String> {
        let proc_path = "/proc/osec/tcp_force_ecn";
        if std::path::Path::new(proc_path).exists() {
            let val = if enable { "1" } else { "0" };
            if let Err(e) = std::fs::write(proc_path, val) {
                log_error!("[admission] 写入 {} 失败: {}", proc_path, e);
                Err(format!("写入 {} 失败: {}", proc_path, e))
            } else {
                log_info!("[admission] 已写入 {} = {}", proc_path, val);
                Ok(())
            }
        } else {
            log_info!("[admission] {} 不存在，跳过写入（驱动未加载）", proc_path);
            Ok(())
        }
    }

    /// 持久化准入模式到 ini
    /// mode: 0=OFF, 1=ON, 2=AUTO
    /// effective: 当前 tcp_force_ecn 的生效值 (true=1, false=0)
    fn persist_admission_mode(&self, mode: u8, effective: bool) -> Result<(), String> {
        let mut guard = config::net_info::NETINFO_CONFIG.lock().unwrap();
        guard.admission.mode = mode;
        guard.admission_switch = effective;
        let _ = guard.to_ini(&format!("{}/net_info.ini", guard.app_path));
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
                if check_server_reachable().await {
                    log_info!("[admission] 关准入可上线，设置 effective=OFF");
                    ADMISSION_EFFECTIVE.store(0, Ordering::Relaxed);
                    let _ = data_hub.persist_admission_mode(2, false);
                    // ADMISSION_MODE 保持 AUTO(2)，不改变
                    ADMISSION_DETECTING.store(false, Ordering::Relaxed);
                    ADMISSION_NETWORK_ANOMALY.store(false, Ordering::Relaxed);
                    data_hub.notify(PolicyChangeType::ConfigChanged);
                    return;
                }

                if !ADMISSION_DETECTING.load(Ordering::Relaxed) { return; }

                // 2. 尝试开准入
                let _ = data_hub.write_admission_proc(true);
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                if check_server_reachable().await {
                    log_info!("[admission] 开准入可上线，设置 effective=ON");
                    ADMISSION_EFFECTIVE.store(1, Ordering::Relaxed);
                    let _ = data_hub.persist_admission_mode(2, true);
                    // ADMISSION_MODE 保持 AUTO(2)，不改变
                    ADMISSION_DETECTING.store(false, Ordering::Relaxed);
                    ADMISSION_NETWORK_ANOMALY.store(false, Ordering::Relaxed);
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

    /// Update process policy (white/black list).
    /// action: 0=移除, 1=白名单, 2=黑名单
    pub fn update_process_policy(
        &self,
        hashes: &[String],
        action: i32,
    ) -> Result<(), String> {
        process_mgr::POLICY_MANAGER
            .lock()
            .unwrap()
            .set_policy_process(hashes, action, if db_policy_enabled() { Some(true) } else { None });
        self.notify(PolicyChangeType::ProcessPolicyChanged);
        Ok(())
    }

    /// Update peripheral (USB) policy. action: 0=移除, 1=白名单, 2=黑名单
    pub fn update_peripheral_policy(
        &self,
        devices: &[udisk::device::UsbInfo],
        action: i32,
    ) -> Result<(), String> {
        // 先读 NETINFO_CONFIG（在外层），避免在持有 SHARED_USB_LIST 锁时再锁 config 导致 AB-BA 死锁
        let usb_protect = config::net_info::NETINFO_CONFIG.lock().unwrap().usb_protect;
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

        // 持久化到离线本地表（仅 DB_POLICY 启用时）
        if db_policy_enabled() {
            let white: Vec<local_store::peripheral_policy::PeripheralPolicyRow> = guard
                .get_whitelist()
                .iter()
                .map(|d| local_store::peripheral_policy::PeripheralPolicyRow {
                    peripheral_eid: d.perpheral_eid.clone(),
                    peripheral_name: d.perpheral_name.clone(),
                    intro: d.intro.clone(),
                    type_: d.type_.clone(),
                    is_white: true,
                })
                .collect();
            let black: Vec<local_store::peripheral_policy::PeripheralPolicyRow> = guard
                .get_blacklist()
                .iter()
                .map(|d| local_store::peripheral_policy::PeripheralPolicyRow {
                    peripheral_eid: d.perpheral_eid.clone(),
                    peripheral_name: d.perpheral_name.clone(),
                    intro: d.intro.clone(),
                    type_: d.type_.clone(),
                    is_white: false,
                })
                .collect();
            if let Err(e) = local_store::peripheral_policy::save_all_local(&white, &black) {
                log_error!("[peripheral_policy] 持久化到本地表失败: {}", e);
            }
        }

        self.notify(PolicyChangeType::PeripheralPolicyChanged);
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

    /// Delete a system snapshot.
    pub async fn delete_backup(&self, backup_id: &str) -> Result<(), String> {
        snapman::clean_snapshot(backup_id).await.map_err(|e| format!("{:?}", e))?;
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

        // 在线模式下，口令跳变成功后异步更新服务器最新跳变信息并持久化
        if info.status == 1 {
            let hub = self.clone();
            tokio::spawn(async move { hub.fetch_newest_jump_info().await; });
        }

        Ok((info.status, info.reason))
    }
}

impl Default for AgentDataHub {
    fn default() -> Self {
        Self::new()
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
        .and_then(|v| v.as_number().and_then(|n| n.as_u64()))
        .map(|n| n != 0)
        .ok_or_else(|| format!("Missing or invalid field: {}", key))
}
