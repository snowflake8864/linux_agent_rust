use std::sync::atomic::{AtomicU8, Ordering};
use tonic::Status;

use grpc_gateway::policy_watch::PolicyChangeType;
use grpc_gateway::dir_policy::DirectionScanRule;
use grpc_gateway::extort_policy::ExtortProtectRule;

/// Agent operation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AgentMode {
    Online = 0,
    Offline = 1,
}

/// Global agent mode, writable from online/task_fetcher, readable from gRPC handlers.
pub static AGENT_MODE: AtomicU8 = AtomicU8::new(AgentMode::Online as u8);

/// Check if we are in offline mode. If online, return PERMISSION_DENIED.
pub fn require_offline() -> Result<(), Status> {
    if AGENT_MODE.load(Ordering::Relaxed) == AgentMode::Online as u8 {
        return Err(Status::permission_denied(
            "在线模式下不允许此操作，请通过管理平台执行"
        ));
    }
    Ok(())
}

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

    /// Update process policy (white/black list).
    pub fn update_process_policy(
        &self,
        hashes: &[String],
        is_white: bool,
    ) -> Result<(), String> {
        process_mgr::POLICY_MANAGER
            .lock()
            .unwrap()
            .set_policy_process(hashes, is_white);
        self.notify(PolicyChangeType::ProcessPolicyChanged);
        Ok(())
    }

    /// Update peripheral (USB) policy.
    pub fn update_peripheral_policy(
        &self,
        devices: Vec<udisk::device::UsbInfo>,
        is_white: bool,
    ) -> Result<(), String> {
        let mut guard = udisk::list::SHARED_USB_LIST.lock().unwrap();
        if is_white {
            guard.update_whitelist(devices);
        } else {
            guard.update_blacklist(devices);
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
        self.notify(PolicyChangeType::JumpStatusChanged);
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
        self.notify(PolicyChangeType::JumpStatusChanged);
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
