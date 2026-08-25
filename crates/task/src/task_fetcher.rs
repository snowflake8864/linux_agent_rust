//crates/task/src/task_fetcher.rs
use config::net_info::{NETINFO_CONFIG, NetInfoConfig};
use std::{fs, io::Cursor, path::PathBuf};
use tokio::time::{interval, Duration, Interval,sleep, timeout};
use std::pin::Pin;
use std::future::Future;
use serde_json::Value;
use serde::Deserialize;
use net_client::core::NetClient;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use tokio::io::AsyncWriteExt; // 
use std::sync::{Arc, Mutex};
use logging::{log_info,log_error,log_warn};
use common::manager::boot::BootManager;
use crate::virtual_port_rule::VirtualPortRule;
use crate::get_process_task::process_all_dirs;
use crate::net_reach_rule::{OutreachDetectRule,update_global_outreach_rules};
use crate::scan_directory_task::{DirectionScanRule,scan_single_dir};
use pattern::{pattern_rules_mgr,process_pattern_rules_mgr::PROCESS_PATTERN_RULES_MGR, GlobalTrustDir};
use tokio::sync::mpsc;
use process_mgr::POLICY_MANAGER;
use netlink::netlink::NlSockInfo; // 引入 NLPolicyType
use hostinfo::net_app::model::get_netapp_json; 
use netblock::ip_policy::{IpPolicy, update_and_write_policies, is_ipv6};
use udisk::{list::SHARED_USB_LIST, device::UsbInfo,monitor::{get_all_local_usb_devices, build_usb_json}};
use procinfo::{get_running_process_infos,build_process_list_json};
use tokio::task;
use serde_json::json;
use tokio::net::UnixStream;
use zip::ZipArchive;
use zip::write::{FileOptions, ZipWriter};
use zip::CompressionMethod;
use snapman::{create_snapshot, restore_snapshot};
use rules_jump_mgr::{IpJumpManager, PasswordManager, IpJumpConfig, PutIpJumpInfo, PutPwJumpInfo};
// 在线/离线状态由 agent_local_svc::start_connectivity_monitor 统一管理，task_fetcher 不再设置
use chrono::{Utc, Datelike};
use std::io::{Read, Write};
use tokio::process::Command;
use std::process::Stdio;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use grpc_gateway::agent_mode::{notify_network_failure, set_online};
use std::sync::OnceLock;
use grpc_gateway::notify::{notify_policy_change, init_local_task_rx, DIR_POLICY_CACHE, EXTORT_POLICY_CACHE, VIRTUAL_PORT_CACHE, TRUST_DIR_CACHE};
use grpc_gateway::policy_watch::PolicyChangeType;

static AUTO_IP_JUMP_DAEMON_RUNNING: AtomicBool = AtomicBool::new(false);

/// 全局 Netlink socket（driver 模式有效，eBPF 模式为 None）
pub static GLOBAL_NL_SOCK: OnceLock<Mutex<Option<NlSockInfo>>> = OnceLock::new();
/// 全局 PatternRulesMgr（文件/勒索保护目录管理）
pub static GLOBAL_PATTERN_MGR: OnceLock<Arc<Mutex<pattern_rules_mgr::PatternRulesMgr>>> = OnceLock::new();



fn get_u32(map: &serde_json::Map<String, Value>, key: &str) -> Result<u32, String> {
    map.get(key)
        .and_then(|v| v.as_number().and_then(|n| n.as_u64()))
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| format!("Missing or invalid field: {}", key))
}

fn get_bool(map: &serde_json::Map<String, Value>, key: &str) -> Result<bool, String> {
    map.get(key)
        .and_then(|v| v.as_number().and_then(|n| n.as_u64()))
        .map(|n| n != 0)         
        .ok_or_else(|| format!("Missing or invalid field: {}", key))
}
pub struct TaskFetcher {
    base_url: String,
    token: Option<String>,  // 'a 表示 token 的生命周期与 TaskFetcher 的生命周期相同
    api_interface: HashMap<String, String>,
    pattern_mgr: Arc<Mutex<pattern_rules_mgr::PatternRulesMgr>>,
    prev_defense_switch: Option<u32>,
    prev_open_port_switch: bool,
    prev_file_switch: bool,
    prev_extortion_switch:bool,
    prev_proc_switch:bool,
    prev_syslog_process_switch:bool,
    prev_dynamic_switch:bool,
    prev_self_protect_switch:bool,
    nl_sock: Option<NlSockInfo>,
    net_client: NetClient,
    ip_jump_manager: Arc<IpJumpManager>,

}
use num_derive::FromPrimitive; // 支持从整数到枚举的转换
use num_traits::FromPrimitive;
/// 对应 C++ SAMPLE_INFO 结构体，用于 getdraw 接口返回的样本文件列表
#[derive(Debug, Clone, Deserialize)]
struct SampleItem {
    aid: i32,
    p_dir: String,
    p_hash: String,
}

#[derive(Debug, FromPrimitive)]
enum TaskTypeEnum {
    TaskUploadProcess = 0,
    TaskUpdate = 1,
    TaskUploadDir = 2,
    TaskDownWhite = 3,
    TaskDownDirPolicy = 4,
    TaskUploadConf = 5, // no use
    TaskDownConf = 6,
    TaskDownBlack = 7,
    TaskDownFileTtap = 8,
    TaskUploadPort = 9,
    TaskDownVirtualPort = 10,
    TaskAutoDownNetBlockPolicy = 11, // no use
    TaskAutoUploadNetBockPolicyy = 12, // no use
    TaskDownNetBlockPolicy = 13,
    TaskDownWhiteIpPolicy = 14, // no use
    TaskDownBlackIpPolicy = 15,
    TaskDownUsbUpload = 16,
    TaskDownUsbDown = 17, // no use
    TaskDownExtort = 19,
    TaskUploadProcessModule = 21,
    TaskUploadAllProcessModule = 22,
    TaskUploadProcessWhiteModule = 23,
    TaskUploadProcessBlackModule = 24,
    TaskUninstall = 25,
    TaskGetWhitePeripherals = 26,
    TaskGetBlackPeripherals = 27,
    TaskUploadSample = 28,
    TaskSyslogEnable = 29, // no use
    TaskSyslogDisable = 30, // no use
    TaskGlobalProc = 31,
    TaskGlobalDir = 33,
    TaskUpdateUUI = 34,
    TaskOutReachDetect = 35,
    TaskPwJump =36,
    TaskIpJump = 37,
    TaskSystemBackup = 38,
    TaskSystemRollback = 39,
    TaskNtpSyncAt = 40,
}
#[allow(dead_code)]
enum NetRule<'a> {
    ServerIpV4(&'a str),
    ServerPort(u32),
    LogIpPort(&'a str),
    VirtualOpenPort(bool),
    DefenseSwitch(u32),
    SelfProtect(u32),
    NetLogPolicy((bool, bool)),
    NetBlockSwitch(u32),
}
fn ip_str_to_u32(ip: &str) -> Result<u32, String> {
    let parsed = ip.parse::<Ipv4Addr>().map_err(|e| e.to_string())?;
    Ok(u32::from_be_bytes(parsed.octets()))
}

/// eBPF 模式下应用防 kill 自保开关（写 proc_agent 的 protected_pids map）。
/// driver 模式的自保防 kill 走 netlink 0x103，不经过此函数；这里仅对 eBPF
/// 后端生效，避免影响 driver 模式现有行为。
fn apply_self_protect_antikill(enable: bool) -> Result<(), String> {
    let is_ebpf = common::backend::get_backend()
        .map(|b| b.name() == "ebpf")
        .unwrap_or(false);
    if is_ebpf {
        common::backend::with_backend(|b| b.write_self_protection(enable as u32))?;
    }
    Ok(())
}

/// 独立的配置差异应用函数：将 old→new 的开关变化下发到内核/BPF。
/// driver 模式：通过 netlink + /proc/osec 下发
/// eBPF  模式：通过 SecurityBackend trait（BPF maps）+ sync_switches 下发
/// gRPC 和服务器路径共用此函数，避免重复逻辑。
pub fn apply_config_diff(old: &NetInfoConfig, new: &NetInfoConfig) -> Result<(), String> {
    // gRPC 路径用：对比 old→new 变化后下发，无 prev_* 状态
    // HTTP task_fetcher 路径走 TaskFetcher::apply_config_diff (self.prev_* 对比)
    let driver_ready = !new.mod_ver.is_empty();

    // ── 自保护开关 ──
    if new.self_protect_switch != old.self_protect_switch {
        if driver_ready {
            if let Some(mgr) = GLOBAL_PATTERN_MGR.get() {
                let mut pattern_mgr = mgr.lock().map_err(|e| e.to_string())?;
                pattern_mgr.add_file_pattern(new.self_protect_switch);
            }
            // eBPF 模式：防 kill（protected_pids）；driver 模式走 netlink 0x103
            apply_self_protect_antikill(new.self_protect_switch)?;
            if let Some(sock_guard) = GLOBAL_NL_SOCK.get() {
                let sock = sock_guard.lock().unwrap();
                if let Some(ref s) = *sock {
                    s.send_uint32(0x103, new.self_protect_switch as u32)
                        .map_err(|e| format!("nl_sock self_protect: {}", e))?;
                }
            }
        }
    }

    // ── 虚拟开端口 ──
    if new.open_port_switch != old.open_port_switch {
        if driver_ready {
            let content = format!("vir_open_port_switch {}\n",
                if new.open_port_switch { "1" } else { "0" });
            common::backend::with_backend(|b| b.write_net_rules(&content))?;
        }
    }

    // ── 动态阻断 ──
    if new.dynamic_switch != old.dynamic_switch {
        common::backend::with_backend(|b| b.write_netblock_switch(
            &(new.dynamic_switch as u32).to_string()
        ))?;
    }

    // ── 文件开关关闭 → 清理保护目录 ──
    if new.file_switch != old.file_switch {
        if driver_ready && !new.file_switch {
            if let Some(mgr) = GLOBAL_PATTERN_MGR.get() {
                let mut pattern_mgr = mgr.lock().map_err(|e| e.to_string())?;
                pattern_mgr.clear_protect_dir();
            }
        }
    }

    // ── 勒索保护关闭 → 清理勒索目录 ──
    if new.extortion_protect != old.extortion_protect {
        if driver_ready && !new.extortion_protect {
            if let Some(mgr) = GLOBAL_PATTERN_MGR.get() {
                let mut pattern_mgr = mgr.lock().map_err(|e| e.to_string())?;
                pattern_mgr.clear_exiport_dir();
            }
        }
    }

    // ── 进程日志开关 ──
    if new.proc_switch != old.proc_switch || new.syslog_process_switch != old.syslog_process_switch {
        log_info!(
            "apply_config_diff: proc_switch:{}→{} syslog_process_switch:{}→{}",
            old.proc_switch, new.proc_switch,
            old.syslog_process_switch, new.syslog_process_switch
        );
        if let Some(sock_guard) = GLOBAL_NL_SOCK.get() {
            let sock = sock_guard.lock().unwrap();
            if let Some(ref s) = *sock {
                let buf = [new.syslog_process_switch as u8, new.proc_switch as u8, 0, 0];
                s.send_message(0x702, &buf)
                    .map_err(|e| format!("nl_sock netlog_policy: {}", e))?;
            }
        }
    }

    // ── defense_switch ──
    let file_flag_temp = new.file_switch || new.extortion_switch;
    let enable_flag = (file_flag_temp as u32) * 2 + (new.proc_switch as u32);
    let defense_switch: u32 = [
        (new.open_port_switch, 14),
        (new.internet_switch, 13),
        (new.syslog_dns_switch, 12),
        (new.syslog_outer_switch, 11),
        (new.syslog_inner_switch, 10),
        (new.proc_switch, 9),
        (new.file_switch, 8),
        (new.extortion_switch, 7),
        (new.proc_protect, 6),
        (new.file_protect, 5),
        (new.extortion_protect, 4),
    ].iter().fold(0u32, |acc, &(flag, shift)| acc | ((flag as u32) << shift)) | enable_flag;

    let old_file_flag_temp = old.file_switch || old.extortion_switch;
    let old_enable_flag = (old_file_flag_temp as u32) * 2 + (old.proc_switch as u32);
    let old_defense_switch: u32 = [
        (old.open_port_switch, 14),
        (old.internet_switch, 13),
        (old.syslog_dns_switch, 12),
        (old.syslog_outer_switch, 11),
        (old.syslog_inner_switch, 10),
        (old.proc_switch, 9),
        (old.file_switch, 8),
        (old.extortion_switch, 7),
        (old.proc_protect, 6),
        (old.file_protect, 5),
        (old.extortion_protect, 4),
    ].iter().fold(0u32, |acc, &(flag, shift)| acc | ((flag as u32) << shift)) | old_enable_flag;

    if defense_switch != old_defense_switch {
        if driver_ready {
            log_info!("apply_config_diff: 下发 defense_switch={}", defense_switch);
            common::backend::with_backend(|b| b.write_defense_switch(
                "defense_switch ", &defense_switch.to_string()
            ))?;
        }
    }

    // ── eBPF 运行时开关同步：无条件写入 BPF maps，确保与 ini 一致 ──
    // 即使 old==new，BPF maps 也可能因重启/初始化导致状态不同步
    log_info!(
        "apply_config_diff: sync eBPF switches file(sw={},prot={}) proc(sw={},prot={})",
        new.file_switch, new.file_protect, new.proc_switch, new.proc_protect
    );
    common::backend::with_backend(|b| {
        b.sync_switches(new.file_switch, new.proc_switch, new.file_protect, new.proc_protect)
    })?;

    Ok(())
}

/// 将单个文件打包成 zip，用于上传样本
fn zip_single_file(src_path: &str, zip_path: &str) -> Result<(), String> {
    let file = std::fs::File::create(zip_path)
        .map_err(|e| format!("Cannot create zip file {}: {}", zip_path, e))?;
    let mut zip = ZipWriter::new(file);
    let options = FileOptions::default()
        .compression_method(CompressionMethod::Stored) // 无密码，不压缩
        .unix_permissions(0o644);

    let file_name = Path::new(src_path)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("Invalid file path: {}", src_path))?;

    zip.start_file(file_name, options)
        .map_err(|e| format!("zip start_file error: {}", e))?;
    let data = std::fs::read(src_path)
        .map_err(|e| format!("Cannot read file {}: {}", src_path, e))?;
    std::io::Write::write_all(&mut zip, &data)
        .map_err(|e| format!("zip write error: {}", e))?;
    zip.finish()
        .map_err(|e| format!("zip finish error: {}", e))?;

    log_info!("zip_single_file: {} -> {}", src_path, zip_path);
    Ok(())
}

/// 简易通配符匹配：支持 '*'（任意长度，含 0）和 '?'（任意单字符）
fn wildcard_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut star_ni = 0usize;
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = Some(pi);
            star_ni = ni;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ni += 1;
            ni = star_ni;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// 解析 upgrade.conf 中的一行为实际存在的脚本路径列表：
/// - 含通配符（* 或 ?）：在 dir 下匹配所有同名模式的普通文件（按文件名排序）
/// - 普通文件名：精确匹配
/// 与 agent_manager::find_upgrade_scripts 的解析规则保持一致
fn resolve_upgrade_conf_line(dir: &str, line: &str) -> Vec<PathBuf> {
    if line.contains('*') || line.contains('?') {
        let mut matched: Vec<PathBuf> = fs::read_dir(dir)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| {
                        p.is_file()
                            && p.file_name()
                                .and_then(|n| n.to_str())
                                .map(|n| wildcard_match(line, n))
                                .unwrap_or(false)
                    })
                    .collect()
            })
            .unwrap_or_default();
        matched.sort();
        matched
    } else {
        let p = PathBuf::from(dir).join(line);
        if p.exists() {
            vec![p]
        } else {
            Vec::new()
        }
    }
}

impl TaskFetcher {
    pub fn new(base_url: &str, token: Option<String>, pattern_mgr: Arc<Mutex<pattern_rules_mgr::PatternRulesMgr>>, nl_sock: Option<NlSockInfo>) -> Self 
    {
        PROCESS_PATTERN_RULES_MGR.lock().init();
        let mut api_interface = HashMap::new();
        api_interface.insert("closetask".to_string(), "v1/closetask".to_string());
        api_interface.insert("update".to_string(), "v1/download".to_string());
        api_interface.insert("getdirinfo".to_string(), "v1/getdirinfo".to_string());
        api_interface.insert("putdir".to_string(), "v1/putdir".to_string());
        api_interface.insert("uninstall".to_string(), "v1/uninstall".to_string());
        api_interface.insert("upload_process".to_string(), "v1/upload_process".to_string());
        api_interface.insert("download_white".to_string(), "v1/getprocwl".to_string());
        api_interface.insert("download_black".to_string(), "v1/getprocbl".to_string());
        api_interface.insert("getconf".to_string(), "v1/getconf".to_string());
        api_interface.insert("getprotect".to_string(), "v1/getprotect".to_string());
        api_interface.insert("getdirpolicy".to_string(), "v1/getdirpolicy".to_string());
        api_interface.insert("upload_process".to_string(), "v1/uploadproc".to_string());
        api_interface.insert("gettrustdir".to_string(), "v1/gettrustdir".to_string());
        api_interface.insert("getvirtualport".to_string(), "v1/getvirtualport".to_string());
        api_interface.insert("upload_gloabal_process".to_string(), "v1/upload/suffix/exe".to_string());
        api_interface.insert("getPlugging".to_string(), "v1/getPlugging".to_string());
        api_interface.insert("getipblacklist".to_string(), "v1/getipblacklist".to_string());
        api_interface.insert("upserviceport".to_string(), "v1/upserviceport".to_string());
        api_interface.insert("addperipherals".to_string(), "v1/addperipherals".to_string());
        api_interface.insert("getwhiteperipherals".to_string(), "v1/getwhiteperipherals".to_string());
        api_interface.insert("getblackperipherals".to_string(), "v1/getblackperipherals".to_string());
        api_interface.insert("getPwJump".to_string(), "v1/getPwJump".to_string());
        api_interface.insert("putPwJump".to_string(), "v1/putPwJump".to_string());
        api_interface.insert("getIpJump".to_string(), "v1/getIpJump".to_string());
        api_interface.insert("putIpJump".to_string(), "v1/putIpJump".to_string());
        api_interface.insert("getBackups".to_string(), "v1/getBackups".to_string());
        api_interface.insert("getRollbacks".to_string(), "v1/getRollbacks".to_string());
        api_interface.insert("uploadRollback".to_string(), "v1/uploadRollback".to_string());
        api_interface.insert("uploadBackup".to_string(), "v1/uploadBackup".to_string());
        api_interface.insert("getOutreachDetect".to_string(), "v1/getOutreachDetect".to_string());
        api_interface.insert("getNtpConf".to_string(), "v1/getNtpConf".to_string());
        api_interface.insert("getdraw".to_string(), "/v1/getdraw".to_string());
        api_interface.insert("uploaddraw".to_string(), "/v1/uploaddraw".to_string());
        let net_client = NetClient::new(
            Some(base_url.to_string()),
            true,
        ).expect("创建 NetClient 失败");


        let (ifcfg, jump_enabled, jump_ip) = {
            let cfg = NETINFO_CONFIG.lock().unwrap();
            (cfg.ifcfg.clone(), cfg.jump.enabled, cfg.jump.ip_jump)
        };

        let ip_jump_manager = IpJumpManager::new(&ifcfg);

        // 仅在跳变总闸 && IP跳变开关开启时才启动 daemon 和清理任务
        if jump_enabled && jump_ip {
            let base_url_owned = base_url.to_string();
            let token_for_cleanup = token.clone();
            let manager_clone = Arc::clone(&ip_jump_manager);
            tokio::spawn(async move {
                manager_clone.start_periodic_cleanup(&base_url_owned, token_for_cleanup, Duration::from_secs(60)).await;
            });

            let base_url_for_jump = base_url.to_string();
            let token_for_jump = token.clone();
            let ip_jump_manager_for_daemon = Arc::clone(&ip_jump_manager);
            tokio::spawn(async move {
                ip_jump_manager_for_daemon.start_ip_jump_daemon(base_url_for_jump, token_for_jump).await;
            });
        }

        // 注册全局资源供 gRPC 路径使用
        GLOBAL_NL_SOCK.set(Mutex::new(nl_sock.clone())).ok();
        GLOBAL_PATTERN_MGR.set(pattern_mgr.clone()).ok();

        // 启动时从 DB 恢复服务器下发策略（防篡改目录/勒索后缀/信任目录）。
        // 离线模式读 *_local 表，在线模式读在线基线表，表为空时保持现状。
        // 必须在 GLOBAL_PATTERN_MGR 注册之后执行（main.rs 已 set_backend + init_dpi_writer）。
        let restore_local = config::net_info::NETINFO_CONFIG
            .lock()
            .map(|c| c.is_offline_mode)
            .unwrap_or(false);
        crate::policy_persistence::restore_policies_from_db(restore_local);

        TaskFetcher {
            base_url: base_url.to_string(),
            token,
            api_interface,
            pattern_mgr,
            prev_defense_switch: None,
            prev_open_port_switch: false,
            prev_file_switch:false,
            prev_extortion_switch:false,
            prev_proc_switch:false,
            prev_syslog_process_switch:false,
            prev_dynamic_switch:false,
            prev_self_protect_switch:false,
            nl_sock,
            net_client,
            ip_jump_manager,
        }
    }
    pub fn get_token(&self) -> Option<String> {
        self.token.clone()
    }
    fn write_net_rule(&self, rule: NetRule) -> Result<(), String> {
        match rule {
            NetRule::ServerIpV4(ip) => {
                let ip_u32 = ip_str_to_u32(ip)?;
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
            NetRule::DefenseSwitch(defense_state) => {
                self.write_defense_switch("defense_switch ", &defense_state.to_string())
            }
            NetRule::SelfProtect(self_protect_state) => {
                log::info!("=======================self_protect_state: {}", self_protect_state);
                self.nl_sock
                    .as_ref()
                    .ok_or("Netlink socket not initialized".to_string())?
                    .send_uint32(0x103, self_protect_state)
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            NetRule::NetLogPolicy((syslog_process_switch,proc_switch)) => {
                let buf = [
                    syslog_process_switch as u8,
                    proc_switch as u8,
                    0,
                    0,
                ];
                self.nl_sock
                    .as_ref()
                    .ok_or("Netlink socket not initialized".to_string())?
                    .send_message(0x702, &buf)
                    .map_err(|e| e.to_string())?;
                Ok(())
            } 
            NetRule::NetBlockSwitch(block_switch) => {
                self.write_netblock_switch(&block_switch.to_string())
            }
        }
    }
    fn write_raw(&self, rule_type: &str, value: &str) -> Result<(), String> {
        let content = format!("{} {}\n", rule_type, value);
        log_info!("[task_fetcher] write_raw '/proc/osec/net_rules' <='{}'", content.trim_end());
        common::backend::with_backend(|b| b.write_net_rules(&content))
    }
    fn write_defense_switch(&self, rule_type: &str, value: &str) -> Result<(), String> {
        log_info!("[task_fetcher] write_defense_switch '/proc/osec/defense_switch' <='{} {}'", rule_type, value);
        common::backend::with_backend(|b| b.write_defense_switch(rule_type, value))
    }

    fn write_netblock_switch(&self, value: &str) -> Result<(), String> {
        common::backend::with_backend(|b| b.write_netblock_switch(value))
    }
    /*
       fn update_config_from_json(&mut self, conf: &serde_json::Map<String, Value>) -> Result<(), String> {

       let mut cfg = NETINFO_CONFIG.lock().unwrap(); // 这里使用 from_ini 解析配置
                                                     // 提取 serveripport 字段，并尝试拆分为 ip 和 port
    /*
    if let Some(url) = conf.get("serveripport")
    .and_then(|v| v.as_str())
    .map(|s| s.to_string()) 
    {

    let (protocol, mut rest) = url.split_once("://")
    .expect("Invalid URL format");

    if let Some(path_idx) = rest.find('/') {
    rest = &rest[..path_idx];
    }

    // 分割IP和端口
    let (ip_str, port_str) = rest.split_once(':')
    .unwrap_or_else(|| (rest, ""));

    if cfg.server_ip != ip_str {
    cfg.server_ip = ip_str.to_string();
    self.write_net_rule(NetRule::ServerIpV4(ip_str))?;
    }
    // 转换端口
    cfg.server_port = if !port_str.is_empty() {
    port_str.parse().expect("Invalid port number")
    } else {
    match protocol.to_lowercase().as_str() {
    "https" => 443,
    "http" => 80,
    _ => panic!("Unsupported protocol"),
    }
    };
    cfg.server_ip_port = format!("https://{}:{}", cfg.server_ip, cfg.server_port);
    log::info!("serveripport: {}", cfg.server_ip_port);

    }
    */
    cfg.cron_time = get_u32(conf, "crontime")?;
    cfg.extortion_protect = get_bool(conf, "extortion_protect")?;
    cfg.extortion_switch = get_bool(conf, "extortion_switch")?;
    cfg.file_protect = get_bool(conf, "file_protect")?;
    cfg.file_switch = get_bool(conf, "file_switch")?;
    cfg.baseline_switch = get_bool(conf, "baseline_switch")?;
    cfg.baseline_time = get_u32(conf, "baseline_time")?;
    cfg.log_proto = get_u32(conf, "logproto")?;
    cfg.log_sent = get_u32(conf, "logsent")?;

    // logipport 可能是空字符串，转成 Option<String>
    cfg.log_ip_port = conf.get("logipport")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    cfg.cli_port = get_u32(conf, "debug_switch")?;
    cfg.module_switch = get_u32(conf, "module_switch")?;


    cfg.self_protect_switch = get_bool(conf, "self_protect_switch")?;
    if cfg.self_protect_switch != self.prev_self_protect_switch {
        self.prev_self_protect_switch = cfg.self_protect_switch;

        if !cfg.mod_ver.is_empty() {
            let mut pattern_mgr = self.pattern_mgr.lock().map_err(|e| e.to_string())?;
            pattern_mgr.add_file_pattern(cfg.self_protect_switch);
            apply_self_protect_antikill(cfg.self_protect_switch)?;
            self.write_net_rule(NetRule::SelfProtect(cfg.self_protect_switch as u32))?;
        }
    }

    cfg.open_port_switch = get_bool(conf, "open_port_switch")?;
    if cfg.open_port_switch != self.prev_open_port_switch {
        self.prev_open_port_switch = cfg.open_port_switch;
        if !cfg.mod_ver.is_empty() {
            self.write_net_rule(NetRule::VirtualOpenPort(cfg.open_port_switch))?;
        }
    }
    cfg.dynamic_switch = get_bool(conf, "dynamic_switch")?;
    if cfg.dynamic_switch != self.prev_dynamic_switch {
        self.prev_dynamic_switch = cfg.dynamic_switch;
        self.write_net_rule(NetRule::NetBlockSwitch(cfg.dynamic_switch as u32))?;
    }

    cfg.proc_protect = get_bool(conf, "proc_protect")?;
    cfg.proc_switch = get_bool(conf, "proc_switch")?;
    cfg.usb_protect = get_bool(conf, "usb_protect")?;
    cfg.usb_switch = get_bool(conf, "usb_switch")?;
    cfg.syslog_inner_switch = get_bool(conf, "syslog_inner_switch")?;
    cfg.syslog_outer_switch = get_bool(conf, "syslog_outer_switch")?;
    cfg.syslog_dns_switch = get_bool(conf, "syslog_dns_switch")?;
    cfg.internet_switch = get_bool(conf, "internet_switch")?;
    cfg.syslog_process_switch = get_bool(conf, "syslog_process_switch")?;

    let _ = cfg.to_ini(&(cfg.app_path.clone() + "/net_info.ini"));
    let file_flag_temp  = cfg.file_switch|cfg.extortion_switch;
    /*

       let mut enable_flag :u32 = 0;
       if ( file_flag_temp && self.cfg.proc_switch ) {
       enable_flag = 3; 
       }    
       if ( file_flag_temp  && !self.cfg.proc_switch ) {
       enable_flag = 2; 
       }    
       if ( !file_flag_temp  && self.cfg.proc_switch ) {
       enable_flag = 1; 
       }    
       if ( !file_flag_temp  && !self.cfg.proc_switch ) {
       enable_flag = 0; 
       } 
       */
    let enable_flag = (file_flag_temp as u32) * 2 + (cfg.proc_switch as u32);
    let mut defense_switch = [
        (cfg.open_port_switch, 14),
        (cfg.internet_switch, 13),
        (cfg.syslog_dns_switch, 12),
        (cfg.syslog_outer_switch, 11),
        (cfg.syslog_inner_switch, 10),
        (cfg.proc_switch, 9),
        (cfg.file_switch, 8),
        (cfg.extortion_switch, 7),
        (cfg.proc_protect, 6),
        (cfg.file_protect, 5),
        (cfg.extortion_protect, 4),
    ]
        .iter()
        .fold(0, |acc, &(flag, shift)| acc | ((flag as u32) << shift));
    defense_switch |= enable_flag;
    if self.prev_defense_switch != Some(defense_switch) {
        self.prev_defense_switch = Some(defense_switch);
        if !cfg.mod_ver.is_empty() {
            self.write_net_rule(NetRule::DefenseSwitch(defense_switch))?;
        }
    }
    if self.prev_file_switch != cfg.file_switch {
        if !cfg.mod_ver.is_empty() {
            if !cfg.file_switch {
                let mut pattern_mgr = self.pattern_mgr.lock().map_err(|e| e.to_string())?;
                pattern_mgr.clear_protect_dir();
            }

        }
        self.prev_file_switch = cfg.file_switch;
    }
    if self.prev_extortion_switch !=cfg.extortion_protect {
        if !cfg.mod_ver.is_empty() {
            if !cfg.extortion_protect {
                let mut pattern_mgr = self.pattern_mgr.lock().map_err(|e| e.to_string())?;
                pattern_mgr.clear_exiport_dir();
            }
        }
    }
    if self.prev_proc_switch != cfg.proc_switch || self.prev_syslog_process_switch != cfg.syslog_process_switch {
        log_info!("===============================proc_switch:{},syslog_process_switch:{}",cfg.proc_switch,cfg.syslog_process_switch);
        self.write_net_rule(NetRule::NetLogPolicy((cfg.syslog_process_switch, cfg.proc_switch)))?;
        self.prev_syslog_process_switch = cfg.syslog_process_switch;
        self.prev_proc_switch = cfg.proc_switch;
    }         

    Ok(())
}
*/

fn update_config_from_json(&mut self, conf: &serde_json::Map<String, Value>) -> Result<(), String> {
    let old_cfg = NETINFO_CONFIG.lock().unwrap().clone();
    let mut new_cfg = old_cfg.clone();

    // 神级宏：有字段就更新，没有就保留旧值，解析失败也保留旧值（永不崩！）
    macro_rules! try_update {
        (u32 $field:ident, $key:literal) => {
            if let Ok(v) = get_u32(conf, $key) {
                new_cfg.$field = v;
            }
        };
        (bool $field:ident, $key:literal) => {
            if let Ok(v) = get_bool(conf, $key) {
                new_cfg.$field = v;
            }
        };
    }

    try_update!(u32 cron_time,          "crontime");
    try_update!(u32 log_proto,          "logproto");
    try_update!(u32 log_sent,           "logsent");
    try_update!(u32 cli_port,           "debug_switch");
    try_update!(u32 module_switch,      "module_switch");
    try_update!(bool extortion_protect,     "extortion_protect");
    try_update!(bool extortion_switch,      "extortion_switch");
    try_update!(bool file_protect,          "file_protect");
    try_update!(bool file_switch,           "file_switch");
    try_update!(bool self_protect_switch,   "self_protect_switch");
    try_update!(bool open_port_switch,      "open_port_switch");
    try_update!(bool dynamic_switch,        "dynamic_switch");
    try_update!(bool proc_protect,          "proc_protect");
    try_update!(bool proc_switch,           "proc_switch");
    try_update!(bool usb_protect,           "usb_protect");
    try_update!(bool usb_switch,            "usb_switch");
    try_update!(bool syslog_inner_switch,   "syslog_inner_switch");
    try_update!(bool syslog_outer_switch,   "syslog_outer_switch");
    try_update!(bool syslog_dns_switch,     "syslog_dns_switch");
    try_update!(bool internet_switch,       "internet_switch");
    try_update!(bool syslog_process_switch,"syslog_process_switch");
    try_update!(bool syslog_login_switch,   "syslog_login_switch");
    try_update!(u32 outreach_time,          "outreach_time");
    try_update!(bool outreach_switch,       "outreach_switch");
    try_update!(bool baseline_switch,       "baseline_switch");
    try_update!(u32 baseline_time,      "baseline_time");
    try_update!(bool hardware_switch,       "hardware_switch");
    try_update!(u32 hardware_time,      "hardware_time");


    if conf.contains_key("logipport") {
        new_cfg.log_ip_port = conf["logipport"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
    }

    {
        let mut guard = NETINFO_CONFIG.lock().unwrap();
        *guard = new_cfg.clone();
        let _ = guard.to_ini(&format!("{}/net_info.ini", guard.app_path));
    }

    self.apply_config_diff(&old_cfg, &new_cfg)?;
    Ok(())
}

fn apply_config_diff(&mut self, _old: &NetInfoConfig, new: &NetInfoConfig) -> Result<(), String> {
    // v2.0 行为：用 self.prev_* 跟踪状态变化，非无条件写入
    let driver_ready = !new.mod_ver.is_empty();

    // ── 自保护开关（netlink 0x103，匹配 v2.0） ──
    if new.self_protect_switch != self.prev_self_protect_switch {
        log_info!("[task_fetcher] self_protect:{}→{} → netlink 0x103",
            self.prev_self_protect_switch, new.self_protect_switch);
        self.prev_self_protect_switch = new.self_protect_switch;
        if driver_ready {
            let mut pattern_mgr = self.pattern_mgr.lock().map_err(|e| e.to_string())?;
            pattern_mgr.add_file_pattern(new.self_protect_switch);
            apply_self_protect_antikill(new.self_protect_switch)?;
            self.nl_sock.as_ref()
                .ok_or("Netlink socket not initialized".to_string())?
                .send_uint32(0x103, new.self_protect_switch as u32)
                .map_err(|e| e.to_string())?;
        }
    }

    // ── 虚拟开端口 ──
    if new.open_port_switch != self.prev_open_port_switch {
        self.prev_open_port_switch = new.open_port_switch;
        if driver_ready {
            let content = format!("vir_open_port_switch {}\n",
                if new.open_port_switch { "1" } else { "0" });
            common::backend::with_backend(|b| b.write_net_rules(&content))?;
        }
    }

    // ── 动态阻断 ──
    if new.dynamic_switch != self.prev_dynamic_switch {
        self.prev_dynamic_switch = new.dynamic_switch;
        common::backend::with_backend(|b| b.write_netblock_switch(
            &(new.dynamic_switch as u32).to_string()
        ))?;
    }

    // ── 文件开关关闭 → 清理保护目录 ──
    if new.file_switch != self.prev_file_switch {
        if driver_ready && !new.file_switch {
            let mut pattern_mgr = self.pattern_mgr.lock().map_err(|e| e.to_string())?;
            pattern_mgr.clear_protect_dir();
        }
        self.prev_file_switch = new.file_switch;
    }

    // ── 勒索保护关闭 → 清理勒索目录 ──
    if new.extortion_protect != self.prev_extortion_switch {
        if driver_ready && !new.extortion_protect {
            let mut pattern_mgr = self.pattern_mgr.lock().map_err(|e| e.to_string())?;
            pattern_mgr.clear_exiport_dir();
        }
        self.prev_extortion_switch = new.extortion_protect;
    }

    // ── 进程日志开关（netlink 0x702，匹配 v2.0） ──
    if new.proc_switch != self.prev_proc_switch || new.syslog_process_switch != self.prev_syslog_process_switch {
        log_info!(
            "[task_fetcher] proc_switch:{}→{} syslog_process:{}→{} → netlink 0x702",
            self.prev_proc_switch, new.proc_switch,
            self.prev_syslog_process_switch, new.syslog_process_switch
        );
        let buf = [new.syslog_process_switch as u8, new.proc_switch as u8, 0, 0];
        self.nl_sock.as_ref()
            .ok_or("Netlink socket not initialized".to_string())?
            .send_message(0x702, &buf)
            .map_err(|e| format!("nl_sock netlog_policy: {}", e))?;
        self.prev_proc_switch = new.proc_switch;
        self.prev_syslog_process_switch = new.syslog_process_switch;
    }

    // ── defense_switch ──
    let file_flag_temp = new.file_switch || new.extortion_switch;
    let enable_flag = (file_flag_temp as u32) * 2 + (new.proc_switch as u32);
    let defense_switch: u32 = [
        (new.open_port_switch, 14),
        (new.internet_switch, 13),
        (new.syslog_dns_switch, 12),
        (new.syslog_outer_switch, 11),
        (new.syslog_inner_switch, 10),
        (new.proc_switch, 9),
        (new.file_switch, 8),
        (new.extortion_switch, 7),
        (new.proc_protect, 6),
        (new.file_protect, 5),
        (new.extortion_protect, 4),
    ].iter().fold(0u32, |acc, &(flag, shift)| acc | ((flag as u32) << shift)) | enable_flag;

    if self.prev_defense_switch != Some(defense_switch) {
        log_info!("[task_fetcher] defense_switch:{:?}→{} → proc_write /proc/osec/defense_switch",
            self.prev_defense_switch, defense_switch);
        self.prev_defense_switch = Some(defense_switch);
        if driver_ready {
            self.write_defense_switch("defense_switch", &defense_switch.to_string())?;
        }
    }

    // ── eBPF 运行时开关同步：始终调用，driver 模式 no-op，eBPF 模式写 BPF maps ──
    log_info!(
        "[task_fetcher] sync_switches file(sw={},prot={}) proc(sw={},prot={})",
        new.file_switch, new.file_protect, new.proc_switch, new.proc_protect
    );
    common::backend::with_backend(|b| {
        b.sync_switches(new.file_switch, new.proc_switch, new.file_protect, new.proc_protect)
    })?;

    Ok(())
}

pub async fn run(
    net_client: &mut NetClient,
    token: Option<String>,
    pattern_mgr: Arc<Mutex<pattern_rules_mgr::PatternRulesMgr>>,
    nl_sock: Option<NlSockInfo>,
) -> Result<(), String> {
    let token_str = token.as_ref().map(|s| s.as_str());
    let base_url = net_client
        .get_base_url()
        .ok_or("task_provider_base_url not set")?;

    let mut task_fetcher = TaskFetcher::new(base_url, token.clone(), pattern_mgr, nl_sock);

    // 初始读取 cron_time
    let initial_cron_time = {
        let cfg = NETINFO_CONFIG.lock().unwrap();
        cfg.cron_time
    };

    let mut task_interval = interval(Duration::from_secs(initial_cron_time as u64));
    let mut current_cron_time = initial_cron_time;

    // Initialize local task channel (for offline gRPC task submissions)
    let mut local_task_rx = init_local_task_rx();
    let mut local_upgrade_rx = grpc_gateway::notify::init_local_upgrade_rx();

    loop {
        let new_cron_time = {
            let cfg = NETINFO_CONFIG.lock().unwrap();
            cfg.cron_time
        };

        if new_cron_time != current_cron_time && new_cron_time > 0 {
            current_cron_time = new_cron_time;
            task_interval = interval(Duration::from_secs(new_cron_time as u64));
            log_info!("任务拉取间隔已更新为 {} 秒", new_cron_time);
        }

        tokio::select! {
            _ = task_interval.tick() => {
                let url = format!("{}/v1/gettask", task_fetcher.base_url);
                match net_client.post_data_async_with_retry(&url, "", Duration::from_secs(100), token_str, 5).await {
                    Ok(response) => {
                        set_online();
                        let parsed: Value = match serde_json::from_str(&response) {
                            Ok(parsed) => parsed,
                            Err(e) => {
                                eprintln!("Failed to parse response: {}", e);
                                log_info!("Failed to parse response: {}", e);
                                continue;
                            }
                        };

                        if parsed["code"] == "000000" {
                            let task_list = parsed["data"]["tasklist"]
                                .as_array()
                                .unwrap_or(&vec![])
                                .iter()
                                .filter_map(|v| v.as_u64().map(|n| n as u32))
                                .collect::<Vec<u32>>();

                            for task_id in task_list {
                                if let Some(task_type) = TaskTypeEnum::from_u32(task_id) {
                                    log_info!("task ID: {}, task type: {:?}", task_id, task_type);
                                    if let Err(e) = task_fetcher.handle_task(task_type).await {
                                        eprintln!("Failed to handle task {}: {}", task_id, e);
                                        log_info!("Failed to handle task {}: {}", task_id, e);
                                    }
                                } else {
                                    eprintln!("Unknown task ID: {}", task_id);
                                    log_info!("Unknown task ID: {}", task_id);
                                }
                            }
                        } else if parsed["code"] == "401" {
                            log_info!("token 无效");
                            return Err("token 无效".to_string());
                        } else {
                            let code = parsed["code"].as_str().unwrap_or("unknown");
                            eprintln!("Invalid response code: {}", code);
                            log_info!("Invalid response code: {}", code);
                            return Err("无效响应码".to_string());
                        }
                    }
                    Err(err) => {
                        eprintln!("Error fetching task: {}", err);
                        log_info!("服务器离线或网络错误: {}", err);
                        notify_network_failure();
                    }
                }
            }
            // Local task injection (from gRPC LocalTaskService, offline only)
            Some(task_id) = local_task_rx.recv() => {
                let task_id_u32 = task_id as u32;
                if let Some(task_type) = TaskTypeEnum::from_u32(task_id_u32) {
                    log_info!("[本地任务] task ID: {}, type: {:?}", task_id, task_type);
                    if let Err(e) = task_fetcher.handle_task(task_type).await {
                        log_info!("[本地任务] 处理失败 {}: {}", task_id, e);
                    }
                } else {
                    log_info!("[本地任务] 未知 task ID: {}", task_id);
                }
            }
            // Local upgrade trigger (from gRPC LocalTaskService::TriggerLocalUpdate)
            Some(zip_path) = local_upgrade_rx.recv() => {
                let arg = if zip_path.is_empty() { None } else { Some(zip_path) };
                log_info!("[本地升级] 收到 gRPC 触发，zip_path={:?}", arg);
                if let Err(e) = task_fetcher.task_update_from_local(arg).await {
                    log_info!("[本地升级] 失败: {}", e);
                }
            }
        }
    }
}


/// 根据任务类型处理任务
async fn handle_task(&mut self, task_type: TaskTypeEnum) -> Result<(), String> {
    let result = match task_type {
        TaskTypeEnum::TaskUploadProcess => self.task_upload_process(0).await,
        TaskTypeEnum::TaskUpdate => self.task_update(1).await,
        TaskTypeEnum::TaskUploadDir => self.task_upload_dir(2).await,
        TaskTypeEnum::TaskDownWhite => self.task_down_white(3).await,
        TaskTypeEnum::TaskDownDirPolicy => self.task_down_dir_policy(4).await,
        TaskTypeEnum::TaskDownConf => self.task_down_conf(6).await,
        TaskTypeEnum::TaskDownBlack => self.task_down_black(7).await,
        TaskTypeEnum::TaskDownFileTtap => self.task_down_file_tt(8).await,
        TaskTypeEnum::TaskUploadPort => self.task_upload_port(9).await,
        TaskTypeEnum::TaskDownVirtualPort => self.task_down_virtual_port(10).await,
        TaskTypeEnum::TaskDownNetBlockPolicy => self.task_down_netblock_policy(13).await,
        TaskTypeEnum::TaskDownExtort => self.task_down_extort(19).await,
        TaskTypeEnum::TaskDownBlackIpPolicy => self.task_down_black_ip_policy(15).await,
        TaskTypeEnum::TaskUploadProcessModule => self.task_upload_process_module(21).await,
        TaskTypeEnum::TaskUploadAllProcessModule => self.task_upload_all_process_module(22).await,
        TaskTypeEnum::TaskUploadProcessWhiteModule => self.task_upload_process_white_module(23).await,
        TaskTypeEnum::TaskUploadProcessBlackModule => self.task_upload_process_black_module(24).await,
        TaskTypeEnum::TaskUninstall => self.task_uninstall(25).await,
        TaskTypeEnum::TaskGetWhitePeripherals => self.task_get_white_peripherals(26).await,
        TaskTypeEnum::TaskGetBlackPeripherals => self.task_get_black_peripherals(27).await,
        TaskTypeEnum::TaskDownUsbUpload => self.task_usb_upload(16).await,
        TaskTypeEnum::TaskUploadSample => self.task_upload_sample(28).await,
        TaskTypeEnum::TaskGlobalProc => self.task_global_proc(31).await,
        TaskTypeEnum::TaskGlobalDir => self.task_global_dir(33).await,
        TaskTypeEnum::TaskUpdateUUI => self.task_update_uuid(34).await,
        TaskTypeEnum::TaskOutReachDetect => self.task_outreach_detect(35).await,
        TaskTypeEnum::TaskPwJump => self.task_down_pwjump(36).await,
        TaskTypeEnum::TaskIpJump => self.task_down_ipjump(37).await,
        TaskTypeEnum::TaskSystemBackup => self.task_get_system_backups(38).await,
        TaskTypeEnum::TaskSystemRollback => self.task_system_rollback(39).await,
        TaskTypeEnum::TaskNtpSyncAt => self.task_ntp_sync(40).await,
        _ => Err("Unknown task type".to_string()),
    };

    // On success, notify gRPC subscribers about the policy change
    if result.is_ok() {
        match task_type {
            TaskTypeEnum::TaskDownConf => notify_policy_change(PolicyChangeType::ConfigChanged),
            TaskTypeEnum::TaskDownWhite | TaskTypeEnum::TaskDownBlack => notify_policy_change(PolicyChangeType::ProcessPolicyChanged),
            TaskTypeEnum::TaskDownDirPolicy => notify_policy_change(PolicyChangeType::DirPolicyChanged),
            TaskTypeEnum::TaskDownExtort => notify_policy_change(PolicyChangeType::ExtortPolicyChanged),
            TaskTypeEnum::TaskDownNetBlockPolicy => notify_policy_change(PolicyChangeType::IpBlockPolicyChanged),
            TaskTypeEnum::TaskDownBlackIpPolicy => notify_policy_change(PolicyChangeType::IpBlackPolicyChanged),
            TaskTypeEnum::TaskGetWhitePeripherals | TaskTypeEnum::TaskGetBlackPeripherals => notify_policy_change(PolicyChangeType::PeripheralPolicyChanged),
            TaskTypeEnum::TaskDownVirtualPort => notify_policy_change(PolicyChangeType::VirtualPortChanged),
            TaskTypeEnum::TaskOutReachDetect => notify_policy_change(PolicyChangeType::OutreachRulesChanged),
            TaskTypeEnum::TaskGlobalDir => notify_policy_change(PolicyChangeType::TrustDirChanged),
            _ => {}
        }
    }

    result
}

// 处理 TASK_UPLOAD_PROCESS 任务
async fn task_upload_process(&self, task_type: u64) -> Result<(), String> {

//    self.report_task_completion(task_type).await
//        .map_err(|e| e.to_string())?;

    let upload_url = match self.api_interface.get("upload_process") {
        Some(url) => url,
        None => return Err("URL for upload_gloabal_process not found".to_string()),
    };

    let url = format!("{}/{}", self.base_url, upload_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>
                                                        // 
    let processes = task::spawn_blocking(|| {
        get_running_process_infos().map_err(|e| e.to_string())
    })
    .await
        .map_err(|e| format!("Spawn error: {:?}", e))?
        .map_err(|e| format!("Collection error: {}", e))?;

    log_info!("Collected {} processes", processes.len());
    //for p in &processes {
    //    log_info!("[{}] {} -> {}", p.pid, p.name, p.exe_path);
    //}

    let mut json_str = String::new();
    match build_process_list_json(&processes, &mut json_str, None) {
        Ok(()) => {
            match self.net_client.post_data_async(
                &url,
                &json_str,
                Duration::from_secs(10),
                token_str,
            ).await{
                Ok(response) => {log_info!("服务器响应: {}", response)},
                Err(err) => {
                    log_info!("发送指标失败: {}", err);
                    eprintln!("发送指标失败: {}", err)
                },
            }

        }
        Err(e) => {
            log_error!("构建 JSON 失败: {}", e);
        }
    }
    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;


    Ok(())
}


pub async fn task_update(&self, task_type: u64) -> Result<(), String> {

    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    let download_url = self.api_interface.get("update")
        .ok_or("URL for download update not found".to_string())?;
    let url = format!("{}/{}", self.base_url, download_url);
    log_info!("upgrade url: {}", url);

    let token = self.get_token();
    let token_owned = token.clone();
    let token_str = token_owned.as_deref();

    let response = self.net_client
        .post_data_async(&url, "", Duration::from_secs(30), token_str)
        .await
        .map_err(|e| format!("Error fetching update info: {}", e))?;

    let parsed: serde_json::Value = serde_json::from_str(&response)
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if parsed["code"] != "000000" {
        log_info!("Invalid response code: {}", parsed["code"].as_str().unwrap_or("unknown"));
        return Err(format!("Invalid response code: {}", parsed["code"].as_str().unwrap_or("unknown")));
    }

    let data = parsed["data"].as_object().ok_or("Missing 'data' object in response")?;
    let alias = data.get("alias").and_then(|v| v.as_str()).unwrap_or("update.zip");
    let download_link = data.get("download").and_then(|v| v.as_str()).ok_or("Missing download url")?;

    // ==================== 2. 下载并解压更新包 ====================
    log_info!("🔽 开始下载更新包: {}", download_link);
    let zip_bytes = self.net_client
        .download_file_async(download_link, Duration::from_secs(600), None)
        .await
        .map_err(|e| format!("下载更新包失败: {}", e))?;

    let temp_dir = "/tmp/osec_update";
    let _ = fs::remove_dir_all(temp_dir); // 先清理旧的残留
    fs::create_dir_all(temp_dir).map_err(|e| e.to_string())?;
    let zip_path = format!("{}/{}", temp_dir, alias);
    fs::write(&zip_path, &zip_bytes).map_err(|e| e.to_string())?;

    let reader = Cursor::new(&zip_bytes);
    let mut archive = ZipArchive::new(reader).map_err(|e| e.to_string())?;
    archive.extract(temp_dir).map_err(|e| e.to_string())?;
    log_info!("✅ 更新包已解压到: {}", temp_dir);

    // 前置校验：确认升级包里有可执行脚本
    // 优先检查 upgrade.conf（每行一个脚本名，支持 '*' / '?' 通配符），没有则退回找含 "installer-" 的 .sh
    let conf_path = format!("{}/upgrade.conf", temp_dir);

    let resolved_scripts: Vec<PathBuf> = if Path::new(&conf_path).exists() {
        log_info!("升级包包含 upgrade.conf，将按配置文件执行");
        let content = fs::read_to_string(&conf_path)
            .map_err(|e| format!("读取 upgrade.conf 失败: {}", e))?;
        let mut matched: Vec<PathBuf> = Vec::new();
        for line in content.lines().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            for p in resolve_upgrade_conf_line(temp_dir, line) {
                if !matched.contains(&p) {
                    matched.push(p);
                }
            }
        }
        matched
    } else {
        // 无 upgrade.conf：退回找含 "installer-" 的 .sh
        let mut found: Option<PathBuf> = None;
        for entry in fs::read_dir(temp_dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if name.contains("installer-") && name.ends_with(".sh") {
                    found = Some(path);
                    break;
                }
            }
        }
        match found {
            Some(p) => vec![p],
            None => {
                let mut files = vec![];
                if let Ok(entries) = fs::read_dir(temp_dir) {
                    for entry in entries.flatten() {
                        if let Some(name) = entry.file_name().to_str() {
                            files.push(name.to_string());
                        } else {
                            files.push("<非UTF8文件名>".to_string());
                        }
                    }
                }
                return Err(format!(
                    "升级包里既无 upgrade.conf 也无含 'installer-' 的脚本，目录文件: {:?}",
                    files
                ));
            }
        }
    };

    if resolved_scripts.is_empty() {
        return Err("upgrade.conf 中没有任何一行匹配到升级脚本（支持通配符 * 和 ?）".to_string());
    }

    log_info!("✅ 找到升级脚本: {:?}", resolved_scripts);


    let binary_name = "MagicArmorAgent";
    let running_arch = detect_runtime_arch();
    let need_hot_upgrade = Path::new(temp_dir).join(format!("{}.{}", binary_name, running_arch)).exists();
    let current_arch = if need_hot_upgrade { running_arch.as_str() } else { "unknown" };
    if !need_hot_upgrade {
        log_info!("[upgrade] ⚠️ 升级包中未找到 {}.{} 的热升级二进制，将当作普通脚本更新处理", binary_name, running_arch);
    }

    if need_hot_upgrade {
        log_info!("[upgrade] 🎯 检测到更新包包含新版本主程序 MagicArmorAgent.{}，开始完整热升级", current_arch);

        write_proc_self().await.map_err(|e| format!("write_proc_self 失败: {}", e))?;

        log_info!("[upgrade] → 步骤2: 停止 agent_manager 服务");
        stop_agent().await?;

        log_info!("[upgrade] → 步骤3: 替换 MagicArmorAgent 主程序");
        replace_binary_with_arch_check(temp_dir).await?;

        log_info!("[upgrade] → 步骤4: 启动新版本服务");
        start_agent().await?;

        log_info!("[upgrade] 🎉 主程序热升级完成！新版本已成功运行");
    } else {
        log_info!("[upgrade] ℹ️ 更新包不包含 MagicArmorAgent 二进制（或架构不匹配），仅下发脚本/配置，跳过热升级");
    }

    if let Err(e) = send_command_to_agent("update").await {
        log_info!("发送 update 命令失败: {}", e);
    } else {
        log_info!("✅ 已发送 update 命令给 agent");
    }

    log_info!("🚀 task_update 任务执行完毕");
    Ok(())
}

async fn task_upload_dir(&self, task_type: u64) -> Result<(), String> {
    const MAX_FILES: usize = 1000;

    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    let download_url = match self.api_interface.get("getdirinfo") {
        Some(url) => url,
        None => return Err("未找到 getdirinfo 策略的 URL".to_string()),
    };
    let url = format!("{}/{}", self.base_url, download_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str());

    let response = match self.net_client
        .post_data_async(&url, "", Duration::from_secs(30), token_str)
        .await
        {
            Ok(response) => response,
            Err(err) => {
                eprintln!("获取 getdirinfo 策略失败: {}", err);
                return Err(err);
            }
        };

    let parsed: Value = match serde_json::from_str(&response) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("解析 getdirinfo 响应失败: {}", e);
            return Err("解析 getdirinfo 响应失败".to_string());
        }
    };

    if parsed["code"] != "000000" {
        eprintln!("警告: getdirinfo 返回 code != 000000: {}", parsed["code"]);
    }

    let rules: Vec<DirectionScanRule> = parsed["data"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect()
        })
    .unwrap_or_default();

    //log_info!("收到 {} 条目录监控策略，开始扫描", rules.len());

    let mut all_files = Vec::new();

    for rule in &rules {
        if all_files.len() >= MAX_FILES {
            log_warn!("已达到最大上报条数 {} 条，停止扫描后续目录", MAX_FILES);
            break;
        }

        match scan_single_dir(&rule.dir, rule.pid).await {
            Ok(mut files) => {
                let remaining = MAX_FILES - all_files.len();
                if files.len() > remaining {
                    log_warn!("目录 {} 文件过多，仅取前 {} 条上报", rule.dir, remaining);
                    files.truncate(remaining);
                }
                let count = files.len();
                all_files.append(&mut files);
                log_info!("扫描 {} → {} 条记录 (累计 {} 条", rule.dir, count, all_files.len());
            }
            Err(e) => log_warn!("扫描目录 {} 失败: {}", rule.dir, e),
        }
    }

    let files_json_str = serde_json::to_string(&all_files)
        .map_err(|e| format!("序列化文件列表失败: {e}"))?;

    let payload = json!({
        "dir": files_json_str   
    });
    let body = payload.to_string();

    let upload_url = self.full_url("putdir")?;

    //   log_info!("上传目录信息 → {}", upload_url);

    let resp = self
        .net_client
        .post_data_async(&upload_url, &body, Duration::from_secs(120), token_str)
        .await
        .map_err(|e| format!("上传目录信息失败: {e}"))?;
    /*
       log_info!(
       "目录扫描上传完成，共 {} 条记录（上限 {} 条），服务器返回: {}",
       all_files.len(),
       MAX_FILES,
       resp.trim()
       );
       */
    Ok(())
}

// 处理 TASK_DOWN_DIR_POLICY 任务
async fn task_down_dir_policy(&self, task_type: u64) -> Result<(), String> {
    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;
    let download_url = match self.api_interface.get("getdirpolicy") {
        Some(url) => url,
        None => return Err("URL for download_white not found".to_string()),
    };


    let url = format!("{}/{}", self.base_url, download_url);
    log_info!("protect ====================={}",url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>

    match self.net_client.post_data_async(&url, "", Duration::from_secs(30), token_str).await {
        Ok(response) => {
            // 解析 JSON 响应
            let parsed: Value = match serde_json::from_str(&response) {
                Ok(parsed) => parsed,
                Err(e) => {
                    eprintln!("Failed to parse response: {}", e);
                    return Err("Failed to parse response.".to_string());
                }
            };

            if parsed["code"] == "000000" {
                //                    log_info!("{}", parsed["data"]);
                let rules = pattern_rules_mgr::PatternRulesMgr::parse_policy_from_json(&parsed["data"])?;
                crate::policy_persistence::save_dir_policy(&rules, false);
                //if (rules.len() > 0)
                {
                    let mut pattern_mgr = self.pattern_mgr.lock().map_err(|e| e.to_string())?;
                    pattern_mgr.set_protect_dir(rules);
                }

                // Update gRPC cache
                if let Some(data) = parsed["data"].as_array() {
                    let proto_rules: Vec<grpc_gateway::dir_policy::DirectionScanRule> = data
                        .iter()
                        .filter_map(|v| {
                            Some(grpc_gateway::dir_policy::DirectionScanRule {
                                dir: v.get("dir")?.as_str()?.to_string(),
                                pid: 0,
                                typ: v.get("type")?.as_u64()? as u32,
                            })
                        })
                        .collect();
                    *grpc_gateway::notify::DIR_POLICY_CACHE.lock().unwrap() = proto_rules;
                    notify_policy_change(PolicyChangeType::DirPolicyChanged);
                }
            } else {
                eprintln!("Error: Invalid response code: {}", parsed["code"]);
                return Err("Invalid response code.".to_string());
            }
        }
        Err(err) => {
            eprintln!("Error fetching task: {}", err);
            return Err(err);
        }
    }
    Ok(())
}


async fn task_down_conf(&mut self, task_type: u64) -> Result<(), String> {
    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    let download_url = match self.api_interface.get("getconf") {
        Some(url) => url,
        None => return Err("URL for download_white not found".to_string()),
    };

    let url = format!("{}/{}", self.base_url, download_url);

    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>
    match self.net_client.post_data_async(&url, "", Duration::from_secs(30), token_str).await {
        Ok(response) => {
            // 解析 JSON 响应
            let parsed: Value = match serde_json::from_str(&response) {
                Ok(parsed) => parsed,
                Err(e) => {
                    eprintln!("Failed to parse response: {}", e);
                    return Err("Failed to parse response.".to_string());
                }
            };

            if parsed["code"] == "000000" {
                let conf = parsed["data"]["conf"]
                    .as_object()
                    .ok_or("Missing 'conf' object in response")?;
                log_info!("==============================conf:{:?}",conf);
                self.update_config_from_json(conf)?;                   

            } else {
                eprintln!("Error: Invalid response code: {}", parsed["code"]);
                // 返回错误的 Result 类型
                return Err("Invalid response code.".to_string());
            }
        }
        Err(err) => {
            eprintln!("Error fetching task: {}", err);
            // 返回错误的 Result 类型
            return Err(err);
        }
    }


    Ok(())
}

// 处理 TASK_DOWN_BLACK 任务
async fn task_down_black(&self, task_type: u64) -> Result<(), String> {

    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    // 获取 download_white 的 URL
    let download_url = match self.api_interface.get("download_black") {
        Some(url) => url,
        None => return Err("URL for download_white not found".to_string()),
    };

    // 组合最终的 URL
    let url = format!("{}/{}", self.base_url, download_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>
    match self.net_client.post_data_async(&url, "", Duration::from_secs(30), token_str).await {
        Ok(response) => {

            // 解析 JSON 响应
            let parsed: Value = match serde_json::from_str(&response) {
                Ok(parsed) => parsed,
                Err(e) => {
                    eprintln!("Failed to parse response: {}", e);
                    return Err("Failed to parse response.".to_string());
                }
            };

            if parsed["code"] == "000000" {

                let hash_list = parsed["data"]["proclist"]
                    .as_array()
                    .ok_or("Missing or invalid proclist in response")?
                    .iter()
                    .filter_map(|item| item["hash"].as_str().map(|s| s.to_string()))
                    .collect::<Vec<String>>();

                if hash_list.is_empty() {
                    return Err("No hashes found in the response".to_string());
                }

                let mut mgr = POLICY_MANAGER.lock().unwrap();
                mgr.set_policy_process(&hash_list, false, Some(false));
            } else {
                eprintln!("Error: Invalid response code: {}", parsed["code"]);
                // 返回错误的 Result 类型
                return Err("Invalid response code.".to_string());
            }
        }
        Err(err) => {
            eprintln!("Error fetching task: {}", err);
            // 返回错误的 Result 类型
            return Err(err);
        }
    }

    Ok(())
}


pub async fn task_down_white(&self, task_type: u64) -> Result<(), String> {

    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    // 获取 download_white 的 URL
    let download_url = match self.api_interface.get("download_white") {
        Some(url) => url,
        None => return Err("URL for download_white not found".to_string()),
    };


    let url = format!("{}/{}", self.base_url, download_url);

    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>
    log_info!("==============url:{},token{:?}", url, token_str);                                                        
    match self.net_client.post_data_async(&url, "", Duration::from_secs(120), token_str).await {
        Ok(response) => {
            //log_info!("[task_down_white] 服务器原始响应: {}", response);
            let parsed: Value = match serde_json::from_str(&response) {
                Ok(parsed) => parsed,
                Err(e) => {
                    eprintln!("Failed to parse response: {}", e);
                    return Err("Failed to parse response.".to_string());
                }
            };

            if parsed["code"] == "000000" {
                let hash_list = parsed["data"]["proclist"]
                    .as_array()
                    .ok_or("Missing or invalid proclist in response")?
                    .iter()
                    .filter_map(|item| item["hash"].as_str().map(|s| s.to_string()))
                    .collect::<Vec<String>>();

                if hash_list.is_empty() {
                    log_error!("[task_down_white] proclist 为空或字段不是 hash，原始响应: {}", response);
                    return Err("No hashes found in the response".to_string());
                }

                let mut mgr = POLICY_MANAGER.lock().unwrap();
                mgr.set_policy_process(&hash_list, true, Some(false));
                log_info!("[task_down_white] 白名单 {} 条已写入内存", hash_list.len());
            } else {
                log_error!("[task_down_white] 响应 code != 000000: code={}", parsed["code"]);
                return Err("Invalid response code.".to_string());
            }
        }
        Err(err) => {
            eprintln!("Error fetching task: {}", err);
            // 返回错误的 Result 类型
            return Err(err);
        }
    }


    Ok(())
}

// 处理 TASK_DOWN_FILE_TT 任务
async fn task_down_file_tt(&self, task_type: u64) -> Result<(), String> {
    println!("Processing TASK_DOWN_FILE_TT...");
    // 下载文件 TT 的处理
    Ok(())
}

async fn task_upload_port(&self, task_type: u64) -> Result<(), String> {
    //println!("Processing TASK_UPLOAD_PORT...");

    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    let upload_url = match self.api_interface.get("upserviceport") {
        Some(url) => url,
        None => return Err("URL for upload_gloabal_process not found".to_string()),
    };


    let url = format!("{}/{}", self.base_url, upload_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>
                                                        // Get JSON string using get_netapp_json
    let json_data = match get_netapp_json() {
        Ok(json) => json,
        Err(e) => return Err(format!("Failed to serialize port data to JSON: {}", e)),
    };
    log_info!("准备上传的数据: {}", json_data);
    match self.net_client.post_data_async(&url, &json_data, Duration::from_secs(30), token_str).await{
        Ok(response) => {log_info!("服务器响应: {}", response)},
        Err(err) => {
            log_info!("发送指标失败: {}", err);
            eprintln!("发送指标失败: {}", err)
        }
    }
    Ok(())
}

pub async fn task_down_virtual_port(&self, task_type: u64) -> Result<(), String> {

    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    let download_url = match self.api_interface.get("getvirtualport") {
        Some(url) => url,
        None => return Err("URL for getvirtualport not found".to_string()),
    };


    let url = format!("{}/{}", self.base_url, download_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str());

    let response = self.net_client.post_data_async(&url, "", Duration::from_secs(30), token_str).await?;
    let parsed: Value = serde_json::from_str(&response)
        .map_err(|e| format!("Failed to parse response JSON: {}", e))?;

    if parsed["code"] != "000000" {
        return Err(format!("Invalid response code: {}", parsed["code"]));
    }

    let conf: Vec<VirtualPortRule> = parsed["data"]
        .as_array()
        .ok_or("Missing 'data' array in response")?
        .iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| format!("Failed to parse VirtualPortRule: {}", e))
        })
    .collect::<Result<Vec<VirtualPortRule>, _>>()?;

    let valid_rules: Vec<_> = conf.into_iter()
        .filter(|r| !r.source_ip.is_empty())
        .collect();

    let total = valid_rules.len();
    log_info!("virtual port ==============================================");
    // Update gRPC cache BEFORE proc write (cache works even without kernel module)
    {
        let proto_rules: Vec<grpc_gateway::virtual_port::VirtualPortRule> = valid_rules
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
        log_info!("=======proto_rules{:?}",proto_rules);
        *VIRTUAL_PORT_CACHE.lock().unwrap() = proto_rules;
        notify_policy_change(PolicyChangeType::VirtualPortChanged);
    }
    log_info!("================valid_rules:{:?}",valid_rules);
    if total == 0 {
        log_error!("No valid rules to write to /proc/osec/net_rules");
        return Ok(());
    }

    // 通过 SecurityBackend 抽象下发：
    // driver 后端 → 原样写 /proc/osec/net_rules（内容与直写完全一致）；
    // eBPF  后端 → 解析 VIR_OPEN_PORT 行写入 pkt_mod_rules map
    let mut batch = String::new();
    for (index, rule) in valid_rules.iter().enumerate() {
        // protocol 转数字: tcp=1, udp=2, 其他=0
        let protocol_num = match rule.protocol.to_lowercase().as_str() {
            "tcp" => 1,
            "udp" => 2,
            _ => 0,
        };

        let is_ipv4 = if rule.dest_ip.contains(':') { 0u8 } else { 1u8 }; // ':' 表示 IPv6
                                                                          // if

        let addr_type = (rule.alarm_level & 0x1f) as u8;

        let rule_str = format!(
            "VIR_OPEN_PORT index={} total={} id={} protocol={} type={} is_ipv4={} source_ip={} start_port={} end_port={}  dest_ip={} dest_port_type={} redirectPort={} addr_type={}\n",
            index,
            total,
            rule.id,
            protocol_num,
            rule.r#type,
            is_ipv4,
            rule.source_ip,
            rule.source_port_range.0,
            rule.source_port_range.1,
            if rule.dest_ip.trim().is_empty() {
                "\"\""
            } else {
                &rule.dest_ip
            },
            rule.dest_port_type,
            if rule.dest_port_type == 0 {
                rule.dest_port.parse::<u16>().unwrap_or(0)
            } else {
                0
            },
            addr_type,
            );

        log_info!("{}", rule_str);
        batch.push_str(&rule_str);
    }

    common::backend::with_backend(|b| b.write_net_rules(&batch))?;

    log_info!("Successfully wrote {} rules via backend", total);

    Ok(())
}


async fn task_down_netblock_policy(&self, task_type: u64) -> Result<(), String> {

    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    let download_url = match self.api_interface.get("getPlugging") {
        Some(url) => url,
        None => return Err("未找到 netblock 策略的 URL".to_string()),
    };

    let url = format!("{}/{}", self.base_url, download_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str());
    let response = match self.net_client
        .post_data_async(&url, "", Duration::from_secs(30), token_str)
        .await
        {
            Ok(response) => response,
            Err(err) => {
                eprintln!("获取 netblock 策略失败: {}", err);
                return Err(err);
            }
        };

    // 解析 JSON 响应
    let parsed: Value = match serde_json::from_str(&response) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("解析 netblock 响应失败: {}", e);
            return Err("解析 netblock 响应失败".to_string());
        }
    };

    if parsed["code"] != "000000" {
        eprintln!("错误: netblock 响应代码无效: {}", parsed["code"]);
        return Err("netblock 响应代码无效".to_string());
    }

    // 提取策略
    let mut policies: Vec<IpPolicy> = Vec::new();
    if let Some(data) = parsed["data"].as_array() {
        for entry in data {
            if let (Some(ip), Some(direction), Some(duration)) = (
                entry["ip"].as_str(),
                entry["direction"].as_u64().map(|d| d as u32),
                entry["duration"].as_u64(),
            ) {
                policies.push(IpPolicy {
                    ip: ip.to_string(),
                    direction,
                    duration,
                    is_ipv6: is_ipv6(ip),
                });
            }
        }
    }

    update_and_write_policies(policies, "netblocks").await
}

async fn task_down_black_ip_policy(&self, task_type: u64) -> Result<(), String> {

    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    let download_url = match self.api_interface.get("getipblacklist") {
        Some(url) => url,
        None => return Err("未找到 black IP 策略的 URL".to_string()),
    };

    let url = format!("{}/{}", self.base_url, download_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str());
    let response = match self.net_client
        .post_data_async(&url, "", Duration::from_secs(30), token_str)
        .await
        {
            Ok(response) => response,
            Err(err) => {
                eprintln!("获取 black IP 策略失败: {}", err);
                return Err(err);
            }
        };

    // 解析 JSON 响应
    let parsed: Value = match serde_json::from_str(&response) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("解析 black IP 响应失败: {}", e);
            return Err("解析 black IP 响应失败".to_string());
        }
    };

    if parsed["code"] != "000000" {
        eprintln!("错误: black IP 响应代码无效: {}", parsed["code"]);
        return Err("black IP 响应代码无效".to_string());
    }

    // 提取策略
    let mut policies: Vec<IpPolicy> = Vec::new();
    if let Some(data) = parsed["data"].as_array() {
        for entry in data {
            if let (Some(ip), Some(direction)) = (
                entry["ip"].as_str(),
                entry["direction"].as_u64().map(|d| d as u32),
            ) {
                policies.push(IpPolicy {
                    ip: ip.to_string(),
                    direction,
                    duration: 0, // black_ip_policy 没有 duration，设为 0
                    is_ipv6: is_ipv6(ip),
                });
            }
        }
    }
   log_info!("black ip policies:{:?}", policies);
    // 更新全局 Map 并下发到内核
    update_and_write_policies(policies, "policies").await
}
async fn task_down_extort(&self, task_type: u64) -> Result<(), String> {

    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    // 获取 download_white 的 URL
    let download_url = match self.api_interface.get("getprotect") {
        Some(url) => url,
        None => return Err("URL for download_white not found".to_string()),
    };

    let url = format!("{}/{}", self.base_url, download_url);
    log_info!("lesuo======={}",url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>
    match self.net_client.post_data_async(&url, "", Duration::from_secs(30), token_str).await {
        Ok(response) => {

            // 解析 JSON 响应
            let parsed: Value = match serde_json::from_str(&response) {
                Ok(parsed) => parsed,
                Err(e) => {
                    eprintln!("Failed to parse response: {}", e);
                    return Err("Failed to parse response.".to_string());
                }
            };

            if parsed["code"] == "000000" {
                let rules = pattern_rules_mgr::PatternRulesMgr::parse_exipor_policy_from_json(&parsed["data"])?;
                crate::policy_persistence::save_extort_policy(&rules, false);
                let mut pattern_mgr = self.pattern_mgr.lock().map_err(|e| e.to_string())?;
                pattern_mgr.set_exiport_dir(rules);

                // Update gRPC cache
                if let Some(data) = parsed["data"].as_array() {
                    let proto_rules: Vec<grpc_gateway::extort_policy::ExtortProtectRule> = data
                        .iter()
                        .filter_map(|v| {
                            let process_arr = v.get("process")?.as_array()?;
                            let mut map_comm = std::collections::HashMap::new();
                            for p in process_arr {
                                if let (Some(h), Some(n)) = (p.get("hash")?.as_str(), p.get("name")?.as_str()) {
                                    map_comm.insert(h.to_string(), n.to_string());
                                }
                            }
                            Some(grpc_gateway::extort_policy::ExtortProtectRule {
                                file_type: v.get("file_suffix")?.as_str()?.to_string(),
                                typ: v.get("type")?.as_u64()? as u32,
                                map_comm,
                            })
                        })
                        .collect();
                    *grpc_gateway::notify::EXTORT_POLICY_CACHE.lock().unwrap() = proto_rules;
                    notify_policy_change(PolicyChangeType::ExtortPolicyChanged);
                }

            } else {
                eprintln!("Error: Invalid response code: {}", parsed["code"]);
                // 返回错误的 Result 类型
                return Err("Invalid response code.".to_string());
            }
        }
        Err(err) => {
            eprintln!("Error fetching task: {}", err);
            // 返回错误的 Result 类型
            return Err(err);
        }
    }

    Ok(())
}



// 处理 TASK_UPLOAD_PROCESS_MODULE 任务
async fn task_upload_process_module(&self, task_type: u64) -> Result<(), String> {
    println!("Processing TASK_UPLOAD_PROCESS_MODULE...");
    // 上传进程模块的处理
    Ok(())
}

// 处理 TASK_UPLOAD_ALL_PROCESS_MODULE 任务
async fn task_upload_all_process_module(&self, task_type: u64) -> Result<(), String> {
    println!("Processing TASK_UPLOAD_ALL_PROCESS_MODULE...");
    // 上传所有进程模块的处理
    Ok(())
}

// 处理 TASK_UPLOAD_PROCESS_WHITE_MODULE 任务
async fn task_upload_process_white_module(&self, task_type: u64) -> Result<(), String> {
    println!("Processing TASK_UPLOAD_PROCESS_WHITE_MODULE...");
    // 上传白名单进程模块的处理
    Ok(())
}

// 处理 TASK_UPLOAD_PROCESS_BLACK_MODULE 任务
async fn task_upload_process_black_module(&self, task_type: u64) -> Result<(), String> {
    println!("Processing TASK_UPLOAD_PROCESS_BLACK_MODULE...");
    // 上传黑名单进程模块的处理
    Ok(())
}

// 处理 TASK_UNINSTALL 任务
async fn task_uninstall(&self, task_type: u64) -> Result<(), String> {
    println!("Processing TASK_UNINSTALL...");

    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;
    let download_url = self.api_interface.get("uninstall")
        .ok_or("URL for download uninstall not found".to_string())?;
    let url = format!("{}/{}", self.base_url, download_url);
    log_info!("url:{}",url);
    let token = self.get_token();
    let token_owned = token.clone();
    let token_str = token_owned.as_deref();

    let response = self.net_client
        .post_data_async(&url, "", Duration::from_secs(30), token_str)
        .await
        .map_err(|e| format!("Error fetching update info: {}", e))?;

    let parsed: serde_json::Value = serde_json::from_str(&response)
        .map_err(|e| format!("Failed to parse response: {}", e))?;
    if parsed["code"] != "000000" {
        log_info!("Invalid response code: {}", parsed["code"].as_str().unwrap_or("unknown"));
        return Err(format!("Invalid response code: {}", parsed["code"].as_str().unwrap_or("unknown")));
    }

    if let Err(e) = send_command_to_agent("uninstall").await {
        log_info!("发送更新命令失败: {}", e);
    }
    Ok(())
}

async fn task_get_white_peripherals(&self, task_type: u64) -> Result<(), String> {

    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    let download_url = match self.api_interface.get("getwhiteperipherals") {
        Some(url) => url,
        None => return Err("URL for download_white not found".to_string()),
    };

    let url = format!("{}/{}", self.base_url, download_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>
    match self.net_client.post_data_async(&url, "", Duration::from_secs(30), token_str).await {
        Ok(response) => {
            // 解析 JSON 响应
            let parsed: Value = match serde_json::from_str(&response) {
                Ok(parsed) => parsed,
                Err(e) => {
                    eprintln!("Failed to parse response: {}", e);
                    return Err("Failed to parse response.".to_string());
                }
            };

            if parsed["code"] == "000000" {
                log_info!("peripherals: {}", parsed["data"]);
                let data = &parsed["data"];
                let whitelist: Vec<UsbInfo> = serde_json::from_value::<Vec<UsbInfo>>(data.clone())
                    .map_err(|e| {
                        log_error!("Failed to deserialize usb info: {}", e);
                        "反序列化失败".to_string()
                    })?
                .into_iter()
                    .map(|mut item| {
                        item.allow = true;
                        item
                    })
                .collect();

                let mut guard = SHARED_USB_LIST.lock().unwrap();
                guard.update_whitelist(whitelist);
            }
        }
        Err(err) => {
            eprintln!("Error fetching task: {}", err);
            // 返回错误的 Result 类型
            return Err(err);
        }
    }


    // 获取白名单外设的处理
    Ok(())
}

// 处理 TASK_getblackperipherals 任务
async fn task_get_black_peripherals(&self, task_type: u64) -> Result<(), String> {

    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;
    // 获取 download_white 的 URL
    let download_url = match self.api_interface.get("getblackperipherals") {
        Some(url) => url,
        None => return Err("URL for download_white not found".to_string()),
    };

    let url = format!("{}/{}", self.base_url, download_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>
    match self.net_client.post_data_async(&url, "", Duration::from_secs(30), token_str).await {
        Ok(response) => {
            // 解析 JSON 响应
            let parsed: Value = match serde_json::from_str(&response) {
                Ok(parsed) => parsed,
                Err(e) => {
                    eprintln!("Failed to parse response: {}", e);
                    return Err("Failed to parse response.".to_string());
                }
            };


            if parsed["code"] == "000000" {
                log_info!("peripherals: {}", parsed["data"]);
                let data = &parsed["data"];
                let blacklist: Vec<UsbInfo> = serde_json::from_value::<Vec<UsbInfo>>(data.clone())
                    .map_err(|e| {
                        log_error!("Failed to deserialize usb info: {}", e);
                        "反序列化失败".to_string()
                    })?
                .into_iter()
                    .map(|mut item| {
                        item.allow = false;
                        item
                    })
                .collect();

                let mut guard = SHARED_USB_LIST.lock().unwrap();
                guard.update_blacklist(blacklist, true);
            }
        }
        Err(err) => {
            eprintln!("Error fetching task: {}", err);
            // 返回错误的 Result 类型
            return Err(err);
        }
    }

    Ok(())
}
async fn task_usb_upload(&self, task_type: u64) -> Result<(), String> {

    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    let upload_url = match self.api_interface.get("addperipherals") {
        Some(url) => url,
        None => return Err("URL for upload_gloabal_process not found".to_string()),
    };

    let url = format!("{}/{}", self.base_url, upload_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>


    let devices = get_all_local_usb_devices();
    //if !devices.is_empty() 
    {
        log_info!("发现 {} 台可上传的 USB 设备", devices.len());
        let mut json_str = String::new();

        log_info!("准备上传的数据: {}", json_str);
        match build_usb_json(&devices,  &mut json_str) {

            Ok(()) => {
                match self.net_client.post_data_async(
                    &url,
                    &json_str,
                    Duration::from_secs(30),
                    token_str
                ).await {
                    Ok(response) => {log_info!("服务器响应: {}", response)},
                    Err(err) => eprintln!("发送指标失败: {}", err),
                }

                log_info!("========================生成 JSON: {}", json_str);
            }
            Err(e) => {
                log_error!("构建 JSON 失败: {}", e);
            }
        }

    }
    Ok(())
}
// 处理 TASK_UPLOADSAMPLE 任务
// 业务逻辑（对应 C++ CEntClientNetAgent::DoTaskUploadSample）：
//   1. POST "" -> /v1/getdraw  获取需上传的样本文件列表
//   2. 逐个 zip -> POST multipart -> /v1/uploaddraw 上传
//   3. 清理临时 zip 文件
async fn task_upload_sample(&self, task_type: u64) -> Result<(), String> {
    log_info!("Processing TASK_UPLOADSAMPLE...");

    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    // ── Step 1: 获取样本文件列表 ──
    let getdraw_url = match self.api_interface.get("getdraw") {
        Some(url) => url,
        None => return Err("URL for getdraw not found".to_string()),
    };
    let getdraw_full = format!("{}/{}", self.base_url, getdraw_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str());

    let response = self.net_client.post_data_async(
        &getdraw_full, "", Duration::from_secs(30), token_str
    ).await.map_err(|e| format!("getdraw request failed: {}", e))?;

    let parsed: Value = serde_json::from_str(&response)
        .map_err(|e| format!("getdraw parse error: {}", e))?;

    if parsed["code"] != "000000" {
        return Err(format!("getdraw bad code: {}", parsed["code"]));
    }

    // ── Step 2: 解析样本列表 ──
    let data = &parsed["data"];
    let samples: Vec<SampleItem> = serde_json::from_value(data.clone())
        .map_err(|e| format!("parse sample list error: {}", e))?;

    if samples.is_empty() {
        log_info!("No samples to upload");
        return Ok(());
    }

    log_info!("Received {} sample files to upload", samples.len());

    // ── Step 3: 获取 uploaddraw API ──
    let uploaddraw_url = match self.api_interface.get("uploaddraw") {
        Some(url) => url,
        None => return Err("URL for uploaddraw not found".to_string()),
    };
    let upload_full = format!("{}/{}", self.base_url, uploaddraw_url);

    // ── Step 4: 逐个打包上传 ──
    for item in &samples {
        // a. 检查文件是否存在
        if !Path::new(&item.p_dir).exists() {
            log_error!("Sample file not found, skip: {}", item.p_dir);
            continue;
        }

        // b. 打包成 zip
        let zip_path = format!("{}.zip", item.p_dir);
        if let Err(e) = zip_single_file(&item.p_dir, &zip_path) {
            log_error!("Failed to zip sample {}: {}", item.p_dir, e);
            continue;
        }

        // c. 检查 zip 文件是否创建成功
        if !Path::new(&zip_path).exists() {
            log_error!("Zip file not created: {}", zip_path);
            continue;
        }

        // d. 上传 zip 文件（multipart: file + hash）
        match self.net_client.post_file_async(
            &upload_full,
            &zip_path,
            &item.p_hash,
            Duration::from_secs(60),
            token_str,
        ).await {
            Ok(resp) => {
                log_info!("Sample uploaded ok [{}] -> {}", item.p_hash, item.p_dir);
                log_info!("Upload response: {}", resp);
            }
            Err(e) => {
                log_error!("Sample upload failed [{}] {}: {}", item.p_hash, item.p_dir, e);
            }
        }

        // e. 清理临时 zip
        let _ = std::fs::remove_file(&zip_path);
        log_info!("Sample upload done: {}", item.p_dir);
    }

    Ok(())
}


// 处理 TASK_GLOBAL_PROC 任务
async fn task_global_proc(&self, task_type: u64) -> Result<(), String> {

    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    let upload_url = match self.api_interface.get("upload_gloabal_process") {
        Some(url) => url,
        None => return Err("URL for upload_gloabal_process not found".to_string()),
    };

    let net_client = match NetClient::new(Some(self.base_url.clone()), true) {
        Ok(client) => client,
        Err(e) => return Err(format!("Failed to create NetClient: {}", e)),
    };

    // 组合最终的 URL
    let url = format!("{}/{}", self.base_url, upload_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>
    process_all_dirs(net_client, &url, token_str).await?;

    Ok(())
}

async fn task_global_dir(&self,task_type: u64) -> Result<(), String> {
    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    let download_url = match self.api_interface.get("gettrustdir") {
        Some(url) => url,
        None => return Err("URL for download_white not found".to_string()),
    };


    let url = format!("{}/{}", self.base_url, download_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str());

    match self.net_client.post_data_async(&url, "", Duration::from_secs(30), token_str).await {
        Ok(response) => {
            let parsed: Value = match serde_json::from_str(&response) {
                Ok(parsed) => parsed,
                Err(e) => {
                    eprintln!("Failed to parse response: {}", e);
                    return Err("Failed to parse response.".to_string());
                }
            };

            if parsed["code"] == "000000" {
                let data_value = &parsed["data"];
                let trust_dirs: Vec<GlobalTrustDir> = match serde_json::from_value(data_value.clone()) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Failed to deserialize data to GlobalTrustDir: {}", e);
                        return Err("Failed to deserialize data.".to_string());
                    }
                };

                PROCESS_PATTERN_RULES_MGR.lock().set_global_trust_dir(trust_dirs.clone());

                // Update gRPC cache
                {
                    let proto_dirs: Vec<grpc_gateway::trust_dir::GlobalTrustDir> = trust_dirs.iter().map(|d| grpc_gateway::trust_dir::GlobalTrustDir {
                        dir: d.dir.clone(), r#type: d.typ as u32, is_extend: d.is_extend as u32,
                    }).collect();
                    *TRUST_DIR_CACHE.lock().unwrap() = proto_dirs;
                    notify_policy_change(PolicyChangeType::TrustDirChanged);
                }
                crate::policy_persistence::save_trust_dir(&trust_dirs, false);
                let mut pattern_mgr = self.pattern_mgr.lock().map_err(|e| e.to_string())?;
                pattern_mgr.set_global_trust_dir(trust_dirs);
            } else {
                eprintln!("Error: Invalid response code: {}", parsed["code"]);
                return Err("Invalid response code.".to_string());
            }
        }
        Err(err) => {
            eprintln!("Error fetching task: {}", err);
            return Err(err);
        }
    }

    Ok(())
}
// 处理 TASK_UPDATE_UUID 任务
async fn task_update_uuid(&self, task_type: u64) -> Result<(), String> {
    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    if fs::remove_file("/etc/.vedasystem").is_ok() {
        log_info!("[task_update_uuid] 已删除 .vedasystem");
    }
    std::process::exit(1)
}

// 处理 TASK_OutreachDetect 任务
async fn task_outreach_detect(&self, task_type: u64) -> Result<(), String> {
    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    let download_url = match self.api_interface.get("getOutreachDetect") {
        Some(url) => url,
        None => return Err("URL for getOutreachDetect not found".to_string()),
    };


    let url = format!("{}/{}", self.base_url, download_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str());

    let response = self.net_client.post_data_async(&url, "", Duration::from_secs(30), token_str).await?;
    let parsed: Value = serde_json::from_str(&response)
        .map_err(|e| format!("Failed to parse response JSON: {}", e))?;

    if parsed["code"] != "000000" {
        return Err(format!("Invalid response code: {}", parsed["code"]));
    }

    let data = parsed["data"].as_object().ok_or("Missing 'data' object in response")?;
    let rules: Vec<OutreachDetectRule> = data["list"]
        .as_array()
        .ok_or("Missing 'data' array in response")?
        .iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| format!("Failed to parse VirtualPortRule: {}", e))
        })
    .collect::<Result<Vec<OutreachDetectRule>, _>>()?;
    update_global_outreach_rules(rules);
    //log_info!("rules:{:?}",rules);
    Ok(())
}

async fn task_down_pwjump(&self, task_type: u64) -> Result<(), String> {

    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    let download_url = match self.api_interface.get("getPwJump") {
        Some(url) => url,
        None => return Err("URL for getPwJump not found".to_string()),
    };

    let url = format!("{}/{}", self.base_url, download_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str());

    let response = match self
        .net_client
        .post_data_async(&url, "", Duration::from_secs(30), token_str)
        .await
        {
            Ok(res) => res,
            Err(err) => {
                eprintln!("Error fetching task: {}", err);
                return Err(err);
            }
        };

    // 解析 JSON
    let parsed: Value = match serde_json::from_str(&response) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to parse response: {}", e);
            return Err("Failed to parse response.".to_string());
        }
    };

    // 检查 code
    if parsed["code"] != "000000" {
        let msg = parsed["msg"].as_str().unwrap_or("Unknown error");
        return Err(format!("API error: {}", msg));
    }

    // 正确提取 pw 字符串
    let new_password = parsed["data"]["pw"]
        .as_str()
        .ok_or("Missing or invalid 'pw' field in response")?;

    // 构造 info
    let mut info = PutPwJumpInfo {
        user: "".to_string(),
        pw: "".to_string(),
        status: 0,
        reason: "".to_string(),
    };
    let mgr = PasswordManager::new();
    let jump_result = mgr.do_pw_jump_async("", new_password, &mut info).await;
    match jump_result {
        Ok(_) => {
            log_info!("pw jump success: {:?}", info);
            //info.user = "zebra".to_string(); 
            info.pw = new_password.to_string();
            info.status = 1; // 成功状态
        },
        Err(e) => {
            log_info!("pw jump fail: {:?}", e);
            //info.user = "zebra".to_string();
            info.pw = new_password.to_string();
            info.status = 2; // 失败状态
            info.reason = e.to_string(); // 记录失败原因
        }
    }
    self.upload_passwd_result(&info.user, &info.pw, info.status, &info.reason).await?;

    Ok(())
}
/*
   async fn task_down_ipjump(&self, task_type: u64) -> Result<(), String> {
   self.report_task_completion(task_type).await
   .map_err(|e| e.to_string())?;

   let download_url = match self.api_interface.get("getIpJump") {
   Some(url) => url,
   None => return Err("URL for getIpJump not found".to_string()),
   };
   let url = format!("{}/{}", self.base_url, download_url);
   log_info!("url: {}", url);
   let token = self.get_token();
   let token_str = token.as_ref().map(|s| s.as_str());
   match self.net_client.post_data_async(&url, "", Duration::from_secs(10), token_str).await {
   Ok(response) => {
   let parsed: Value = match serde_json::from_str(&response) {
   Ok(parsed) => parsed,
   Err(e) => {
   log_error!("Failed to parse response: {}", e);
   return Err("Failed to parse response.".to_string());
   }
   };
   if parsed["code"] != "000000" {
   let msg = parsed["msg"].as_str().unwrap_or("Unknown error");
   log_error!("API error: {}",msg);
   return Err(format!("API error: {}", msg));
   }
   let data = parsed["data"].as_object().ok_or("Missing 'data' object in response")?;
   log_info!("data: {:?}", data);
   let gateway = data.get("gateway").and_then(|v| v.as_str()).unwrap_or("");
   let source_ip = data.get("source_ip").and_then(|v| v.as_str()).unwrap_or("");
   let target_ip = data.get("target_ip").and_then(|v| v.as_str()).unwrap_or("");
   let mode = data.get("mode").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
   let allow_size = data.get("allow_size").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
   let aging_time = data.get("aging_time").and_then(|v| v.as_u64()).unwrap_or(300) as u32;
   let active_time = data.get("active_time").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
   log_info!(
   "IP Jump Task: source_ip={}, target_ip={}, gateway={}, mode={}, allow_size={}, aging_time={},active_time={}",
   source_ip, target_ip, gateway, mode, allow_size, aging_time,active_time
   );
   if source_ip.is_empty() && target_ip.is_empty() {
   log_info!("Both source_ip and target_ip are empty; skipping IP jump.");
   self.report_task_completion(task_type).await?;
   return Ok(());
   }

   let config = IpJumpConfig {
   source_ip: source_ip.to_string(),
   target_ip: target_ip.to_string(),
   gateway: gateway.to_string(),
   };
   let mut info = PutIpJumpInfo {
   source_ip: "".to_string(),
   target_ip: "".to_string(),
   gateway: "".to_string(),
   agent_ip: "".to_string(),
   status: 0,
   reason: "".to_string(),
   };
   let jump_result = self.ip_jump_manager.do_ip_jump_async(config, &mut info, mode).await;
   match jump_result {
   Ok(_) => {
   log_info!("ip jump success: {:?}", info);
   info.status = 1;
   }
   Err(e) => {
   log_error!("ip jump fail: {:?}", e);
   info.status = 2;
   info.reason = e.to_string();
   }
   }
self.upload_ip_jump_result(
    &info.source_ip,
    &info.target_ip,
    &info.gateway,
    &info.agent_ip,
    info.status as u8,
    &info.reason,
).await?;
}
Err(err) => {
    log_error!("Error fetching task: {}", err);
    return Err(err);
}
}
Ok(())
    }
*/
/*
async fn task_down_ipjump(&self, task_type: u64) -> Result<(), String> {
    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    let download_url = match self.api_interface.get("getIpJump") {
        Some(url) => url,
        None => return Err("URL for getIpJump not found".to_string()),
    };
    let url = format!("{}/{}", self.base_url, download_url);
    log_info!("url: {}", url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str());
    match self.net_client.post_data_async(&url, "", Duration::from_secs(10), token_str).await {
        Ok(response) => {
            let parsed: Value = match serde_json::from_str(&response) {
                Ok(parsed) => parsed,
                Err(e) => {
                    log_error!("Failed to parse response: {}", e);
                    return Err("Failed to parse response.".to_string());
                }
            };
            if parsed["code"] != "000000" {
                let msg = parsed["msg"].as_str().unwrap_or("Unknown error");
                log_error!("API error: {}", msg);
                return Err(format!("API error: {}", msg));
            }
            let data = parsed["data"].as_object().ok_or("Missing 'data' object in response")?;
            log_info!("data: {:?}", data);
            let gateway = data.get("gateway").and_then(|v| v.as_str()).unwrap_or("");
            let source_ip = data.get("source_ip").and_then(|v| v.as_str()).unwrap_or("");
            let target_ip = data.get("target_ip").and_then(|v| v.as_str()).unwrap_or("");
            let mode = data.get("mode").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
            let allow_size = data.get("allow_size").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let aging_time = data.get("aging_time").and_then(|v| v.as_u64()).unwrap_or(300) as u32;
            let active_time = data.get("active_time").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            log_info!(
                "IP Jump Task: source_ip={}, target_ip={}, gateway={}, mode={}, allow_size={}, aging_time={}, active_time={}",
                source_ip, target_ip, gateway, mode, allow_size, aging_time, active_time
            );
            if source_ip.is_empty() && target_ip.is_empty() {
                log_info!("Both source_ip and target_ip are empty; skipping IP jump.");
                self.report_task_completion(task_type).await?;
                return Ok(());
            }

            let config = IpJumpConfig {
                source_ip: source_ip.to_string(),
                target_ip: target_ip.to_string(),
                gateway: gateway.to_string(),
            };
            let mut info = PutIpJumpInfo {
                source_ip: "".to_string(),
                target_ip: "".to_string(),
                gateway: "".to_string(),
                agent_ip: "".to_string(),
                status: 0,
                reason: "".to_string(),
            };
            let jump_result = self.ip_jump_manager.do_ip_jump_async(config, &mut info, mode).await;
            match jump_result {
                Ok(_) => {
                    log_info!("ip jump success: {:?}", info);
                    info.status = 1;
                }
                Err(e) => {
                    log_error!("ip jump fail: {:?}", e);
                    info.status = 2;
                    info.reason = e.to_string();
                }
            }
            self.upload_ip_jump_result(
                &info.source_ip,
                &info.target_ip,
                &info.gateway,
                &info.agent_ip,
                info.status as u8,
                &info.reason,
            ).await?;

            if active_time > 0 {
                if AUTO_IP_JUMP_DAEMON_RUNNING.compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed).is_ok() {
                    log_info!("Spawning auto IP Jump daemon with interval: {}s", active_time);

                    let base_url = self.base_url.clone();
                    let token = self.get_token();
                    let ip_jump_manager = self.ip_jump_manager.clone();
                    let api_interface = self.api_interface.clone();
                    let upload_url = format!("{}/{}", base_url, api_interface.get("putIpJump").cloned().unwrap_or_else(|| "v1/putIpJump".to_string()));

                    tokio::spawn(async move {
                        let mut current_interval = active_time;
                        loop {
                            sleep(Duration::from_secs(current_interval as u64)).await;

                            let download_url = api_interface.get("getIpJump")
                                .cloned()
                                .unwrap_or_else(|| "v1/getIpJump".to_string());
                            let url = format!("{}/{}", base_url, download_url);
                            let token_str = token.as_deref();

                            let client = match NetClient::new(Some(base_url.clone()), true) {
                                Ok(c) => c,
                                Err(e) => {
                                    log_error!("Auto IP Jump: create NetClient failed: {}", e);
                                    continue;
                                }
                            };

                            match client.post_data_async(&url, "", Duration::from_secs(10), token_str).await {
                                Ok(response) => {
                                    if let Ok(parsed) = serde_json::from_str::<Value>(&response) {
                                        if parsed["code"] == "000000" {
                                            if let Some(data) = parsed["data"].as_object() {
                                                let gateway = data.get("gateway").and_then(|v| v.as_str()).unwrap_or("");
                                                let source_ip = data.get("source_ip").and_then(|v| v.as_str()).unwrap_or("");
                                                let target_ip = data.get("target_ip").and_then(|v| v.as_str()).unwrap_or("");
                                                let new_active_time = data.get("active_time").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                                                let mode = data.get("mode").and_then(|v| v.as_u64()).unwrap_or(1) as u32;

                                                current_interval = new_active_time;

                                                let mut info = PutIpJumpInfo {
                                                    source_ip: "".to_string(),
                                                    target_ip: "".to_string(),
                                                    gateway: "".to_string(),
                                                    agent_ip: "".to_string(),
                                                    status: 0,
                                                    reason: "".to_string(),
                                                };

                                                if !source_ip.is_empty() || !target_ip.is_empty() {
                                                    let config = IpJumpConfig {
                                                        source_ip: source_ip.to_string(),
                                                        target_ip: target_ip.to_string(),
                                                        gateway: gateway.to_string(),
                                                    };
                                                    match ip_jump_manager.do_ip_jump_async(config, &mut info, mode).await {
                                                        Ok(_) => {
                                                            log_info!("Auto IP jump success");
                                                            info.status = 1;
                                                        }
                                                        Err(e) => {
                                                            log_error!("Auto IP jump fail: {:?}", e);
                                                            info.status = 2;
                                                            info.reason = e.to_string();
                                                        }
                                                    }
                                                }

                                                let json_body = build_upload_ip_jump_json(
                                                    &info.source_ip,
                                                    &info.target_ip,
                                                    &info.gateway,
                                                    &info.agent_ip,
                                                    info.status as u8,
                                                    &info.reason,
                                                );
                                                let _ = client.post_data_async(
                                                    &upload_url,
                                                    &json_body,
                                                    Duration::from_secs(10),
                                                    token_str,
                                                ).await;

                                                if new_active_time == 0 {
                                                    log_info!("Auto IP Jump daemon stopped by server");
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    log_error!("Auto IP Jump request failed: {}", e);
                                }
                            }
                        }
                        AUTO_IP_JUMP_DAEMON_RUNNING.store(false, Ordering::SeqCst);
                    });
                }
            }
        }
        Err(err) => {
            log_error!("Error fetching task: {}", err);
            return Err(err);
        }
    }
    Ok(())
}
*/
async fn task_down_ipjump(&self, task_type: u64) -> Result<(), String> {
    self.report_task_completion(task_type).await?;

    let download_url = self.api_interface.get("getIpJump")
        .cloned()
        .unwrap_or_else(|| "v1/getIpJump".to_string());
    let url = format!("{}/{}", self.base_url, download_url);
    log_info!("url: {}", url);

    let token = self.get_token();
    let token_str = token.as_deref();

    // Include agent_ip in the request body so server can identify this agent
    let agent_ip = rules_jump_mgr::utils::get_local_ips_all().await.unwrap_or_default();
    let body = if agent_ip.is_empty() {
        String::new()
    } else {
        json!({"agent_ip": agent_ip}).to_string()
    };
    log_info!("getIpJump request body: {}", body);

    let response = self.net_client
        .post_data_async(&url, &body, Duration::from_secs(30), token_str)
        .await
        .map_err(|e| e.to_string())?;

    let parsed: Value = serde_json::from_str(&response)
        .map_err(|e| {
            log_error!("Failed to parse response: {}", e);
            "Failed to parse response.".to_string()
        })?;

    if parsed["code"] != "000000" {
        let msg = parsed["msg"].as_str().unwrap_or("Unknown error");
        log_error!("API error: {}", msg);
        return Err(format!("API error: {}", msg));
    }

    let data = parsed["data"].as_object().ok_or("Missing 'data' object in response")?;
    log_info!(" {:?}", data);

    let mode = data.get("mode").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
    let gateway = data.get("gateway").and_then(|v| v.as_str()).unwrap_or("");
    let source_ip = data.get("source_ip").and_then(|v| v.as_str()).unwrap_or("");
    let target_ip = data.get("target_ip").and_then(|v| v.as_str()).unwrap_or("");
    let active_time = data.get("active_time").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let aging_time = data.get("aging_time").and_then(|v| v.as_u64()).unwrap_or(2) as u32;  // 默认 2 分钟

    log_info!(
        "IP Jump Task: mode={},source_ip={}, target_ip={}, gateway={}, active_time={}, aging_time={}",
        mode,source_ip, target_ip, gateway, active_time, aging_time
    );

    if source_ip.is_empty() && target_ip.is_empty() {
        log_info!("Both source_ip and target_ip are empty; skipping IP jump.");
        self.report_task_completion(task_type).await?;
        return Ok(());
    }

    self.ip_jump_manager.send_instruction(
        source_ip.to_string(),
        target_ip.to_string(),
        gateway.to_string(),
        active_time,
        aging_time,
        mode,
    )?;

    Ok(())
}


async fn task_get_system_backups(&self, task_type: u64) -> Result<(), String> {
    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    let download_url = match self.api_interface.get("getBackups") {
        Some(url) => url,
        None => return Err("URL for download_white not found".to_string()),
    };

    let url = format!("{}/{}", self.base_url, download_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>
    match self.net_client.post_data_async(&url, "", Duration::from_secs(30), token_str).await {
        Ok(response) => {
            // 解析 JSON 响应
            let parsed: Value = match serde_json::from_str(&response) {
                Ok(parsed) => parsed,
                Err(e) => {
                    eprintln!("Failed to parse response: {}", e);
                    return Err("Failed to parse response.".to_string());
                }
            };
            if parsed["code"] == "000000" {
                if let Some(arr) = parsed["data"].as_array() {
                    for obj in arr {
                        if let Some(id) = obj["id"].as_str() {
                            match create_snapshot(id, "").await {  // 添加 .await
                                Ok(size) => {
                                    log_info!("✅ 快照创建成功: {}", id);
                                    // 成功上报
                                    if let Err(e) = self.upload_backup(id, 1, &size, "").await {
                                        eprintln!("上报成功状态失败: {}", e);
                                    }
                                }
                                Err(e) => {
                                    log_error!("❌ 快照创建失败: {} -> {}", id, e);
                                    // 失败上报
                                    if let Err(report_err) = self.upload_backup(id, 0, "", &e).await {
                                        eprintln!("上报失败状态失败: {}", report_err);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(err) => {
            eprintln!("Error fetching task: {}", err);
            // 返回错误的 Result 类型
            return Err(err);
        }
    }
    self.report_task_completion(task_type).await?;

    Ok(())
}
async fn task_system_rollback(&self, task_type: u64) -> Result<(), String> {
    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    let download_url = match self.api_interface.get("getRollbacks") {
        Some(url) => url,
        None => return Err("URL for getRollbacks not found".to_string()),
    };
    let url = format!("{}/{}", self.base_url, download_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str());

    let response = self
        .net_client
        .post_data_async(&url, "", Duration::from_secs(30), token_str)
        .await
        .map_err(|e| format!("Error fetching task: {}", e))?;

    let parsed: Value = serde_json::from_str(&response)
        .map_err(|e| {
            eprintln!("Failed to parse response: {}", e);
            "Failed to parse response.".to_string()
        })?;

    if parsed["code"] != "000000" {
        return Err("API returned non-success code.".to_string());
    }

    let mut has_success = false;

    if let Some(arr) = parsed["data"].as_array() {
        for obj in arr {
            if let Some(id) = obj["id"].as_str() {
                match restore_snapshot(id).await {
                    Ok(_) => {
                        log_info!("✅ 系统恢复成功: {}", id);
                        has_success = true;
                        if let Err(e) = self.upload_rollback(id, 1, "").await {
                            eprintln!("上报成功状态失败: {}", e);
                        }
                    }
                    Err(e) => {
                        log_error!("❌ 系统恢复失败: {} -> {}", id, e);
                        if let Err(report_err) = self.upload_rollback(id, 0, &e).await {
                            eprintln!("上报失败状态失败: {}", report_err);
                        }
                    }
                }
            }
        }
    }


    if has_success {
        self.reboot_system().await?;
    }

    Ok(())
}
async fn task_ntp_sync(&self, task_type: u64) -> Result<(), String> {

    self.report_task_completion(task_type).await
        .map_err(|e| e.to_string())?;

    let download_url = match self.api_interface.get("getNtpConf") {
        Some(url) => url,
        None => return Err("URL for ntp sync not found".to_string()),
    };

    let url = format!("{}/{}", self.base_url, download_url);
    let token = self.get_token();
    let token_str = token.as_ref().map(|s| s.as_str());

    let response = match self
        .net_client
        .post_data_async(&url, "", Duration::from_secs(30), token_str)
        .await
        {
            Ok(res) => res,
            Err(err) => {
                eprintln!("Error fetching task: {}", err);
                return Err(err);
            }
        };

    let parsed: Value = match serde_json::from_str(&response) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to parse response: {}", e);
            return Err("Failed to parse response.".to_string());
        }
    };

    if parsed["code"] != "000000" {
        let msg = parsed["msg"].as_str().unwrap_or("Unknown error");
        return Err(format!("API error: {}", msg));
    }

    let ntp_server = parsed["data"]["server_addr"]
        .as_str()
        .ok_or("Missing or invalid 'ntp server' field in response")?;

    log_info!("NTP server: {}", ntp_server);

    self.sync_time_via_ntp(ntp_server).await?;


    log_info!("NTP time sync completed successfully");
    Ok(())
}

async fn sync_time_via_ntp(&self, ntp_server: &str) -> Result<(), String> {
    let target = if ntp_server.contains(':') {
        ntp_server.to_string()
    } else {
        format!("{}:123", ntp_server)
    };

    let packet = ntp::request(&target)
        .map_err(|e| format!("NTP request failed: {}", e))?;

    let ntp_timestamp = packet.transmit_time;
    let ntp_sec = ntp_timestamp.sec as u64;
    const NTP_TO_UNIX_OFFSET: u64 = 2208988800;
    let unix_sec = ntp_sec.saturating_sub(NTP_TO_UNIX_OFFSET);

    let utc_datetime = chrono::DateTime::from_timestamp(unix_sec as i64, 0)
        .ok_or("Invalid timestamp")?;

    // NTP返回的是UTC时间，转换为本地时区
    let local_datetime = utc_datetime.with_timezone(&chrono::Local);
    let date_str = local_datetime.format("%Y-%m-%d %H:%M:%S").to_string();
    let utc_str = utc_datetime.format("%Y-%m-%d %H:%M:%S").to_string();
    log_info!("NTP time obtained (UTC: {}, Local: {})", utc_str, date_str);
    
    let output = Command::new("date")
        .arg("-s")
        .arg(&date_str)
        .output()
        .await
        .map_err(|e| format!("Failed to execute date: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to set system time: {}", stderr));
    }

    let _ = Command::new("hwclock")
        .arg("-w")
        .output()
        .await;

    Ok(())
}

async fn reboot_system(&self) -> Result<(), String> {
    log_info!("系统即将重启以应用快照恢复...");

    match Command::new("systemctl").arg("reboot").spawn() {
        Ok(_) => {
            log_info!("systemctl reboot 已触发");
        }
        Err(_) => {
            Command::new("reboot")
                .spawn()
                .map_err(|e| format!("reboot 命令启动失败: {}", e))?;
            log_info!("直接调用 reboot");
        }
    }

    tokio::time::sleep(Duration::from_millis(800)).await;

    Ok(())
}
async fn report_task_completion(&self, task_type: u64) -> Result<(), String> {
    let token_option = self.get_token();
    let token_str = token_option.as_ref().map(|s| s.as_str());
    let url = self.full_url("closetask")?; // 提取为 helper
    let json_data = build_closetask_json(task_type);

    log_info!("Reporting completion: {} => {}", url, json_data);

    match self.net_client
        .post_data_async(&url, &json_data, Duration::from_secs(30), token_str)
        .await{
            Ok(response) => {log_info!("服务器响应: {}", response)},
            Err(err) => {
                log_info!("发送指标失败: {}", err);
                eprintln!("发送指标失败: {}", err)
            }
        }
    Ok(())
}
fn full_url(&self, key: &str) -> Result<String, String> {
    let suffix = self.api_interface.get(key).ok_or_else(|| format!("URL key '{}' not found", key))?;
    Ok(format!("{}/{}", self.base_url, suffix))
}
async fn upload_backup(&self, id: &str, state: i32, size: &str, fail_reason: &str) -> Result<(), String> {
    let token_option = self.get_token();
    let token_str = token_option.as_ref().map(|s| s.as_str());
    let url = self.full_url("uploadBackup")?;
    let json_data = build_upload_backup_json(id, state, size, fail_reason);
    log_info!("Reporting upload_backup: {} => {}", url, json_data);

    match self.net_client
        .post_data_async(&url, &json_data, Duration::from_secs(30), token_str)
        .await{
            Ok(response) => {log_info!("服务器响应: {}", response)},
            Err(err) => {
                log_info!("发送指标失败: {}", err);
                eprintln!("发送指标失败: {}", err)
            }
        }
    Ok(())
}
async fn upload_rollback(&self, id: &str, state: i32, fail_reason: &str) -> Result<(), String> {
    let token_option = self.get_token();
    let token_str = token_option.as_ref().map(|s| s.as_str());
    let url = self.full_url("uploadRollback")?;
    let json_data = build_upload_rollback_json(id, state, fail_reason);
    log_info!("Reporting upload_rollback: {} => {}", url, json_data);

    match self.net_client
        .post_data_async(&url, &json_data, Duration::from_secs(30), token_str)
        .await{
            Ok(response) => {log_info!("服务器响应: {}", response)},
            Err(err) => {
                log_info!("发送指标失败: {}", err);
                eprintln!("发送指标失败: {}", err)
            },
        }
    Ok(())
}

async fn upload_passwd_result(&self, user: &str, pw: &str, state: u8, fail_reason: &str) -> Result<(), String> {
    let token_option = self.get_token();
    let token_str = token_option.as_ref().map(|s| s.as_str());
    let url = self.full_url("putPwJump")?;
    let json_data = build_upload_passwd_json(user, pw, state,fail_reason);
    log_info!("Reporting putPwJump: {} => {}", url, json_data);

    match self.net_client
        .post_data_async(&url, &json_data, Duration::from_secs(30), token_str)
        .await{
            Ok(response) => {log_info!("服务器响应: {}", response)},
            Err(err) => {
                log_info!("发送指标失败: {}", err);
                eprintln!("发送指标失败: {}", err)
            },
        }
    Ok(())
}

async fn upload_ip_jump_result(&self, source_ip: &str, target_ip: &str, gateway: &str, agent_ip: &str, state: u8, fail_reason: &str) -> Result<(), String> {
    let token_option = self.get_token();
    let token_str = token_option.as_ref().map(|s| s.as_str());
    let url = self.full_url("putIpJump")?;
    let json_data = build_upload_ip_jump_json(source_ip, target_ip, gateway, agent_ip, state , fail_reason);
    log_info!("Reporting putIpJump: {} => {}", url, json_data);

    match self.net_client
        .post_data_async(&url, &json_data, Duration::from_secs(30), token_str)
        .await{
            Ok(response) => {log_info!("服务器响应: {}", response)},
            Err(err) => {
                log_info!("发送指标失败: {}", err);
                eprintln!("发送指标失败: {}", err)
            },
        }
    Ok(())
}

    /// 本地升级触发（gRPC TriggerLocalUpdate 入口）。
    /// `zip_path`: Some("/path/to/xxx.zip") 指定具体文件，None 则自动扫描 /opt/osec/upgrade/。
    /// 跳过服务器下载步骤，直接将本地 zip 当作已下载的升级包处理。
    /// 本地升级（测试用）：从 upgrade/ 目录取 zip → 解压 → 通知 agent_manager 执行脚本。
    /// 不杀进程、不替换二进制、不走 systemctl，纯脚本升级路径。
    pub async fn task_update_from_local(&self, zip_path: Option<String>) -> Result<(), String> {
        let temp_dir = "/tmp/osec_update";
        let _ = fs::remove_dir_all(temp_dir);
        fs::create_dir_all(temp_dir).map_err(|e| e.to_string())?;

        // ── 1. 获取 zip 包（指定路径 或 自动扫描 upgrade/）──
        let (zip_bytes, alias) = match zip_path {
            Some(ref path) => {
                log_info!("[本地升级] 使用指定升级包: {}", path);
                if !Path::new(path).exists() {
                    return Err(format!("指定的升级包不存在: {}", path));
                }
                let bytes = fs::read(path)
                    .map_err(|e| format!("读取升级包失败: {}", e))?;
                let name = Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("update.zip")
                    .to_string();
                (bytes, name)
            }
            None => {
                const LOCAL_UPGRADE_DIR: &str = "/opt/osec/upgrade";
                match find_local_upgrade_zip(LOCAL_UPGRADE_DIR) {
                    Some((found_path, zip_name)) => {
                        log_info!("[本地升级] 在 {} 中发现升级包: {}", LOCAL_UPGRADE_DIR, found_path);
                        let bytes = fs::read(&found_path)
                            .map_err(|e| format!("读取升级包失败: {}", e))?;
                        let _ = fs::remove_file(&found_path);
                        log_info!("[本地升级] 已清理: {}", found_path);
                        (bytes, zip_name)
                    }
                    None => {
                        return Err(format!(
                            "{} 目录中未找到 .zip 升级包",
                            LOCAL_UPGRADE_DIR
                        ));
                    }
                }
            }
        };

        // ── 2. 解压到 /tmp/osec_update ──
        let zip_path_temp = format!("{}/{}", temp_dir, alias);
        fs::write(&zip_path_temp, &zip_bytes).map_err(|e| e.to_string())?;

        let reader = Cursor::new(&zip_bytes);
        let mut archive = ZipArchive::new(reader).map_err(|e| e.to_string())?;
        archive.extract(temp_dir).map_err(|e| e.to_string())?;
        log_info!("[本地升级] ✅ 升级包已解压到: {}", temp_dir);

        // ── 3. 通知 agent_manager 执行脚本 ──
        if let Err(e) = send_command_to_agent("update").await {
            log_info!("[本地升级] 发送 update 命令给 agent_manager 失败: {}", e);
            return Err(e);
        }
        log_info!("[本地升级] ✅ 已通知 agent_manager 执行升级脚本（agent_manager 会自行 find_upgrade_scripts + run_scripts_and_cleanup）");

        log_info!("[本地升级] 🚀 task_update_from_local 完成");
        Ok(())
    }
}

pub fn build_closetask_json(tasklist: u64) -> String {
    let json_data = json!({
        "tasklist": tasklist
    });
    json_data.to_string()
}


// 定义返回类型为 `impl Future`，并显式添加 `Send` trait bound
pub trait TaskService {
    fn task_fetcher(&mut self, host_is_offline_tx: mpsc::Sender<bool>, token_rx: mpsc::Receiver<String>, nl_sock: Option<NlSockInfo>) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>; 
}
impl TaskService for BootManager {
    fn task_fetcher(
        &mut self,
        host_is_offline_tx: mpsc::Sender<bool>,
        token_rx: mpsc::Receiver<String>,
        nl_sock: Option<NlSockInfo>,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {
            let mut token_rx = token_rx;
            loop {

                let base_url = self.get_base_url();
                let mut net_client = match NetClient::new(Some(base_url), true) {
                    Ok(client) => client,
                    Err(err) => {
                        eprintln!("创建 NetClient 失败: {}", err);
                        return Err("创建 NetClient 失败".to_string());
                    }
                };
                println!("等待接收 token...");
                // 阻塞，等待接收到新的 token
                if let Some(token) = token_rx.recv().await {
                    let token_option = Some(token); // 接收到的 token

                    println!("收到 token，开始任务处理...");
                    let nl_sock = nl_sock.clone(); 
                    // 调用 TaskFetcher::run，处理任务
                    match TaskFetcher::run(&mut net_client, token_option, self.pattern_mgr(),nl_sock).await {
                        Ok(()) => {
                            println!("任务处理成功，继续监听 token...");
                        }
                        Err(err) => {
                            eprintln!("任务处理失败或服务器离线: {}", err);
                            notify_network_failure();

                            // 发送离线信号，通知重新获取 token
                            if let Err(e) = host_is_offline_tx.send(true).await {
                                eprintln!("发送离线信号失败: {}", e);
                            }

                            // 跳出当前循环，重新等待 token
                            continue;
                        }
                    }
                } else {
                    eprintln!("Token 通道已关闭，退出任务...");
                    break;
                }
            }

            Ok("后台任务已启动.".to_string())
        })
    }
}

pub fn build_upload_backup_json(id: &str, state: i32, size: &str, fail_reason: &str) -> String {
    let json_data = json!({
        "id": id,
        "state": state,
        "storage_dir": "",
        "file_name": "",
        "file_size": size,
        "fail_reason": fail_reason,
        "param": ""
    });
    json_data.to_string()
}
pub fn build_upload_rollback_json(id: &str, state: i32, fail_reason: &str) -> String {
    let json_data = json!({
        "id": id,
        "state": state,
        "fail_reason": fail_reason,
    });
    json_data.to_string()
}

pub fn build_upload_passwd_json(user: &str, pw: &str, state: u8, fail_reason: &str) -> String {
    let json_data = json!({
        "status": state,
        "user": user,
        "pw": pw,
        "reason": fail_reason,
    });
    json_data.to_string()
}

fn build_upload_ip_jump_json(source_ip: &str, target_ip: &str, gateway: &str, agent_ip: &str, state: u8, fail_reason: &str) -> String {
    let json_data = json!({
        "source_ip": source_ip,
        "target_ip": target_ip,
        "gateway": gateway,
        "agent_ip": agent_ip,
        "status": state,
        "reason": fail_reason,
    });
    json_data.to_string()
}

async fn send_command_to_agent(cmd: &str) -> Result<(), String> {
    let socket_path = "/tmp/osec_agent.sock";
    let mut stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| format!("连接 agent_manager 失败: {}", e))?;

    stream
        .write_all(format!("{}\n", cmd).as_bytes())
        .await
        .map_err(|e| format!("发送命令失败: {}", e))?;

    Ok(())
}

async fn write_proc_self() -> Result<(), String> {
    let now = Utc::now();

    let year  = now.year() as u64;
    let month = now.month() as u64;
    let day   = now.day() as u64;

    let concatenated = format!("{}{}{}", year, month, day);
    let num = concatenated.parse::<u64>()
        .map_err(|e| format!("日期拼接解析失败: {}", e))?;

    let final_value = num + 1;
    let formatted = final_value.to_string();

    let proc_path = "/proc/osec/self";

    log_info!("[agent_manager] Writing {}", proc_path);

    if !Path::new(proc_path).exists() {
        log_info!("[agent_manager] {} 不存在，跳过写入", proc_path);
        return Ok(());
    }

    let content = format!("veda {} 0\n", formatted);

    // 直接用 fs::write，更简洁
    fs::write(proc_path, content.as_bytes())
        .map_err(|e| format!("写入失败: {}", e))?;

    log_info!("[agent_manager] 已写入: {}", content.trim());

    // 验证读取
    let read_back = fs::read_to_string(proc_path)
        .map_err(|e| format!("读取失败: {}", e))?;

    log_info!("[task_fetcher] 读取结果: {}", read_back.trim());

    Ok(())
}

const MAX_WAIT_SECONDS: u64 = 15;
const POLL_INTERVAL_MILLIS: u64 = 300;

async fn is_process_running(name: &str) -> bool {
    Command::new("pgrep")
        .arg("-x")  // 精确匹配进程名
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

fn detect_runtime_arch() -> String {
    match std::process::Command::new("uname").arg("-m").output() {
        Ok(output) => {
            let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();
            match arch.as_str() {
                "x86_64" | "amd64" => "x86_64".to_string(),
                "aarch64" | "arm64"  => "aarch64".to_string(),
                "loongarch64" => "loongarch64".to_string(),
                "mips64" | "mips64el" => "mips64".to_string(),
                other => {
                    log::warn!("[upgrade] uname -m 返回未知架构: {}，回退到编译目标 {}", other, std::env::consts::ARCH);
                    std::env::consts::ARCH.to_string()
                }
            }
        }
        Err(e) => {
            log::error!("[upgrade] uname -m 执行失败: {}，使用编译目标架构", e);
            std::env::consts::ARCH.to_string()
        }
    }
}

pub async fn stop_agent() -> Result<(), String> {
    log_info!("[upgrade] 开始停止 agent_manager / MagicArmorAgent / osec_cli 服务");

    async fn service_exists(name: &str) -> bool {
        Command::new("systemctl")
            .args(["status", name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    async fn process_running(name: &str) -> bool {
        is_process_running(name).await
    }

    let has_systemctl = Command::new("which")
        .arg("systemctl")
        .stdout(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);

    let mut stopped_any = false;

    if has_systemctl && service_exists("agent_manager").await {
        log_info!("[upgrade] 使用 systemctl stop agent_manager");
        let _ = Command::new("systemctl")
            .args(["stop", "agent_manager"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        stopped_any = true;
    } else if process_running("agent_manager").await {
        log_info!("[upgrade] 强制终止 agent_manager 进程");
        let _ = Command::new("pkill").args(["-9", "agent_manager"]).status().await;
        stopped_any = true;
    }

    if has_systemctl && service_exists("osec_cli").await {
        log_info!("[upgrade] 使用 systemctl stop osec_cli");
        let _ = Command::new("systemctl")
            .args(["stop", "osec_cli"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        stopped_any = true;
    } else if process_running("osec_cli").await {
        log_info!("[upgrade] 强制终止 osec_cli 进程");
        let _ = Command::new("pkill").args(["-9", "osec_cli"]).status().await;
        stopped_any = true;
    }

    log_info!("[upgrade] 强制杀死 MagicArmorAgent 进程");
    for _ in 0..3 {
        let _ = Command::new("pkill").args(["-9", "MagicArmorAgent"]).status().await;
        let _ = Command::new("killall").args(["-9", "MagicArmorAgent"]).status().await;
        sleep(Duration::from_millis(200)).await;
    }
    stopped_any = true;

    log_info!(
        "[upgrade] 等待相关进程完全退出（最多 {} 秒）...",
        MAX_WAIT_SECONDS
    );

    let wait_ok = timeout(Duration::from_secs(MAX_WAIT_SECONDS), async {
        while process_running("MagicArmorAgent").await
            || process_running("agent_manager").await
            || process_running("osec_cli").await
        {
            sleep(Duration::from_millis(POLL_INTERVAL_MILLIS)).await;
        }
    })
    .await
        .is_ok();

    if wait_ok {
        log_info!("[upgrade] 所有相关进程已完全停止");
    } else {
        log_info!("[upgrade] ⚠️ 警告：部分进程未在 {} 秒内退出，继续操作（有风险）", MAX_WAIT_SECONDS);
        let _ = Command::new("pkill").args(["-9", "MagicArmorAgent"]).status().await;
        let _ = Command::new("pkill").args(["-9", "agent_manager"]).status().await;
        let _ = Command::new("pkill").args(["-9", "osec_cli"]).status().await;
        sleep(Duration::from_secs(1)).await;
    }

    if !stopped_any {
        log_info!("[upgrade] 无需停止：没有运行中的 agent_manager / osec_cli / MagicArmorAgent");
    }

    Ok(())
}

pub async fn start_agent() -> Result<(), String> {
    log_info!("[upgrade] 启动 agent_manager 服务");

    // ---------- 检查 systemctl 是否存在 ----------
    let has_systemctl = Command::new("which")
        .arg("systemctl")
        .stdout(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);

    if has_systemctl {
        // ---------- 检查 agent_manager.service 是否已安装 ----------
        let service_installed = Command::new("systemctl")
            .args(["status", "agent_manager.service"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);

        // ---------- service 未安装 → 自动安装并 enable ----------
        if !service_installed {
            let src = Path::new("/opt/osec/agent_manager.service");
            let dst = Path::new("/etc/systemd/system/agent_manager.service");

            if src.exists() {
                log_info!("[upgrade] 未找到 agent_manager.service，正在安装...");

                if let Err(e) = tokio::fs::copy(src, dst).await {
                    return Err(format!("复制 service 文件失败: {}", e));
                }

                // daemon-reload
                let _ = Command::new("systemctl")
                    .args(["daemon-reload"])
                    .status()
                    .await;

                // ★ 必须 enable，让服务随系统启动 ★
                let _ = Command::new("systemctl")
                    .args(["enable", "agent_manager"])
                    .status()
                    .await;

                log_info!("[upgrade] agent_manager.service 安装并 enable 完成");
            } else {
                log_info!(
                    "[upgrade] ⚠️ /opt/osec/agent_manager.service 不存在，无法自动安装 service 文件"
                );
            }
        }

        // ---------- 启动 agent_manager ----------
        log_info!("[upgrade] 使用 systemctl start agent_manager");
        let status = Command::new("systemctl")
            .args(["start", "agent_manager"])
            .status()
            .await
            .map_err(|e| format!("执行 systemctl start 失败: {}", e))?;

        if status.success() {
            log_info!("[upgrade] agent_manager 服务启动成功");
        } else {
            log_info!("[upgrade] ⚠️ systemctl start 返回非零，但新进程可能已被拉起");
        }
    } 
    else {
        // ---------- service 命令 ----------
        let has_service = Command::new("which")
            .arg("service")
            .stdout(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);

        if has_service {
            log_info!("[upgrade] 使用 service 启动 agent_manager");
            let _ = Command::new("service")
                .args(["agent_manager", "start"])
                .status()
                .await;
        } else {
            // ---------- fallback：直接后台启动 MagicArmorAgent ----------
            log_info!("[upgrade] 无服务管理器，直接后台启动 MagicArmorAgent");
            let _ = Command::new("/opt/osec/MagicArmorAgent")
                .arg("--daemon")
                .spawn();
        }
    }

    // ---------- 等待 MagicArmorAgent 出现 ----------
    tokio::time::sleep(Duration::from_millis(800)).await;
    if is_process_running("MagicArmorAgent").await {
        log_info!("[upgrade] MagicArmorAgent 已成功运行");
    } else {
        log_info!("[upgrade] ⚠️ MagicArmorAgent 启动后未检测到进程（可能稍后被拉起）");
    }

    Ok(())
}

pub async fn replace_binary_with_arch_check(temp_dir: &str) -> Result<(), String> {
    let target_dir = "/opt/osec";
    let binary_name = "MagicArmorAgent";

    log_info!("[upgrade] 开始替换二进制，临时目录: {}", temp_dir);

    let current_arch = detect_runtime_arch();
    log_info!("[upgrade] 当前系统架构: {}", current_arch);

    let expected_filename = format!("{}.{}", binary_name, current_arch);
    let src_path = Path::new(temp_dir).join(&expected_filename);

    log_info!("[upgrade] 期望的新二进制文件: {}", src_path.display());

    if !src_path.exists() {
        let mut actual_files = Vec::new();
        if let Ok(entries) = fs::read_dir(temp_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_string_lossy().into_owned().strip_prefix("MagicArmorAgent.") {
                    actual_files.push(format!("MagicArmorAgent.{}", name));
                } else if let Some(name) = entry.file_name().to_str() {
                    actual_files.push(name.to_string());
                }
            }
        }

        log_info!("[upgrade] ❌ 更新包中未找到匹配架构的文件！");
        log_info!("[upgrade]    期望文件 : {}", expected_filename);
        log_info!("[upgrade]    实际文件 : {:?}", actual_files);
        log_info!("[upgrade]    临时目录 : {}", temp_dir);

        return Err(format!(
                "更新包缺少当前架构({})的二进制！\n期望: {}\n实际包含: {:?}",
                current_arch, expected_filename, actual_files
        ));
    }

    log_info!("✅ 找到匹配的新二进制: {}", src_path.display());

    log_info!("[upgrade] 确保目标目录存在: {}", target_dir);
    fs::create_dir_all(target_dir)
        .map_err(|e| format!("创建目标目录 {} 失败: {}", target_dir, e))?;

    // 备份旧版本
    let target_path = format!("{}/{}", target_dir, binary_name);
    let backup_path = format!("{}/{}.bak", target_dir, binary_name);

    if Path::new(&target_path).exists() {
        log_info!("[upgrade] 发现旧版本，备份到: {}", backup_path);
        let _ = fs::remove_file(&backup_path); // 删除上一次的备份
        fs::rename(&target_path, &backup_path)
            .map_err(|e| format!("备份旧二进制失败: {}", e))?;
        log_info!("✅ 旧版本备份成功 → {}", backup_path);
    } else {
        log_info!("[upgrade] 未发现旧版本，跳过备份");
    }

    //  复制新版本
    log_info!("[upgrade] 正在复制新二进制 → {}", target_path);
    let copied_bytes = fs::copy(&src_path, &target_path)
        .map_err(|e| format!("复制二进制失败: {}", e))?;
    log_info!("✅ 复制完成，大小: {} bytes", copied_bytes);

    // 设置可执行权限
    log_info!("[upgrade] 设置可执行权限 755");
    fs::set_permissions(&target_path, Permissions::from_mode(0o755))
        .map_err(|e| format!("设置执行权限失败: {}", e))?;
    log_info!("✅ 权限设置完成");

    let _ = fs::remove_file(&src_path);
    log_info!("🧹 已删除临时文件: {}", src_path.display());

    log_info!("🎉 新版本 MagicArmorAgent 已成功部署！");
    log_info!("    架构: {}", current_arch);
    log_info!("    路径: {}", target_path);

    Ok(())
}

/// 扫描本地目录，返回第一个找到的 .zip 文件 (完整路径, 文件名)。
/// 供 task_update_from_local() 自动扫描 /opt/osec/upgrade/ 时使用。
fn find_local_upgrade_zip(dir: &str) -> Option<(String, String)> {
    let d = Path::new(dir);
    if !d.exists() || !d.is_dir() {
        log_info!("[本地升级] 目录不存在: {}", dir);
        return None;
    }
    let entries = fs::read_dir(d).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.to_lowercase().ends_with(".zip") {
                log_info!("[本地升级] 在 {} 中找到升级包: {}", dir, name);
                return Some((path.to_string_lossy().to_string(), name.to_string()));
            }
        }
    }
    log_info!("[本地升级] {} 目录中未找到 .zip 文件", dir);
    None
}



