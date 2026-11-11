//! 策略单一来源（方案 B）：
//!
//! 服务器与 gRPC 都只把解析后的策略写入 SQLite，运行时的内存/内核策略统一由
//! 本模块从 DB 读取后下发。每个策略域通过 `policy_meta.version` 做变更检测，
//! 未变化时不会重复 apply。

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

use grpc_gateway::notify::{
    notify_policy_change, DIR_POLICY_CACHE, EXTORT_POLICY_CACHE, TRUST_DIR_CACHE,
    VIRTUAL_PORT_CACHE,
};
use grpc_gateway::policy_watch::PolicyChangeType;
use logging::{log_error, log_info};
use pattern::pattern_rules_mgr::{POLICY_EXIPOR_PROTECT, POLICY_PROTECT_DIR};
use pattern::process_pattern_rules_mgr::PROCESS_PATTERN_RULES_MGR;
use pattern::GlobalTrustDir;

use crate::task_fetcher::GLOBAL_PATTERN_MGR;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Domain {
    Process,
    DirPolicy,
    ExtortPolicy,
    TrustDir,
    Peripheral,
    VirtualPort,
    IpBlock,
    IpBlack,
    Outreach,
}

const ALL_DOMAINS: [Domain; 9] = [
    Domain::Process,
    Domain::DirPolicy,
    Domain::ExtortPolicy,
    Domain::TrustDir,
    Domain::Peripheral,
    Domain::VirtualPort,
    Domain::IpBlock,
    Domain::IpBlack,
    Domain::Outreach,
];

fn snapshot_key(domain: Domain) -> &'static str {
    match domain {
        Domain::VirtualPort => "virtual_port",
        Domain::IpBlock => "ip_block",
        Domain::IpBlack => "ip_black",
        Domain::Outreach => "outreach",
        _ => "",
    }
}

struct State {
    backend_ready: bool,
    inflight: HashSet<Domain>,
    dirty: HashSet<Domain>,
    applied: HashMap<Domain, u64>,
}

impl State {
    fn new() -> Self {
        Self {
            backend_ready: false,
            inflight: HashSet::new(),
            dirty: HashSet::new(),
            applied: HashMap::new(),
        }
    }
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();

fn state() -> &'static Mutex<State> {
    STATE.get_or_init(|| Mutex::new(State::new()))
}

/// 服务器进程黑白名单是分两次任务下发的，暂存到两侧都到齐后一次写库并 apply。
static PROCESS_PENDING: OnceLock<Mutex<(Option<Vec<String>>, Option<Vec<String>>)>> =
    OnceLock::new();

fn process_pending() -> &'static Mutex<(Option<Vec<String>>, Option<Vec<String>>)> {
    PROCESS_PENDING.get_or_init(|| Mutex::new((None, None)))
}

fn db_enabled() -> bool {
    local_store::sqlite_db_enabled()
}

fn process_db_enabled() -> bool {
    db_enabled()
        && config::net_info::NETINFO_CONFIG
            .lock()
            .map(|c| c.db_policy.process_policy)
            .unwrap_or(false)
}

fn domain_version(domain: Domain) -> Result<u64, String> {
    let r = match domain {
        Domain::Process => local_store::process_policy::version(),
        Domain::DirPolicy => local_store::dir_policy::version(),
        Domain::ExtortPolicy => local_store::extort_policy::version(),
        Domain::TrustDir => local_store::trust_dir::version(),
        Domain::Peripheral => local_store::peripheral_policy::version(),
        Domain::VirtualPort | Domain::IpBlock | Domain::IpBlack | Domain::Outreach => {
            local_store::policy_snapshot::version(snapshot_key(domain))
        }
    };
    r.map_err(|e| e.to_string())
}

// ── 应用（内存 + 内核） ───────────────────────────────

fn apply_dir_rules(rules: Vec<POLICY_PROTECT_DIR>) -> Result<(), String> {
    let proto_rules: Vec<grpc_gateway::dir_policy::DirectionScanRule> = rules
        .iter()
        .map(|r| grpc_gateway::dir_policy::DirectionScanRule {
            dir: r.dir.clone(),
            pid: 0,
            typ: r.typ as u32,
        })
        .collect();

    let mgr = GLOBAL_PATTERN_MGR
        .get()
        .ok_or_else(|| "GLOBAL_PATTERN_MGR 未初始化".to_string())?
        .clone();
    mgr.lock()
        .map_err(|e| e.to_string())?
        .set_protect_dir(rules);

    *DIR_POLICY_CACHE.lock().unwrap() = proto_rules;
    notify_policy_change(PolicyChangeType::DirPolicyChanged);
    Ok(())
}

fn apply_extort_rules(rules: Vec<POLICY_EXIPOR_PROTECT>) -> Result<(), String> {
    let proto_rules: Vec<grpc_gateway::extort_policy::ExtortProtectRule> = rules
        .iter()
        .map(|r| grpc_gateway::extort_policy::ExtortProtectRule {
            file_type: r.file_type.clone(),
            typ: r.typ as u32,
            map_comm: r.map_comm.clone(),
        })
        .collect();

    let mgr = GLOBAL_PATTERN_MGR
        .get()
        .ok_or_else(|| "GLOBAL_PATTERN_MGR 未初始化".to_string())?
        .clone();
    mgr.lock()
        .map_err(|e| e.to_string())?
        .set_exiport_dir(rules);

    *EXTORT_POLICY_CACHE.lock().unwrap() = proto_rules;
    notify_policy_change(PolicyChangeType::ExtortPolicyChanged);
    Ok(())
}

fn apply_trust_dirs(dirs: Vec<GlobalTrustDir>) -> Result<(), String> {
    let proto_dirs: Vec<grpc_gateway::trust_dir::GlobalTrustDir> = dirs
        .iter()
        .map(|d| grpc_gateway::trust_dir::GlobalTrustDir {
            dir: d.dir.clone(),
            r#type: d.typ as u32,
            is_extend: d.is_extend as u32,
        })
        .collect();

    // 信任目录同时影响进程规则与文件 DPI，两处都要更新（与在线下发路径一致）。
    PROCESS_PATTERN_RULES_MGR
        .lock()
        .set_global_trust_dir(dirs.clone());
    let mgr = GLOBAL_PATTERN_MGR
        .get()
        .ok_or_else(|| "GLOBAL_PATTERN_MGR 未初始化".to_string())?
        .clone();
    mgr.lock()
        .map_err(|e| e.to_string())?
        .set_global_trust_dir(dirs);

    *TRUST_DIR_CACHE.lock().unwrap() = proto_dirs;
    notify_policy_change(PolicyChangeType::TrustDirChanged);
    Ok(())
}

fn apply_process() -> Result<(), String> {
    let mut mgr = process_mgr::POLICY_MANAGER.lock().unwrap();
    mgr.load_policy_from_db_merged();
    mgr.apply_loaded_policy_to_kernel();
    drop(mgr);
    notify_policy_change(PolicyChangeType::ProcessPolicyChanged);
    Ok(())
}

fn apply_peripheral() -> Result<(), String> {
    if !db_enabled() {
        return Ok(());
    }
    let mut rows = local_store::peripheral_policy::load_all().map_err(|e| e.to_string())?;
    // 兼容旧版本：基线表为空但旧本地表有数据时才回退本地表。
    if rows.is_empty() && local_store::peripheral_policy::local_present().unwrap_or(false) {
        rows = local_store::peripheral_policy::load_all_local().map_err(|e| e.to_string())?;
    }

    let mut white = Vec::new();
    let mut black = Vec::new();
    for row in rows {
        let info = udisk::device::UsbInfo::new(
            row.peripheral_eid,
            row.peripheral_name,
            row.intro,
            row.type_,
            row.is_white,
        );
        if row.is_white {
            white.push(info);
        } else {
            black.push(info);
        }
    }
    *udisk::list::SHARED_USB_LIST.lock().unwrap() =
        udisk::list::BlackWhiteList::from_vecs(black, white);
    notify_policy_change(PolicyChangeType::PeripheralPolicyChanged);
    Ok(())
}

fn apply_virtual_port_rules(rules: Vec<crate::virtual_port_rule::VirtualPortRule>) -> Result<(), String> {
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
    *VIRTUAL_PORT_CACHE.lock().unwrap() = proto_rules;

    let valid_rules: Vec<_> = rules
        .into_iter()
        .filter(|r| !r.source_ip.is_empty())
        .collect();
    if valid_rules.is_empty() {
        notify_policy_change(PolicyChangeType::VirtualPortChanged);
        return Ok(());
    }

    let total = valid_rules.len();
    let mut batch = String::new();
    for (index, rule) in valid_rules.iter().enumerate() {
        let protocol_num = match rule.protocol.to_lowercase().as_str() {
            "tcp" => 1,
            "udp" => 2,
            _ => 0,
        };
        let is_ipv4 = if rule.dest_ip.contains(':') { 0u8 } else { 1u8 };
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
            if rule.dest_ip.trim().is_empty() { "\"\"" } else { &rule.dest_ip },
            rule.dest_port_type,
            if rule.dest_port_type == 0 { rule.dest_port.parse::<u16>().unwrap_or(0) } else { 0 },
            addr_type,
        );
        batch.push_str(&rule_str);
    }
    common::backend::with_backend(|b| b.write_net_rules(&batch))?;
    notify_policy_change(PolicyChangeType::VirtualPortChanged);
    Ok(())
}

fn apply_outreach_rules(rules: Vec<crate::net_reach_rule::OutreachDetectRule>) -> Result<(), String> {
    crate::net_reach_rule::update_global_outreach_rules(rules);
    notify_policy_change(PolicyChangeType::OutreachRulesChanged);
    Ok(())
}

fn load_snapshot<T: serde::de::DeserializeOwned>(domain: Domain) -> Vec<T> {
    let key = snapshot_key(domain);
    match local_store::policy_snapshot::load(key) {
        Ok(Some(json)) => match serde_json::from_str::<Vec<T>>(&json) {
            Ok(v) => v,
            Err(e) => {
                log_error!("[policy_store] 反序列化 {} 失败: {}", key, e);
                Vec::new()
            }
        },
        Ok(None) => Vec::new(),
        Err(e) => {
            log_error!("[policy_store] 读取 {} 失败: {}", key, e);
            Vec::new()
        }
    }
}

fn apply_ip_domain(domain: Domain, source: &str) -> Result<(), String> {
    let rules = load_snapshot::<netblock::ip_policy::IpPolicy>(domain);
    netblock::ip_policy::apply_policies_sync(rules, source)
}

fn apply_domain(domain: Domain) -> Result<(), String> {
    match domain {
        Domain::Process => apply_process(),
        Domain::DirPolicy => {
            let rules = crate::policy_persistence::load_dir_policy_merged().unwrap_or_default();
            apply_dir_rules(rules)
        }
        Domain::ExtortPolicy => {
            let rules = crate::policy_persistence::load_extort_policy_merged().unwrap_or_default();
            apply_extort_rules(rules)
        }
        Domain::TrustDir => {
            let mut dirs = crate::policy_persistence::load_trust_dir_merged().unwrap_or_default();
            // 内置默认信任目录始终保留（去重），避免服务器下发空列表时丢失 /opt/osec/log。
            let defaults = GLOBAL_PATTERN_MGR
                .get()
                .and_then(|m| m.lock().ok().map(|g| g.default_trust_dirs()))
                .unwrap_or_default();
            for d in defaults {
                if !dirs.iter().any(|x| x.dir == d.dir) {
                    dirs.push(d);
                }
            }
            apply_trust_dirs(dirs)
        }
        Domain::Peripheral => apply_peripheral(),
        Domain::VirtualPort if db_enabled() => apply_virtual_port_rules(load_snapshot(domain)),
        Domain::IpBlock if db_enabled() => apply_ip_domain(domain, "netblocks"),
        Domain::IpBlack if db_enabled() => apply_ip_domain(domain, "policies"),
        Domain::Outreach if db_enabled() => apply_outreach_rules(load_snapshot(domain)),
        Domain::VirtualPort | Domain::IpBlock | Domain::IpBlack | Domain::Outreach => Ok(()),
    }
}

// ── 变更检测与加载 ─────────────────────────────────────

/// 从 DB 重新加载指定域；版本未变化时直接跳过。
pub fn reload_domain(domain: Domain) -> Result<(), String> {
    {
        let mut st = state().lock().unwrap();
        if !st.backend_ready {
            st.dirty.insert(domain);
            return Ok(());
        }
        if st.inflight.contains(&domain) {
            st.dirty.insert(domain);
            return Ok(());
        }
        st.inflight.insert(domain);
    }

    let mut result = Ok(());
    // 最多追赶 4 次，吸收 apply 期间发生的并发写入。
    for _ in 0..4 {
        let version = match domain_version(domain) {
            Ok(v) => v,
            Err(e) => {
                result = Err(e);
                break;
            }
        };
        let already = state().lock().unwrap().applied.get(&domain).copied();
        if already == Some(version) {
            break;
        }
        match apply_domain(domain) {
            Ok(()) => {
                let mut st = state().lock().unwrap();
                st.applied.insert(domain, version);
                st.dirty.remove(&domain);
            }
            Err(e) => {
                result = Err(e);
                break;
            }
        }
        match domain_version(domain) {
            Ok(latest) if latest == version => break,
            Ok(_) => continue,
            Err(e) => {
                result = Err(e);
                break;
            }
        }
    }

    let mut st = state().lock().unwrap();
    st.inflight.remove(&domain);
    if result.is_err() {
        st.dirty.insert(domain);
    } else if let Ok(latest) = domain_version(domain) {
        // 极端情况下 apply 期间持续有新写入：保留 dirty，等下一次事件再追赶。
        if st.applied.get(&domain).copied() != Some(latest) {
            st.dirty.insert(domain);
        }
    }
    result
}

/// 启动/后端就绪后调用：加载所有域一次（未变化的域会被版本去重跳过）。
pub fn load_all_domains() {
    for domain in ALL_DOMAINS {
        if let Err(e) = reload_domain(domain) {
            log_error!("[policy_store] 加载 {:?} 失败: {}", domain, e);
        }
    }
}

/// 旧版本把 gRPC 策略写在 `*_local` 表、服务器策略写在基线表。
/// 新版服务器与 gRPC 同等对待，统一写基线表；这里把仅存在于本地表的数据迁移到基线表。
fn migrate_legacy_local_to_baseline() {
    if !db_enabled() {
        return;
    }

    if let Ok(None) = local_store::dir_policy::load_all() {
        if let Ok(Some(json)) = local_store::dir_policy::load_all_local() {
            let _ = local_store::dir_policy::save_all(&json);
            let _ = local_store::dir_policy::clear_local();
        }
    }
    if let Ok(None) = local_store::extort_policy::load_all() {
        if let Ok(Some(json)) = local_store::extort_policy::load_all_local() {
            let _ = local_store::extort_policy::save_all(&json);
            let _ = local_store::extort_policy::clear_local();
        }
    }
    if let Ok(None) = local_store::trust_dir::load_all() {
        if let Ok(Some(json)) = local_store::trust_dir::load_all_local() {
            let _ = local_store::trust_dir::save_all(&json);
            let _ = local_store::trust_dir::clear_local();
        }
    }

    if local_store::process_policy::load_all().map(|v| v.is_empty()).unwrap_or(false)
        && local_store::process_policy::local_present().unwrap_or(false)
    {
        if let Ok(rows) = local_store::process_policy::load_all_local() {
            let (white, black): (Vec<_>, Vec<_>) = rows.into_iter().partition(|(_, w)| *w);
            let white: Vec<String> = white.into_iter().map(|(h, _)| h).collect();
            let black: Vec<String> = black.into_iter().map(|(h, _)| h).collect();
            let _ = local_store::process_policy::save_all(&white, &black);
            let _ = local_store::process_policy::clear_local();
        }
    }

    if local_store::peripheral_policy::load_all().map(|v| v.is_empty()).unwrap_or(false)
        && local_store::peripheral_policy::local_present().unwrap_or(false)
    {
        if let Ok(rows) = local_store::peripheral_policy::load_all_local() {
            let (white, black): (Vec<_>, Vec<_>) = rows.into_iter().partition(|r| r.is_white);
            let _ = local_store::peripheral_policy::save_all(&white, &black);
            let _ = local_store::peripheral_policy::clear_local();
        }
    }
}

/// 首次运行/从未上线时，把内置默认信任目录写入 DB 作为基线。
fn seed_default_trust_dirs() {
    if !db_enabled() {
        return;
    }
    if !matches!(local_store::trust_dir::load_all(), Ok(None)) {
        return;
    }
    let defaults = GLOBAL_PATTERN_MGR
        .get()
        .and_then(|m| m.lock().ok().map(|g| g.default_trust_dirs()))
        .unwrap_or_default();
    if defaults.is_empty() {
        return;
    }
    if let Err(e) = crate::policy_persistence::save_trust_dir(&defaults, false) {
        log_error!("[policy_store] 写入默认信任目录失败: {}", e);
    } else {
        log_info!("[policy_store] 首次启动，已写入默认信任目录 {} 条", defaults.len());
    }
}

/// 后端（驱动/eBPF + DPI writer）就绪后调用，flush 之前积累的变更并全量加载一次。
pub fn mark_backend_ready() {
    {
        let mut st = state().lock().unwrap();
        st.backend_ready = true;
    }
    migrate_legacy_local_to_baseline();
    seed_default_trust_dirs();
    log_info!("[policy_store] 后端就绪，开始从 DB 加载策略");
    load_all_domains();
}

/// 重新检查所有域，仅加载版本变化的域（用于上线/离线切换、清单对账）。
pub fn reload_changed_domains() {
    load_all_domains();
}

// ── 写入口（服务器 / gRPC 统一走这里：先写 DB，再从 DB 加载） ──

pub fn commit_dir_policy(rules: &[POLICY_PROTECT_DIR]) -> Result<(), String> {
    if !db_enabled() {
        return apply_dir_rules(rules.to_vec());
    }
    // 服务器与 gRPC 同等对待：都写同一份“当前生效”基线表，最后一次写入生效。
    crate::policy_persistence::save_dir_policy(rules, false)?;
    reload_domain(Domain::DirPolicy)
}

pub fn commit_extort_policy(rules: &[POLICY_EXIPOR_PROTECT]) -> Result<(), String> {
    if !db_enabled() {
        return apply_extort_rules(rules.to_vec());
    }
    // 服务器与 gRPC 同等对待：都写同一份“当前生效”基线表，最后一次写入生效。
    crate::policy_persistence::save_extort_policy(rules, false)?;
    reload_domain(Domain::ExtortPolicy)
}

pub fn commit_trust_dir(dirs: &[GlobalTrustDir]) -> Result<(), String> {
    if !db_enabled() {
        return apply_trust_dirs(dirs.to_vec());
    }
    // 服务器与 gRPC 同等对待：都写同一份“当前生效”基线表，最后一次写入生效。
    crate::policy_persistence::save_trust_dir(dirs, false)?;
    reload_domain(Domain::TrustDir)
}

fn save_snapshot<T: serde::Serialize>(domain: Domain, rules: &[T]) -> Result<(), String> {
    let json = serde_json::to_string(rules).map_err(|e| e.to_string())?;
    local_store::policy_snapshot::save(snapshot_key(domain), &json)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

pub fn commit_virtual_port(rules: &[crate::virtual_port_rule::VirtualPortRule]) -> Result<(), String> {
    if !db_enabled() {
        return apply_virtual_port_rules(rules.to_vec());
    }
    save_snapshot(Domain::VirtualPort, rules)?;
    reload_domain(Domain::VirtualPort)
}

pub fn commit_ip_block(rules: &[netblock::ip_policy::IpPolicy]) -> Result<(), String> {
    if !db_enabled() {
        return netblock::ip_policy::apply_policies_sync(rules.to_vec(), "netblocks");
    }
    save_snapshot(Domain::IpBlock, rules)?;
    reload_domain(Domain::IpBlock)
}

pub fn commit_ip_black(rules: &[netblock::ip_policy::IpPolicy]) -> Result<(), String> {
    if !db_enabled() {
        return netblock::ip_policy::apply_policies_sync(rules.to_vec(), "policies");
    }
    save_snapshot(Domain::IpBlack, rules)?;
    reload_domain(Domain::IpBlack)
}

pub fn commit_outreach(rules: &[crate::net_reach_rule::OutreachDetectRule]) -> Result<(), String> {
    if !db_enabled() {
        return apply_outreach_rules(rules.to_vec());
    }
    save_snapshot(Domain::Outreach, rules)?;
    reload_domain(Domain::Outreach)
}

/// gRPC 本地修改进程策略：传入修改后的完整生效名单，写基线表后整体重载。
pub fn commit_process_policy(white: &[String], black: &[String]) -> Result<(), String> {
    if !process_db_enabled() {
        let mut mgr = process_mgr::POLICY_MANAGER.lock().unwrap();
        mgr.set_policy_process(white, true, None);
        mgr.set_policy_process(black, false, None);
        return Ok(());
    }
    // 服务器与 gRPC 同等对待：都写当前生效基线表。
    local_store::process_policy::save_all(white, black).map_err(|e| e.to_string())?;
    reload_domain(Domain::Process)
}

/// 服务器进程名单是白/黑两次任务下发，两侧都到齐后一次写在线基线表。
pub fn stage_process_baseline(is_white: bool, list: &[String]) -> Result<(), String> {
    if !process_db_enabled() {
        let mut mgr = process_mgr::POLICY_MANAGER.lock().unwrap();
        mgr.set_policy_process(list, is_white, None);
        return Ok(());
    }
    let (white, black) = {
        let mut pending = process_pending().lock().unwrap();
        if is_white {
            pending.0 = Some(list.to_vec());
        } else {
            pending.1 = Some(list.to_vec());
        }
        match (pending.0.clone(), pending.1.clone()) {
            (Some(w), Some(b)) => {
                *pending = (None, None);
                (w, b)
            }
            _ => return Ok(()),
        }
    };
    local_store::process_policy::save_all(&white, &black).map_err(|e| e.to_string())?;
    reload_domain(Domain::Process)
}

/// gRPC 本地修改外设策略：写本地表后整体重载。
pub fn commit_peripheral_policy(
    white: &[local_store::peripheral_policy::PeripheralPolicyRow],
    black: &[local_store::peripheral_policy::PeripheralPolicyRow],
) -> Result<(), String> {
    if !db_enabled() {
        return apply_peripheral_rows_now(white, black);
    }
    // 服务器与 gRPC 同等对待：都写当前生效基线表。
    local_store::peripheral_policy::save_all(white, black).map_err(|e| e.to_string())?;
    reload_domain(Domain::Peripheral)
}

/// 服务器外设名单分白/黑两次任务下发；每次用 DB 中的另一侧补齐后写在线基线表。
pub fn commit_peripheral_baseline_side(
    is_white: bool,
    rows: &[local_store::peripheral_policy::PeripheralPolicyRow],
) -> Result<(), String> {
    if !db_enabled() {
        return apply_peripheral_rows_now(
            if is_white { rows } else { &[] },
            if is_white { &[] } else { rows },
        );
    }
    let current = local_store::peripheral_policy::load_all().map_err(|e| e.to_string())?;
    let mut white: Vec<_> = current.iter().filter(|r| r.is_white).cloned().collect();
    let mut black: Vec<_> = current.iter().filter(|r| !r.is_white).cloned().collect();
    if is_white {
        white = rows.to_vec();
    } else {
        black = rows.to_vec();
    }
    local_store::peripheral_policy::save_all(&white, &black).map_err(|e| e.to_string())?;
    reload_domain(Domain::Peripheral)
}

fn apply_peripheral_rows_now(
    white: &[local_store::peripheral_policy::PeripheralPolicyRow],
    black: &[local_store::peripheral_policy::PeripheralPolicyRow],
) -> Result<(), String> {
    fn to_info(row: &local_store::peripheral_policy::PeripheralPolicyRow) -> udisk::device::UsbInfo {
        udisk::device::UsbInfo::new(
            row.peripheral_eid.clone(),
            row.peripheral_name.clone(),
            row.intro.clone(),
            row.type_.clone(),
            row.is_white,
        )
    }
    let w: Vec<_> = white.iter().map(to_info).collect();
    let b: Vec<_> = black.iter().map(to_info).collect();
    *udisk::list::SHARED_USB_LIST.lock().unwrap() =
        udisk::list::BlackWhiteList::from_vecs(b, w);
    notify_policy_change(PolicyChangeType::PeripheralPolicyChanged);
    Ok(())
}

/// 上线时清空所有离线本地表（服务器策略接管），并重载受影响的域。
pub fn clear_local_policies() {
    if !db_enabled() {
        return;
    }
    if let Err(e) = local_store::process_policy::clear_local() {
        log_error!("[policy_store] 清空 process_policy_local 失败: {}", e);
    }
    crate::policy_persistence::clear_local_policies();
    if let Err(e) = local_store::peripheral_policy::clear_local() {
        log_error!("[policy_store] 清空 peripheral_policy_local 失败: {}", e);
    }
    reload_changed_domains();
}
