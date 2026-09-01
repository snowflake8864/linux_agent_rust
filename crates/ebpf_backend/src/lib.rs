use aya::maps::HashMap as AyaHashMap;
use aya::maps::Array as AyaArray;
use aya::maps::RingBuf;
use log::{info, warn};
use logging::log_info;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicBool, Ordering};

pub mod loader;
pub mod types;
pub mod capability;
pub mod dpi_parser;
use loader::ModularLoader;
use types::*;
use common::backend::SecurityBackend;

/// Maps (file_mode, run_mode, type_idx) → n_type for alert reporting.
/// file_mode: 0=file, 1=directory
/// run_mode:  0=monitor, 1=protect
/// type_idx:  0=CREATE, 1=DELETE, 2=MODIFY, 3=OPEN, 4=RENAME
static WARN_LOG_TYPE: [[[u16; 5]; 2]; 2] = [
    [ // file_mode=0 (regular file)
        [3001, 3002, 3003, 3004, 3005], // monitor
        [3101, 3102, 3103, 3104, 3105], // protect
    ],
    [ // file_mode=1 (directory)
        [2001, 2002, 2003, 2004, 2005], // monitor
        [2101, 2102, 2103, 2104, 2105], // protect
    ],
];

/// 自保专用目录保护列表（与 DPI dir_policies 独立）。
/// (路径, 是否保护整个目录子树, 文件名前缀列表)
const SELF_PROTECT_DIRS: &[(&str, bool, &[&str])] = &[
    ("/opt/osec", true, &[]),
    ("/var/lib/dpkg/info", false, &["osec."]),
    ("/etc/systemd/system/multi-user.target.wants", false, &["osec.", "agent_manager."]),
];

/// eBPF 后端 — 按需加载 proc/file/net 模块，通过 BPF maps 下发规则
pub struct EbpfBackend {
    loader: Arc<Mutex<ModularLoader>>,
    file_loaded: bool,
    proc_loaded: bool,
    net_loaded: bool,
    /// 功能开关 (对应 *_SWITCH 配置)
    file_switch: bool,
    proc_switch: AtomicBool,
    /// 进程黑白名单策略是否已加载（决定何时允许开启进程检测）
    proc_detection_enabled: AtomicBool,
    /// 防护模式 (对应 *_PROTECT 配置): false=监控, true=保护
    file_protect: bool,
    proc_protect: bool,
    pub interface: String,
    pub engine: String,
    /// MD5 → [(dev, inode, path)] 映射（后台扫描填充）
    pub md5_map: Arc<RwLock<std::collections::HashMap<String, Vec<Md5Entry>>>>,
    /// (dev, inode) → {md5, mtime, path}：以文件身份为主键的 MD5 表。
    /// BPF 进程事件与后台扫描共用；inode 全局唯一，宿主机/容器(其它 mount ns)进程
    /// 统一按此查表，不依赖路径字符串。与 md5_map 互为正反查询。
    pub inode_md5_map: Arc<RwLock<std::collections::HashMap<(u64, u64), InodeMd5Rec>>>,
    /// 进程规则缓存 (whitelist, blacklist)
    process_cache: Arc<Mutex<(Vec<String>, Vec<String>)>>,
    /// 待下发规则缓存: hash → action (0=white, 1=black), 用于 md5_map 尚未包含该 hash 时暂存
    pending_rules: Arc<Mutex<std::collections::HashMap<String, u8>>>,
    /// 已下发规则缓存: hash → action (0=white, 1=black), 用于模式切换时刷新 BPF proc_rules
    applied_rules: Arc<Mutex<std::collections::HashMap<String, u8>>>,
    /// eBPF ring buffer 读取器（从 proc_agent 的 event_ringbuf 读取进程拦截/监控事件）
    proc_ringbuf: Arc<Mutex<Option<RingBuf<aya::maps::MapData>>>>,
    /// eBPF ring buffer 读取器（从 file_agent 的 event_ringbuf 读取文件拦截/监控事件）
    file_ringbuf: Arc<Mutex<Option<RingBuf<aya::maps::MapData>>>>,
    /// eBPF ring buffer 读取器（从 net_agent 的 pkt_events 读取虚开端口命中事件）
    net_ringbuf: Arc<Mutex<Option<RingBuf<aya::maps::MapData>>>>,
    /// path → (md5, mtime) 缓存（后台扫描填充 + 首次命中时补充）
    pub path_hash_cache: Arc<RwLock<std::collections::HashMap<String, (String, u64)>>>,
    /// DPI patterns buffer — accumulated until `build` triggers matching
    dpi_pat_buffer: Arc<Mutex<String>>,
    /// DPI rules buffer — accumulated until `build` triggers matching
    dpi_rule_buffer: Arc<Mutex<String>>,
    /// DPI true process buffer
    dpi_tp_buffer: Arc<Mutex<String>>,
    /// Active dir_policies keys for clear operations
    active_dir_keys: Arc<Mutex<Vec<DirKey>>>,
    /// 进程信任白名单 patterns buffer — 累积到 build 时解析为 (dev,inode)
    proc_pat_buffer: Arc<Mutex<String>>,
    /// 已下发的进程信任白名单 proc_rules keys（用于 clear 时按 (dev,inode) 移除）
    active_proc_whitelist: Arc<Mutex<Vec<ProcKey>>>,
    /// 虚拟开端口（VIR_OPEN_PORT）策略状态：镜像驱动的"攒齐一批→整体生效"语义
    vir_port_state: Arc<Mutex<VirPortState>>,
    /// NET_AGENT 挂载时修改的 sysctl 原始值（退出时还原）
    net_sysctl_state: Mutex<Option<NetSysctlState>>,
    /// 源地址阻断（对齐驱动 block_saddr）：已写入 saddr_block_rules 的 key
    saddr_block_keys: Mutex<Vec<u32>>,
    /// 最近一次下发的阻断 IP 全量列表（开关重开时据此恢复）
    saddr_latest: Mutex<Vec<String>>,
    /// 动态阻断总开关（对应驱动 net_block_enable / write_netblock_switch）
    netblock_enabled: AtomicBool,
    /// 上次容器 overlay 补扫时间戳（秒），节流用：300 秒内不重复扫描
    last_overlay_rescan: std::sync::atomic::AtomicU64,
}

#[derive(Debug, Clone)]
pub struct Md5Entry {
    pub inode: u64,
    pub dev: u64,
    pub path: String,
}

// ── 虚拟开端口（端口虚开/重定向）──
/// 单条 VIR_OPEN_PORT 规则（对应驱动 network_dos.c 的 NetworkKernelRulesInfo）
#[derive(Debug, Clone, Default)]
struct VirPortRule {
    /// IPPROTO 编号：6=TCP, 17=UDP（VIR_OPEN_PORT 文本 1=tcp 2=udp，解析时换算）
    protocol: u8,
    /// 虚开的本机 IP（规则的 source_ip 字段，网络字节序；0=任意，走 find_net_rule wildcard 命中）
    dst_ip: u32,
    start_port: u16,
    end_port: u16,
    /// 重定向目标 IP（规则的 dest_ip 字段，网络字节序，非 0）
    dest_ip: u32,
    /// true=dest_port_type==1，保持原端口转发；false=用 redirect_port
    keep_port: bool,
    /// 重定向端口（主机字节序）
    redirect_port: u16,
    /// 告警等级（策略 addr_type & 0x1f，对应驱动 osec_report->type / 上报 weight）
    addr_type: u8,
}

/// VIR_OPEN_PORT 攒批状态。
/// 镜像驱动语义：index==0 重置缓冲；index+1==total 时整批生效；
/// vir_open_port_switch 为总闸（对应驱动 NET_DOS_ENABLE），关闭时规则表清空。
#[derive(Debug, Default)]
struct VirPortState {
    /// 对应 vir_open_port_switch 总闸（驱动 NET_DOS_ENABLE）。
    /// None=未收到过开关行，视为开启 —— eBPF 模式下若总闸行从未到达，
    /// 默认关闭会导致规则永远不生效。
    enabled: Option<bool>,
    expect_total: usize,
    pending: Vec<VirPortRule>,
    /// 最近一次完整下发且已生效的规则集（总闸重开时据此恢复写入）
    latest: Vec<VirPortRule>,
}

/// 网络转发 sysctl 原始值（退出时还原，对齐老框架 setup_sysctl/restore_sysctl）
#[derive(Debug)]
struct NetSysctlState {
    accept_local_all: Option<String>,
    accept_local_iface: Option<String>,
    ip_forward: Option<String>,
    interface: String,
}

/// XDP 端口重定向依赖的内核转发设置：
/// - SNAT 后转发包的源 IP 是本机地址，内核默认按 martian 丢弃，需 accept_local=1
/// - 重定向转发本身需要 ip_forward=1
/// 仅在 NET_AGENT 启用挂载时设置；进程退出时由 shutdown() 还原原值。
fn apply_net_sysctls(interface: &str) -> NetSysctlState {
    let iface_path = format!("/proc/sys/net/ipv4/conf/{}/accept_local", interface);
    let items: [(&str, &str); 3] = [
        ("/proc/sys/net/ipv4/conf/all/accept_local", "1"),
        (&iface_path, "1"),
        ("/proc/sys/net/ipv4/ip_forward", "1"),
    ];
    let state = NetSysctlState {
        accept_local_all: std::fs::read_to_string(items[0].0).ok().map(|s| s.trim().to_string()),
        accept_local_iface: std::fs::read_to_string(items[1].0).ok().map(|s| s.trim().to_string()),
        ip_forward: std::fs::read_to_string(items[2].0).ok().map(|s| s.trim().to_string()),
        interface: interface.to_string(),
    };

    info!("[EbpfBackend] 应用网络转发 sysctl (iface={})...", interface);
    for (path, val) in items {
        match std::fs::write(path, val) {
            Ok(()) => info!("[EbpfBackend] ✅ sysctl {} = {}", path, val),
            Err(e) => warn!("[EbpfBackend] ⚠ 写 {}={} 失败: {}", path, val, e),
        }
    }
    state
}

fn restore_net_sysctls(state: &NetSysctlState) {
    let pairs = [
        (format!("/proc/sys/net/ipv4/conf/{}/accept_local", state.interface), &state.accept_local_iface),
        ("/proc/sys/net/ipv4/conf/all/accept_local".to_string(), &state.accept_local_all),
        ("/proc/sys/net/ipv4/ip_forward".to_string(), &state.ip_forward),
    ];
    info!("[EbpfBackend] 还原网络转发 sysctl...");
    for (path, orig) in pairs {
        if let Some(v) = orig {
            match std::fs::write(&path, v) {
                Ok(()) => info!("[EbpfBackend] ✅ 还原 {} = {}", path, v),
                Err(e) => warn!("[EbpfBackend] ⚠ 还原 {}={} 失败: {}", path, v, e),
            }
        } else {
            info!("[EbpfBackend] {} 无原始值（原本不可读），跳过还原", path);
        }
    }
}

/// 解析 VIR_OPEN_PORT 行里的 IP 字段为网络字节序 u32。
/// 空串 / `""` 占位 / 0.0.0.0 / 255.255.255.255 → 0
/// （对齐驱动 `eip != 4294967295 && eip != 0 才转发` 的判断，避免全网重定向）。
fn parse_vir_ip(s: &str) -> u32 {
    let s = s.trim().trim_matches('"');
    match s.parse::<Ipv4Addr>() {
        Ok(a) if !a.is_unspecified() && !a.is_broadcast() => u32::from(a).to_be(),
        _ => 0,
    }
}

/// 解析一行 VIR_OPEN_PORT 规则，返回 (index, total, Option<rule>)。
/// 协议非 tcp/udp、IPv6、无有效 dest_ip 或既不保端口也无 redirectPort 的规则
/// （纯告警模式，eBPF 无对应语义）返回 None，但仍推进 index/total 计数。
fn parse_vir_open_port_line(line: &str) -> Option<(usize, usize, Option<VirPortRule>)> {
    let rest = line.trim().strip_prefix("VIR_OPEN_PORT ")?;
    let mut index: Option<usize> = None;
    let mut total: Option<usize> = None;
    let mut id = 0u32;
    let mut rule = VirPortRule::default();
    let mut proto_num = 0u8;
    let mut is_ipv4 = true;

    // 按 key=value 词法解析，兼容字段间的多余空格（下发端格式串里有双空格）
    for tok in rest.split_whitespace() {
        let Some((k, v)) = tok.split_once('=') else { continue };
        match k {
            "index" => index = v.parse::<usize>().ok(),
            "total" => total = v.parse::<usize>().ok(),
            "id" => id = v.parse::<u32>().unwrap_or(0),
            "protocol" => proto_num = v.parse::<u8>().unwrap_or(0),
            "is_ipv4" => is_ipv4 = v.parse::<u8>().unwrap_or(1) == 1,
            "source_ip" => rule.dst_ip = parse_vir_ip(v),
            "start_port" => rule.start_port = v.parse::<u16>().unwrap_or(0),
            "end_port" => rule.end_port = v.parse::<u16>().unwrap_or(0),
            "dest_ip" => rule.dest_ip = parse_vir_ip(v),
            // dest_port_type==1 → 保持原端口转发（与驱动 forward_dport 逻辑一致）
            "dest_port_type" => rule.keep_port = (v.parse::<u32>().unwrap_or(0) & 1) == 1,
            "redirectPort" => rule.redirect_port = v.parse::<u16>().unwrap_or(0),
            // 告警等级，上报 weight 用（对齐驱动 osec_report->type）
            "addr_type" => rule.addr_type = (v.parse::<u32>().unwrap_or(0) & 0x1f) as u8,
            _ => {} // type 字符串在 eBPF 侧无对应语义，忽略
        }
    }

    let (i, t) = (index?, total?);

    let mut r = Some(rule);
    if !is_ipv4 || proto_num == 0 {
        warn!("[EbpfBackend] VIR_OPEN_PORT id={} {} 规则，XDP 仅支持 IPv4 tcp/udp，跳过",
            id, if is_ipv4 { "协议未知" } else { "为 IPv6" });
        r = None;
    } else {
        let mut rule = r.take().unwrap();
        if rule.keep_port {
            // 保持原端口转发：不修改目的端口
            rule.redirect_port = 0;
        }
        // 纯告警规则（无有效 dest_ip 或无重定向端口）不再丢弃：
        // 以"零改写"条目写入 pkt_mod_rules，命中后仍产生事件用于上报告警，
        // 对齐驱动行为（端口区间命中即上报 openport 审计，无论是否转发）。
        // 协议换算：文本 1=tcp 2=udp → IPPROTO 6/17
        rule.protocol = match proto_num { 1 => 6, _ => 17 };
        r = Some(rule);
    }
    Some((i, t, r))
}

/// 解析进程模式行 `name=...,key=...,match_full_path=1`，返回 (name, key, match_full_path)。
fn parse_process_pattern_line(line: &str) -> Option<(&str, &str, bool)> {
    let mut name = None;
    let mut key = None;
    let mut full = false;
    for kv in line.trim().split(',') {
        let kv = kv.trim();
        if let Some(v) = kv.strip_prefix("name=") {
            name = Some(v);
        } else if let Some(v) = kv.strip_prefix("key=") {
            key = Some(v);
        } else if kv == "match_full_path=1" {
            full = true;
        }
    }
    Some((name?, key?, full))
}

/// 把路径 stat 成 (dev, inode)，只接受普通文件（跟随符号链接）。
fn stat_path_to_proc_key(path: &str) -> Option<ProcKey> {
    use std::os::linux::fs::MetadataExt;
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    Some(ProcKey { dev: meta.st_dev() as u32, inode: meta.st_ino() })
}

impl EbpfBackend {
    pub fn new(
        bpf_dir: &str,
        file_enabled: bool, file_switch: bool, file_protect: bool,
        proc_enabled: bool, proc_switch: bool, proc_protect: bool,
        net_enabled: bool,
        interface: &str,
        engine: &str,
        proc_rules_max_entries: u32,
    ) -> anyhow::Result<Self> {
        let mut loader = ModularLoader::new();
        let mut file_loaded = false;
        let mut proc_loaded = false;
        let mut net_loaded = false;

        info!("[EbpfBackend] ===== 开始加载 eBPF 模块 =====");
        info!("[EbpfBackend] .o加载: file={}, proc={}, net={} | switch: file={}, proc={} | protect: file={}, proc={}",
            file_enabled, proc_enabled, net_enabled, file_switch, proc_switch, file_protect, proc_protect);

        if file_enabled {
            let path = format!("{}/file_agent.bpf.o", bpf_dir);
            info!("[EbpfBackend] 检查文件: {}", path);
            if Path::new(&path).exists() {
                info!("[EbpfBackend] 找到 file_agent.bpf.o，开始加载...");
                loader.load_file_agent(&path)?;
                file_loaded = true;
                info!("[EbpfBackend] ✅ file_agent.bpf.o 加载成功");
            } else {
                warn!("[EbpfBackend] ❌ {} 不存在，跳过 file agent", path);
            }
        } else {
            info!("[EbpfBackend] FILE_AGENT=0，跳过 file agent");
        }

        if proc_enabled {
            let path = format!("{}/proc_agent.bpf.o", bpf_dir);
            info!("[EbpfBackend] 检查文件: {}", path);
            if Path::new(&path).exists() {
                info!("[EbpfBackend] 找到 proc_agent.bpf.o，开始加载...");
                loader.load_proc_agent(&path, proc_rules_max_entries)?;
                proc_loaded = true;
                info!("[EbpfBackend] ✅ proc_agent.bpf.o 加载成功");
            } else {
                warn!("[EbpfBackend] ❌ {} 不存在，跳过 proc agent", path);
            }
        } else {
            info!("[EbpfBackend] PROC_AGENT=0，跳过 proc agent");
        }

        if net_enabled {
            let path = format!("{}/net_agent.bpf.o", bpf_dir);
            info!("[EbpfBackend] 检查文件: {}", path);
            if Path::new(&path).exists() {
                info!("[EbpfBackend] 找到 net_agent.bpf.o，开始加载...");
                loader.load_net_agent(&path)?;
                net_loaded = true;
                info!("[EbpfBackend] ✅ net_agent.bpf.o 加载成功");
            } else {
                warn!("[EbpfBackend] ❌ {} 不存在，跳过 net agent", path);
            }
        } else {
            info!("[EbpfBackend] NET_AGENT=0，跳过 net agent");
        }

        info!("[EbpfBackend] ===== ELF 解析完成: file={}, proc={}, net={} =====",
            file_loaded, proc_loaded, net_loaded);

        Ok(Self {
            loader: Arc::new(Mutex::new(loader)),
            file_loaded, proc_loaded, net_loaded,
            file_switch, proc_switch: AtomicBool::new(proc_switch),
            proc_detection_enabled: AtomicBool::new(false),
            file_protect, proc_protect,
            interface: interface.to_string(),
            engine: engine.to_string(),
            md5_map: Arc::new(RwLock::new(std::collections::HashMap::new())),
            inode_md5_map: Arc::new(RwLock::new(std::collections::HashMap::new())),
            process_cache: Arc::new(Mutex::new((Vec::new(), Vec::new()))),
            pending_rules: Arc::new(Mutex::new(std::collections::HashMap::new())),
            applied_rules: Arc::new(Mutex::new(std::collections::HashMap::new())),
            proc_ringbuf: Arc::new(Mutex::new(None)),
            file_ringbuf: Arc::new(Mutex::new(None)),
            net_ringbuf: Arc::new(Mutex::new(None)),
            path_hash_cache: Arc::new(RwLock::new(std::collections::HashMap::new())),
            dpi_pat_buffer: Arc::new(Mutex::new(String::new())),
            dpi_rule_buffer: Arc::new(Mutex::new(String::new())),
            dpi_tp_buffer: Arc::new(Mutex::new(String::new())),
            active_dir_keys: Arc::new(Mutex::new(Vec::new())),
            proc_pat_buffer: Arc::new(Mutex::new(String::new())),
            active_proc_whitelist: Arc::new(Mutex::new(Vec::new())),
            vir_port_state: Arc::new(Mutex::new(VirPortState::default())),
            net_sysctl_state: Mutex::new(None),
            saddr_block_keys: Mutex::new(Vec::new()),
            saddr_latest: Mutex::new(Vec::new()),
            netblock_enabled: AtomicBool::new(false),
            last_overlay_rescan: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// 将缓存的 VIR_OPEN_PORT 规则集刷入 net_agent 的 vir_port_rules 区间表。
    /// 一条规则占一个槽位（区间不展开），总开关关闭时清空全表。
    /// 镜像驱动语义：每次刷新为全量替换。
    fn apply_vir_port_rules(&self) -> Result<(), String> {
        const VIR_PORT_MAX: u32 = 16;
        let st = self.vir_port_state.lock().unwrap();
        let mut loader = self.loader.lock().unwrap();
        let bpf = loader.net_bpf_mut()
            .ok_or_else(|| "net agent 未加载".to_string())?;
        let map_ref = bpf.map_mut("vir_port_rules")
            .ok_or_else(|| "vir_port_rules map 不存在".to_string())?;
        // ARRAY 类型 map，必须用 Array 接口（HashMap::try_from 会报 invalid map type 2）
        let mut tbl: AyaArray<_, VirPortBpfRule> =
            AyaArray::try_from(map_ref).map_err(|e| e.to_string())?;

        // 全量替换：先清空所有槽位（protocol=0 即空槽，XDP 侧跳过）
        let empty = VirPortBpfRule {
            protocol: 0, keep_port: 0, start_port: 0, end_port: 0,
            redirect_port: 0, dst_ip: 0, new_dst_ip: 0, addr_type: 0, pad: [0; 3],
        };
        for i in 0..VIR_PORT_MAX {
            let _ = tbl.set(i, &empty, 0);
        }

        if !st.enabled.unwrap_or(true) {
            info!("[EbpfBackend] vir_open_port_switch=0，虚拟端口规则保持清空");
            return Ok(());
        }

        let latest = &st.latest;
        if latest.len() > VIR_PORT_MAX as usize {
            warn!("[EbpfBackend] 虚开端口规则 {} 条超过表容量 {}，截断",
                latest.len(), VIR_PORT_MAX);
        }
        for (i, r) in latest.iter().take(VIR_PORT_MAX as usize).enumerate() {
            // 纯告警规则（无 dest_ip 且不保端口无 redirect）：new_dst_ip=0/redirect=0
            // 即为零改写条目，命中仍发事件用于告警
            let v = VirPortBpfRule {
                protocol: r.protocol,
                keep_port: r.keep_port as u8,
                start_port: r.start_port,
                end_port: r.end_port,
                redirect_port: r.redirect_port,
                dst_ip: r.dst_ip,
                new_dst_ip: r.dest_ip,
                addr_type: r.addr_type,
                pad: [0; 3],
            };
            tbl.set(i as u32, &v, 0)
                .map_err(|e| format!("vir_port_rules insert[{}]: {}", i, e))?;
        }
        // 计数放最后写：XDP 侧以此做热路径短路，未配置时一次查找即返回
        let meta_ref = bpf.map_mut("vir_port_meta")
            .ok_or_else(|| "vir_port_meta map 不存在".to_string())?;
        let mut meta: AyaArray<_, u32> =
            AyaArray::try_from(meta_ref).map_err(|e| e.to_string())?;
        let count = if st.enabled.unwrap_or(true) {
            (latest.len() as u32).min(VIR_PORT_MAX)
        } else {
            0
        };
        meta.set(0u32, &count, 0)
            .map_err(|e| format!("vir_port_meta update: {}", e))?;
        info!("[EbpfBackend] ✅ 虚拟开端口下发完成: {} 条区间规则", count);
        Ok(())
    }

    /// 将 saddr_latest 刷入 net_agent 的 saddr_block_rules map。
    /// 先清上次写入的 key 再写本次全量；总开关关闭时只清不写（对齐驱动 net_block_enable）。
    fn apply_saddr_blocks(&self) -> Result<(), String> {
        let enabled = self.netblock_enabled.load(Ordering::SeqCst);
        let list = self.saddr_latest.lock().unwrap().clone();
        let mut tracked = self.saddr_block_keys.lock().unwrap();

        let mut loader = self.loader.lock().unwrap();
        let bpf = loader.net_bpf_mut()
            .ok_or_else(|| "net agent 未加载".to_string())?;
        let map_ref = bpf.map_mut("saddr_block_rules")
            .ok_or_else(|| "saddr_block_rules map 不存在".to_string())?;
        let mut m: AyaHashMap<_, u32, u8> =
            AyaHashMap::try_from(map_ref).map_err(|e| e.to_string())?;

        // 清上次写入的条目
        for k in tracked.drain(..) {
            let _ = m.remove(&k);
        }

        if !enabled {
            info!("[EbpfBackend] 动态阻断开关=0，源地址阻断表保持清空");
            return Ok(());
        }

        let mut n = 0usize;
        for ip in &list {
            match ip.parse::<Ipv4Addr>() {
                Ok(addr) => {
                    // 网络字节序，与 XDP 里 ip->saddr 原始字节一致
                    let key = u32::from(addr).to_be();
                    m.insert(&key, &1u8, 0)
                        .map_err(|e| format!("saddr_block_rules insert {}: {}", ip, e))?;
                    tracked.push(key);
                    n += 1;
                }
                Err(_) => warn!("[EbpfBackend] 阻断 IP 非法，跳过: {}", ip),
            }
        }
        // 计数放最后写：XDP 侧以此做热路径短路，未配置阻断时一次 ARRAY 读即返回
        let meta_ref = bpf.map_mut("saddr_block_meta")
            .ok_or_else(|| "saddr_block_meta map 不存在".to_string())?;
        let mut meta: AyaArray<_, u32> =
            AyaArray::try_from(meta_ref).map_err(|e| e.to_string())?;
        meta.set(0u32, &(n as u32), 0)
            .map_err(|e| format!("saddr_block_meta update: {}", e))?;
        info!("[EbpfBackend] ✅ 源地址阻断下发完成: {} 条 (开关={})", n, enabled as u8);
        Ok(())
    }

    pub fn init(&self) -> anyhow::Result<()> {
        info!("[EbpfBackend] ===== 开始挂载 eBPF 程序到内核 =====");
        let mut loader = self.loader.lock().unwrap();

        if self.file_loaded {
            info!("[EbpfBackend] --- 挂载 file agent ---");
            loader.attach_file_programs()?;
            // 启用 file feature switch (index 0) + 创建 ringbuf reader
            if let Some(bpf) = loader.file_bpf_mut() {
                ModularLoader::enable_feature(bpf, 0, self.file_switch)?;
                ModularLoader::set_global_mode(bpf, 0, self.file_protect)?;
                // 写入 agent 自身 PID，防止自保规则阻断 agent 的文件操作（如写 net_info.ini）
                ModularLoader::set_agent_pid(bpf, std::process::id())?;
                if let Some(map) = bpf.take_map("event_ringbuf") {
                    match RingBuf::try_from(map) {
                        Ok(rb) => {
                            *self.file_ringbuf.lock().unwrap() = Some(rb);
                            info!("[EbpfBackend] ✅ File event ringbuf reader 创建成功");
                        }
                        Err(e) => warn!("[EbpfBackend] ❌ 创建 file ringbuf reader 失败: {}", e),
                    }
                } else {
                    warn!("[EbpfBackend] ⚠ file_agent 无 event_ringbuf map，文件事件不上报");
                }
            }
            info!("[EbpfBackend] ✅ File agent 挂载完成");
        } else {
            info!("[EbpfBackend] file_loaded=false，跳过 file agent 挂载");
        }

        if self.proc_loaded {
            info!("[EbpfBackend] --- 挂载 proc agent ---");
            loader.attach_proc_programs()?;
            // 挂载后先关闭 proc feature switch (index 1)：此刻 proc_rules 表为空，
            // 若直接使能，任何未命中信任白名单的 exec 都会被误判为“不明进程”。
            // 等黑白名单策略真正写入 proc_rules 后再由 enable_proc_detection() 开启。
            if let Some(bpf) = loader.proc_bpf_mut() {
                ModularLoader::enable_feature(bpf, 1, false)?;
                ModularLoader::set_global_mode(bpf, 1, self.proc_protect)?;
                // 写入 agent 自身 PID，防止自保规则下 agent 被外部进程 kill
                ModularLoader::set_agent_pid(bpf, std::process::id())?;
                if let Some(map) = bpf.take_map("event_ringbuf") {
                    match RingBuf::try_from(map) {
                        Ok(rb) => {
                            *self.proc_ringbuf.lock().unwrap() = Some(rb);
                            info!("[EbpfBackend] ✅ Proc event ringbuf reader 创建成功");
                        }
                        Err(e) => warn!("[EbpfBackend] ❌ 创建 ringbuf reader 失败: {}", e),
                    }
                } else {
                    warn!("[EbpfBackend] ❌ 未找到 event_ringbuf map");
                }
            }
            info!("[EbpfBackend] ✅ Proc agent 挂载完成");
        } else {
            info!("[EbpfBackend] proc_loaded=false，跳过 proc agent 挂载");
        }

        if self.net_loaded {
            info!("[EbpfBackend] --- 挂载 net agent ---");
            // 端口重定向依赖：accept_local（SNAT 后本机源地址不被判 martian）+ ip_forward
            *self.net_sysctl_state.lock().unwrap() = Some(apply_net_sysctls(&self.interface));
            loader.attach_net_programs(&self.interface, &self.engine)?;
            // 启用 net feature switch (index 2) — net_agent 可能没有 feature_switches map，容错
            if let Some(bpf) = loader.net_bpf_mut() {
                ModularLoader::enable_feature(bpf, 2, true)?;
                // 创建 pkt_events ringbuf reader（虚开端口命中事件 → 告警上报）
                if let Some(map) = bpf.take_map("pkt_events") {
                    match RingBuf::try_from(map) {
                        Ok(rb) => {
                            *self.net_ringbuf.lock().unwrap() = Some(rb);
                            info!("[EbpfBackend] ✅ Net event ringbuf reader 创建成功");
                        }
                        Err(e) => warn!("[EbpfBackend] ❌ 创建 net ringbuf reader 失败: {}", e),
                    }
                } else {
                    warn!("[EbpfBackend] ⚠ net_agent 无 pkt_events map，虚开端口不上报告警");
                }
            }
            info!("[EbpfBackend] ✅ Net agent 挂载完成 ({}@{})", self.interface, self.engine);
        } else {
            info!("[EbpfBackend] net_loaded=false，跳过 net agent 挂载");
        }

        info!("[EbpfBackend] ===== 所有 eBPF 程序挂载完毕 =====");
        Ok(())
    }

    /// 黑白名单策略首次真正写入 proc_rules 后才启用进程检测（feature_switches[1]）。
    /// 幂等，只开启一次。init() 阶段检测被关闭，避免启动空表导致误报；
    /// 在线(服务器 push → add_md5_rules 直写)与离线(扫描后 replay_pending_rules 补写)两条路径
    /// 首次写规则时都会走到这里。
    pub fn enable_proc_detection(&self) {
        if self.proc_detection_enabled.swap(true, Ordering::SeqCst) {
            return; // 已开启
        }
        let mut loader = self.loader.lock().unwrap();
        if let Some(bpf) = loader.proc_bpf_mut() {
            let _ = ModularLoader::enable_feature(bpf, 1, self.proc_switch.load(Ordering::SeqCst));
            info!("[EbpfBackend] ✅ 进程策略已加载，启用进程检测 (proc_switch={})",
                self.proc_switch.load(Ordering::SeqCst));
        }
    }

    pub fn is_file_loaded(&self) -> bool { self.file_loaded }
    pub fn is_proc_loaded(&self) -> bool { self.proc_loaded }
    pub fn is_net_loaded(&self) -> bool { self.net_loaded }

    /// 运行时更新 feature_switches + global_modes + 刷新已有 proc_rules
    pub fn sync_runtime_switches(&self, file_switch: bool, proc_switch: bool,
                                  file_protect: bool, proc_protect: bool) {
        // 记录运行时进程开关，供 enable_proc_detection 按最新值开启检测
        self.proc_switch.store(proc_switch, Ordering::SeqCst);
        {
            let mut loader = self.loader.lock().unwrap();
            if self.file_loaded {
                if let Some(bpf) = loader.file_bpf_mut() {
                    let _ = ModularLoader::enable_feature(bpf, 0, file_switch);
                    let _ = ModularLoader::set_global_mode(bpf, 0, file_protect);
                }
            }
            if self.proc_loaded {
                if let Some(bpf) = loader.proc_bpf_mut() {
                    // 进程检测需在黑白名单策略加载后才允许开启，避免启动空表误报。
                    let effective = proc_switch && self.proc_detection_enabled.load(Ordering::SeqCst);
                    let _ = ModularLoader::enable_feature(bpf, 1, effective);
                    let _ = ModularLoader::set_global_mode(bpf, 1, proc_protect);
                }
            }
        }
        // 无条件刷新所有 proc_rules，确保模式与 global_modes 一致
        self.refresh_all_proc_rules(proc_protect);
    }

    /// 用新 mode 重写所有已下发的 proc_rules BPF 条目
    fn refresh_all_proc_rules(&self, protect: bool) {
        let mode: u8 = if protect { 2 } else { 1 };
        let applied = match self.applied_rules.lock() {
            Ok(g) => g,
            Err(e) => { log::error!("[EbpfBackend] ❌ applied_rules mutex poisoned (refresh), recovering"); e.into_inner() }
        };
        let md5_map = match self.md5_map.read() {
            Ok(g) => g,
            Err(e) => { log::error!("[EbpfBackend] ❌ md5_map mutex poisoned (refresh), recovering"); e.into_inner() }
        };
        let mut refreshed = 0;

        for (hash, &action) in applied.iter() {
            if let Some(entries) = md5_map.get(hash) {
                for e in entries {
                    let _ = self.add_proc_rule_by_inode(e.dev as u32, e.inode, action, mode);
                }
                refreshed += 1;
            }
        }
        log::info!("[EbpfBackend] 🔄 模式切换: 已刷新 {} 条 proc_rules (mode={})", refreshed,
            if protect { "PROTECT" } else { "MONITOR" });
    }

    /// 从 ringbuf 中读取所有待处理事件（epoll + 同步读取）
    fn drain_ringbuf(ringbuf_mutex: &Arc<Mutex<Option<RingBuf<aya::maps::MapData>>>>) -> Vec<Vec<u8>> {
        let mut guard = match ringbuf_mutex.lock() {
            Ok(g) => g,
            Err(e) => {
                log::error!("[EbpfBackend] ❌ drain_ringbuf mutex poisoned! recovering... err={}", e);
                e.into_inner()
            }
        };
        if let Some(ref mut ringbuf) = *guard {
            let mut items: Vec<Vec<u8>> = Vec::new();
            while let Some(item) = ringbuf.next() {
                items.push(item.to_vec());
            }
            items
        } else {
            Vec::new()
        }
    }

    /// 解析进程 ringbuf 事件
    fn parse_event(data: &[u8]) -> Option<(&UnifiedEvent, String, String)> {
        if data.len() < UNIFIED_EVENT_SIZE { return None; }
        let event: &UnifiedEvent = unsafe { &*(data.as_ptr() as *const UnifiedEvent) };
        let path = String::from_utf8_lossy(&event.path).trim_end_matches('\0').to_string();
        let comm = String::from_utf8_lossy(&event.comm).trim_end_matches('\0').to_string();
        Some((event, path, comm))
    }

    /// 解析文件 ringbuf 事件 (92 bytes, 含 op_type)
    fn parse_file_event(data: &[u8]) -> Option<(&FileEvent, String, String)> {
        if data.len() < FILE_EVENT_SIZE { return None; }
        let event: &FileEvent = unsafe { &*(data.as_ptr() as *const FileEvent) };
        let path = String::from_utf8_lossy(&event.path).trim_end_matches('\0').to_string();
        let comm = String::from_utf8_lossy(&event.comm).trim_end_matches('\0').to_string();
        Some((event, path, comm))
    }

    /// 按 op_type 位掩码推导 type_idx (匹配 G_WARN_LOG_TYPE 列)
    /// OP_CREATE=0, OP_DELETE=1, OP_MODIFY=2, OP_OPEN=3, OP_RENAME=4
    fn op_type_to_idx(op: u8) -> usize {
        if op & OP_CREATE != 0 { 0 }
        else if op & OP_DELETE != 0 { 1 }
        else if op & OP_MODIFY != 0 { 2 }
        else if op & OP_WRITE != 0 { 2 }  // OP_WRITE → modify
        else { 3 }  // OP_READ → open (idx=3), and fallback
    }

    /// 启动 eBPF 进程事件 ring buffer 读取器
    /// 当 eBPF proc_agent 拦截/监控进程时，通过 ringbuf 发送事件，这里读取并上报告警
    pub fn start_proc_event_reader(self: &Arc<Self>) {
        if !self.proc_loaded { return; }
        let rb = self.proc_ringbuf.clone();
        let backend = self.clone();
        std::thread::spawn(move || {
            info!("[EbpfBackend] 进程事件 ringbuf reader 已启动");
            let mut tick: u64 = 0;
            let mut total_events: u64 = 0;
            let mut total_errors: u64 = 0;
            loop {
                let items = Self::drain_ringbuf(&rb);
                if !items.is_empty() {
                    log::info!("[EbpfBackend] 📨 进程 ringbuf 收到 {} 条事件", items.len());
                }
                total_events += items.len() as u64;
                for data in &items {
                    log::info!("[EbpfBackend] 📨 事件原始数据: len={} first_bytes={:02x?}", data.len(), &data[..std::cmp::min(data.len(), 16)]);
                    match Self::parse_event(data) {
                        Some((event, path, comm)) => {
                            let is_black = event.event_type == 2; // EVENT_PROC
                            log::info!("[EbpfBackend] 📨 事件解析: type={} blocked={} pid={} uid={} dev={} inode={} path={} comm={}",
                                event.event_type, event.blocked, event.pid, event.uid, event.dev, event.inode, path, comm);
                            let n_type = if event.blocked == 1 {
                                if is_black { 1102 } else { 1101 }
                            } else if is_black { 1002 } else { 1001 };
                            let action_str = if event.blocked == 1 { "拦截" } else { "监控" };
                            log::info!("[EbpfBackend] 📨 开始上报: n_type={} action={} pid={}", n_type, action_str, event.pid);
                            if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                backend.report_process_event(event, &path, &comm, n_type, action_str);
                            })) {
                                total_errors += 1;
                                log::error!("[EbpfBackend] ❌ report_process_event panic! pid={} err={:?} (total_errors={})",
                                    event.pid, e, total_errors);
                            } else {
                                log::info!("[EbpfBackend] 📨 上报完成: n_type={} pid={}", n_type, event.pid);
                            }
                        }
                        None => {
                            total_errors += 1;
                            log::warn!("[EbpfBackend] 📨 事件解析失败: len={} (total_errors={})", data.len(), total_errors);
                        }
                    }
                }
                /*
                tick += 1;
                if tick % 600 == 0 {  // ~5分钟 (500ms * 600)
                    log::info!("[EbpfBackend] 💓 proc ringbuf reader alive: tick={} total_events={} total_errors={}",
                        tick, total_events, total_errors);
                }
                */
                if items.is_empty() {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        });
    }

    /// 启动 eBPF 文件事件 ring buffer 读取器
    /// 当 eBPF file_agent 拦截/监控文件操作时，通过 ringbuf 发送事件，这里读取并上报告警
    pub fn start_file_event_reader(self: &Arc<Self>) {
        if !self.file_loaded { return; }
        let rb = self.file_ringbuf.clone();
        let backend = self.clone();
        std::thread::spawn(move || {
            info!("[EbpfBackend] 文件事件 ringbuf reader 已启动");
            loop {
                let items = Self::drain_ringbuf(&rb);
                for data in &items {
                    if let Some((event, path, comm)) = Self::parse_file_event(data) {
                        if event.event_type == EVENT_SELF_PROTECT {
                            backend.report_self_protect_event(&path, &comm, event.pid, event.uid, event.op_type);
                            continue;
                        }
                        let type_idx = Self::op_type_to_idx(event.op_type);
                        let run_mode: usize = if event.blocked == 1 { 1 } else { 0 };
                        let n_type = WARN_LOG_TYPE[0][run_mode][type_idx];
                        let op_name = match type_idx {
                            0 => "CREATE", 1 => "DELETE", 2 => "MODIFY",
                            3 => "OPEN", 4 => "RENAME", _ => "?",
                        };
                        if event.blocked == 1 {
                            log::warn!("[EbpfBackend] 🚫 文件拦截: path={} comm={} pid={} op_type=0x{:02X}→{} n_type={}",
                                path, comm, event.pid, event.op_type, op_name, n_type);
                            backend.report_file_event(&path, &comm, n_type, "拦截", event.pid, event.op_type, op_name);
                        } else {
                            log::info!("[EbpfBackend] 👀 文件监控: path={} comm={} pid={} op_type=0x{:02X}→{} n_type={}",
                                path, comm, event.pid, event.op_type, op_name, n_type);
                            backend.report_file_event(&path, &comm, n_type, "监控", event.pid, event.op_type, op_name);
                        }
                    }
                }
                if items.is_empty() {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        });
    }

    /// 启动 eBPF 网络事件 ring buffer 读取器
    /// net_agent XDP 命中虚开端口/重定向规则时通过 pkt_events 发送事件，
    /// 这里转换为 OpenPortLog 上报（对齐驱动 openport 审计 → /v1/upOpenPort）。
    pub fn start_net_event_reader(self: &Arc<Self>) {
        if !self.net_loaded { return; }
        let rb = self.net_ringbuf.clone();
        let backend = self.clone();
        std::thread::spawn(move || {
            info!("[EbpfBackend] 网络事件 ringbuf reader 已启动");
            // 同 (攻击IP, 虚开端口) 30 秒去重：抑制 SYN 重传造成的告警风暴
            let mut last_seen: std::collections::HashMap<(u32, u16), std::time::Instant> =
                std::collections::HashMap::new();
            loop {
                let items = Self::drain_ringbuf(&rb);
                for data in &items {
                    if data.len() < PKT_EVENT_SIZE { continue; }
                    let ev: PktEvent = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const PktEvent) };
                    // 只关心 XDP ingress 命中 pkt_mod 规则的事件（0x40），阻断(0x80)走别的告警
                    if ev.event_type != 3 || ev.tcp_flags_set != 0x40 { continue; }

                    let attack_ip = u32::from_be(ev.src_ip);
                    let dest_ip = u32::from_be(ev.dst_ip);
                    let dport = u16::from_be(ev.dst_port);

                    // 去重窗口
                    let key = (attack_ip, dport);
                    let now = std::time::Instant::now();
                    if let Some(t) = last_seen.get(&key) {
                        if now.duration_since(*t) < std::time::Duration::from_secs(30) {
                            continue;
                        }
                    }
                    last_seen.insert(key, now);
                    last_seen.retain(|_, t| now.duration_since(*t) < std::time::Duration::from_secs(120));

                    // 用本地规则缓存补全 redirect_ip / redirect_port / weight(addr_type)
                    let (weight, redirect_ip, redirect_port) = {
                        let st = backend.vir_port_state.lock().unwrap();
                        match st.latest.iter().find(|r| {
                            r.protocol == ev.protocol
                                && dport >= r.start_port && dport <= r.end_port
                                && (r.dst_ip == 0 || r.dst_ip == ev.dst_ip)
                        }) {
                            Some(r) => (
                                r.addr_type as i32,
                                if r.dest_ip != 0 {
                                    Ipv4Addr::from(u32::from_be(r.dest_ip)).to_string()
                                } else {
                                    String::new()
                                },
                                if !r.keep_port && r.redirect_port != 0 { r.redirect_port as i32 } else { 0 },
                            ),
                            None => (0, String::new(), 0),
                        }
                    };

                    let log = reporter::OpenPortLog {
                        weight,
                        time: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i32,
                        attack_ip: Ipv4Addr::from(attack_ip).to_string(),
                        destination_ip: Ipv4Addr::from(dest_ip).to_string(),
                        open_port: dport as i32,
                        redirect_ip,
                        redirect_port,
                    };
                    info!("[EbpfBackend] 🚨 虚开端口命中: {}:{} -> {}:{} redirect={}:{} weight={}",
                        log.attack_ip, u16::from_be(ev.src_port), log.destination_ip,
                        log.open_port, log.redirect_ip, log.redirect_port, log.weight);
                    reporter::fake_port_audit::push_open_port_log(log);
                }
                if items.is_empty() {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        });
    }

    /// 获取文件 MD5：从 path_hash_cache 查（mtime 校验），miss 时计算并回填
    fn get_md5_cached(&self, path: &str) -> Option<String> {
        // 1. 查缓存（带 mtime 校验，与 process_mgr::md5_cache 一致）
        {
            let cache = self.path_hash_cache.read().unwrap();
            if let Some((cached_md5, cached_mtime)) = cache.get(path) {
                if let Ok(meta) = std::fs::metadata(path) {
                    if let Some(cur_mtime) = meta.modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    {
                        if cur_mtime.as_secs() == *cached_mtime {
                            return Some(cached_md5.clone());
                        }
                    }
                }
            }
        }
        // 2. miss：读取文件计算 MD5
        let data = std::fs::read(path).ok()?;
        let hash = hex::encode(md5::compute(&data).0);
        if let Some(mtime_secs) = std::fs::metadata(path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
        {
            self.path_hash_cache.write().unwrap()
                .insert(path.to_string(), (hash.clone(), mtime_secs));
        }
        Some(hash)
    }

/// 上报进程告警（拦截: n_type=1101, 监控: n_type=1001）
fn report_process_event(&self, event: &UnifiedEvent, path: &str, comm: &str, n_type: u16, action: &str) {
//            log::info!("[EbpfBackend] 📋 report_process_event BEGIN: n_type={} pid={} uid={} dev={} inode={} path={} comm={}", n_type, event.pid, event.uid, event.dev, event.inode, path, comm);
        let key = (event.dev, event.inode);
        // 根据 UID 筛选候选 PID 列表（仅遍历 /proc 一次，符合性能要求）
        let uid = event.uid;
        let mut candidate_pids = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let pid_str = entry.file_name().to_string_lossy().to_string();
                if let Ok(pid) = pid_str.parse::<u32>() {
                    let status_path = format!("/proc/{}/status", pid);
                    if let Ok(content) = std::fs::read_to_string(&status_path) {
                        if let Some(uid_line) = content.lines().find(|line| line.starts_with("Uid:")) {
                            let parts: Vec<&str> = uid_line.split_whitespace().collect();
                            if let Some(uid_str) = parts.get(1) {
                                if let Ok(process_uid) = uid_str.parse::<u32>() {
                                    if process_uid == uid {
                                        candidate_pids.push(pid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let (md5_hash, real_path) = self.resolve_proc_md5(event.pid, key, path, uid, &candidate_pids);
        log::info!("[EbpfBackend] 📋 resolve_proc_md5 done: md5={} real_path={}",
            md5_hash.as_deref().unwrap_or("(none)"), real_path);
        let is_container = real_path != path;
        /*
        if is_container {
            info!("[EbpfBackend] 🔍 跨 mount ns 进程(疑似容器): pid={} uid={} comm={} ns_path={} real_path={} dev={} inode={} md5={}",
                event.pid, event.uid, comm, path, real_path,
                event.dev, event.inode,
                md5_hash.as_deref().unwrap_or("(none)"));
        }
        */
        // 容器进程且 md5 未命中 → 按需补扫容器 overlay（防止启动后新容器的可执行文件漏扫）
        let mut md5_hash = md5_hash;
        let mut real_path = real_path;
        if is_container && md5_hash.is_none() {
            self.maybe_rescan_container_overlays();
            // 补扫后重新解析 md5（新扫描的数据已入 md5_map/inode_md5_map）
            let (h, p) = self.resolve_proc_md5(event.pid, key, path, uid, &candidate_pids);
            md5_hash = h;
            real_path = p;
            if md5_hash.is_some() {
                info!("[EbpfBackend] 🔍 补扫后命中: dev={} inode={} md5={}",
                    event.dev, event.inode, md5_hash.as_deref().unwrap_or(""));
            }
        } 
        // 不明进程命中时，通过 inode→MD5→全量名单表查找，即时补写 proc_rules，
        // 让下一次 exec 能按名单放行/拦截。
        // resolved_action: None=真未知, Some(0)=白名单, Some(1)=黑名单
        let mut resolved_action: Option<u8> = None;
        if matches!(n_type, 1001 | 1101) {
            if let Some(h) = md5_hash.as_deref() {
                //log::info!("[EbpfBackend] 📋 尝试解析待定规则: n_type={} hash={}", n_type, h);
                resolved_action = self.try_resolve_pending_rule(key, h, &real_path);
                //log::info!("[EbpfBackend] 📋 resolved_action={:?} (None=真未知,0=白名单,1=黑名单)", resolved_action);
            } else {

                log::info!("[EbpfBackend] 📋 无 md5，跳过 try_resolve_pending_rule");
            }
        }

        if resolved_action == Some(0) {
            log::info!("[EbpfBackend] 白名单进程放行: pid={} uid={} comm={} dev={} inode={}",
                event.pid, event.uid, comm, event.dev, event.inode);
            return;
        }

        let final_n_type = match resolved_action {
            Some(1) => {
                // 黑名单：修改标记（与 EVENT_PROC 的 n_type 对齐）
                if event.blocked == 1 { 1102 } else { 1002 }
            }
            _ => n_type,                  // 真未知（None 或意外值）
        };

        // 黑名单命中：同步 BPF 后仍上报告警（标记为黑名单 n_type）
        // 真未知：正常上报，让服务器有机会评判
        // 容器进程路径格式：去掉 /proc/<pid>/root/ 前缀，加 ;container 后缀
        // /proc/<pid>/root/<path> 结构固定：第4个/之后就是容器内路径
        let display_path = if is_container {
            let clean = {
                let mut slash_count = 0u32;
                let mut cut_pos = 0usize;
                for (i, c) in real_path.char_indices() {
                    if c == '/' {
                        slash_count += 1;
                        if slash_count == 4 {
                            cut_pos = i + 1; // 第4个/之后
                            break;
                        }
                    }
                }
                if cut_pos > 0 && cut_pos < real_path.len() {
                    &real_path[cut_pos..]
                } else {
                    real_path.as_str()
                }
            };
            format!("{};container", clean)
        } else {
            real_path.clone()
        };
        let log = reporter::AuditLogInfo {
            file_path: Some(display_path.clone()),
            md5: md5_hash.clone(),
            n_type: final_n_type,
            n_level: if final_n_type >= 1100 { 3 } else { 2 },
            n_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
            rename_dir: None,
            notice_remark: Some(format!("eBPF进程{}: pid={} uid={}", action, event.pid, event.uid)),
            exception_process: Some(comm.to_string()),
            peripheral_name: None, peripheral_remark: None, peripheral_eid: None,
            p_param: Some(display_path.clone()),
        };
        log::info!("[EbpfBackend] 📋 broadcasting alert: n_type={} level={} path={}", final_n_type, log.n_level, display_path);
        reporter::broadcast_audit_log(&log);
        log::info!("[EbpfBackend] 📋 sending http upload: n_type={}", final_n_type);
        reporter::send_to_http_upload(&log);

        if matches!(final_n_type, 1001 | 1101) {
            log::info!("[EbpfBackend] 📋 sending autoupload_process: pid={} hash={}", event.pid, md5_hash.as_deref().unwrap_or("(none)"));
            reporter::send_to_autoupload_process(&reporter::AuditProcess {
                n_time: 0,
                str_name: String::new(),
                str_vendor: String::new(),
                str_package: String::new(),
                n_process_id: event.pid,
                n_parent_id: 0,
                n_priority: 0,
                n_thread_count: 0,
                n_working_set_size: 0,
                str_start_time: String::new(),
                str_executable_path: display_path,
                str_user: reporter::get_user_name(event.uid),
                hash: md5_hash.unwrap_or_default(),
                map_depends: vec![],
            });
        }
        log::info!("[EbpfBackend] 📋 report_process_event END: n_type={} pid={}", final_n_type, event.pid);
    }

    /// 按文件身份 (dev, inode) 解析进程可执行文件的 MD5 与展示路径。
    /// 返回 (md5, 展示路径)；md5 可能为 None（文件已删除/进程秒退且表未命中）。
    fn resolve_proc_md5(&self, pid: u32, key: (u64, u64), hint_path: &str, uid: u32, candidate_pids: &[u32])
        -> (Option<String>, String)
    {
// 核心修改：直接遍历候选 PID 列表（由 UID 筛选），不再遍历 /proc 全量
log::info!("[EbpfBackend] 🔍 resolve_proc_md5: uid={} candidate_pids_count={}", uid, candidate_pids.len());

// 直接遍历候选 PID 列表
for pid in candidate_pids {
    let root = format!("/proc/{}/root", pid);
    
    if hint_path.starts_with('/') {
        if let Some((hash, rp)) = self.read_container_md5(key, hint_path, &root) {
            log::info!("[EbpfBackend] 🔍 仅遍历UID下PID命中: pid={} md5={}", pid, &hash[..8]);
            return (Some(hash), rp);
        }
    } else {
        // 相对路径逻辑
        let name = hint_path.trim_start_matches("./");
        let candidates = ["/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/small", "/usr/local/sbin"];
        for prefix in &candidates {
            let full = format!("{}/{}", prefix, name);
            if let Some((hash, rp)) = self.read_container_md5(key, &full, &root) {
                log::info!("[EbpfBackend] 🔍 仅遍历UID下PID命中: pid={} md5={}", pid, &hash[..8]);
                return (Some(hash), rp);
            }
        }
    }
}

// 如果候选 PID 列表遍历完毕仍未命中，返回失败
log::info!("[EbpfBackend] 🔍 未在候选 PID 列表中找到匹配");
(None, hint_path.to_string())
    }

    /// 从某个进程 root（/proc/<pid>/root，宿主机或任一容器）下读取 hint_path 指向的文件，
    /// 校验 stat 出的 (dev,ino)==key 后算 MD5 并回填 inode_md5_map（容器条目 mtime=0 不校验）。
    fn read_container_md5(&self, key: (u64, u64), hint_path: &str, root: &str)
        -> Option<(String, String)>
    {
        use std::os::unix::fs::MetadataExt;
        // 相对路径如 ./grep → /proc/<pid>/root/./grep，内核会解析
        let full = format!("{}/{}", root, hint_path);
        let meta = std::fs::metadata(&full).ok()?;
        if (meta.dev(), meta.ino()) != key {
            return None;
        }
        let hash = Self::compute_file_md5(&full)?;
        match self.inode_md5_map.write() {
            Ok(mut map) => { map.insert(key, InodeMd5Rec { md5: hash.clone(), mtime: 0, path: hint_path.to_string() }); }
            Err(e) => {
                log::error!("[EbpfBackend] ❌ inode_md5_map write poisoned (read_container_md5), recovering");
                e.into_inner().insert(key, InodeMd5Rec { md5: hash.clone(), mtime: 0, path: hint_path.to_string() });
            }
        }
        Some((hash, full))
    }

    /// 上报进程已退出时，遍历其它存活进程，用其 /proc/<pid2>/root 去容器文件系统里
    /// 按 (dev,ino) 匹配 hint_path 对应文件并算 MD5。
    fn resolve_md5_via_surviving_proc(&self, key: (u64, u64), hint_path: &str, except_pid: u32)
        -> Option<(String, String)>
    {
        let entries = std::fs::read_dir("/proc").ok()?;
        for entry in entries.flatten() {
            let pid: u32 = match entry.file_name().to_string_lossy().parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if pid == except_pid {
                continue;
            }
            let root = format!("/proc/{}/root", pid);
            if let Some((hash, rp)) = self.read_container_md5(key, hint_path, &root) {
                return Some((hash, rp));
            }
        }
        None
    }

    /// 缓存未命中时用宿主机真实路径解析：stat(real_path) 身份 (dev,ino)==key → 现场算 MD5 入表。
    /// 身份不符（如容器 ns 路径指向宿主机同名文件）返回 None。
    fn lookup_or_compute_md5(&self, key: (u64, u64), real_path: &str) -> Option<(String, String)> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(real_path).ok()?;
        if (meta.dev(), meta.ino()) != key {
            return None; // 身份不符：路径只是同名巧合，不可信
        }
        let mtime = meta.modified().ok()?
            .duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
        let hash = Self::compute_file_md5(real_path)?;
        match self.inode_md5_map.write() {
            Ok(mut map) => { map.insert(key, InodeMd5Rec { md5: hash.clone(), mtime, path: real_path.to_string() }); }
            Err(e) => {
                log::error!("[EbpfBackend] ❌ inode_md5_map write poisoned (lookup_or_compute_md5), recovering");
                e.into_inner().insert(key, InodeMd5Rec { md5: hash.clone(), mtime, path: real_path.to_string() });
            }
        }
        Some((hash, real_path.to_string()))
    }

    fn compute_file_md5(path: &str) -> Option<String> {
        let data = std::fs::read(path).ok()?;
        Some(hex::encode(md5::compute(&data).0))
    }

    /// 上报文件告警
    fn report_file_event(&self, path: &str, comm: &str, n_type: u16, action: &str, pid: u32, op_type: u8, op_name: &str) {
        let md5_hash = self.get_md5_cached(path);
        let log = reporter::AuditLogInfo {
            file_path: Some(path.to_string()),
            md5: md5_hash,
            n_type,
            n_level: if action == "拦截" { 3 } else { 2 },
            n_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
            rename_dir: None,
            notice_remark: Some(format!("eBPF文件{}: pid={} op=0x{:02X}({}) n_type={}",
                action, pid, op_type, op_name, n_type)),
            exception_process: Some(comm.to_string()),
            peripheral_name: None, peripheral_remark: None, peripheral_eid: None,
            p_param: Some(path.to_string()),
        };
        reporter::broadcast_audit_log(&log);   // gRPC 推送
        reporter::send_to_http_upload(&log);   // HTTP 上报到服务器
    }

    // ── 内部 helper ──

    fn add_proc_rule_by_inode(&self, dev: u32, inode: u64, action: u8, mode: u8) -> anyhow::Result<()> {
        let mut loader = self.loader.lock().unwrap();
        let bpf = loader.proc_bpf_mut().ok_or_else(|| anyhow::anyhow!("Proc agent not loaded"))?;
        let mut proc_rules: AyaHashMap<_, ProcKey, ProcRuleVal> =
            AyaHashMap::try_from(bpf.map_mut("proc_rules").unwrap())?;
        proc_rules.insert(ProcKey { dev, inode }, ProcRuleVal::new(action, mode), 0)?;
        Ok(())
    }

    // ── 进程信任白名单（PROCESS_PATTERNS）→ proc_rules (dev,inode) ──

    /// 移除之前下发的信任进程白名单 proc_rules 条目。
    fn clear_proc_whitelist_bpf(&self) {
        let keys = std::mem::take(&mut *self.active_proc_whitelist.lock().unwrap());
        if keys.is_empty() {
            return;
        }
        let mut loader = match self.loader.lock() {
            Ok(l) => l,
            Err(_) => return,
        };
        let bpf = match loader.proc_bpf_mut() {
            Some(b) => b,
            None => return,
        };
        let map_data = match bpf.map_mut("proc_rules") {
            Some(m) => m,
            None => return,
        };
        let mut proc_rules = match AyaHashMap::<_, ProcKey, ProcRuleVal>::try_from(map_data) {
            Ok(m) => m,
            Err(_) => return,
        };
        for key in &keys {
            let _ = proc_rules.remove(key);
        }
        info!("[EbpfBackend] 已清除进程信任白名单 {} 条", keys.len());
    }

    /// 解析累积的进程模式文本，把每个信任进程解析成 (dev,inode) 写入 proc_rules 白名单。
    /// action=ALLOW(0), mode=0(继承)；BPF 命中后按 (dev,inode) 做 O(1) hash 查找并放行，
    /// 不做任何字符串比对。信任目录 trueDir_* 在此跳过（由 file DPI dir_policies 处理）。
    fn commit_proc_whitelist_bpf(&self) {
        let text = self.proc_pat_buffer.lock().unwrap().clone();
        if text.trim().is_empty() {
            log_info!("[EbpfBackend] 信任进程白名单: proc_pat_buffer 为空，跳过下发");
            return;
        }

        let search_dirs = self.trusted_process_search_dirs();
        log_info!("[EbpfBackend] 信任进程白名单: 开始解析 {} 行, search_dirs={:?}",
            text.lines().count(), search_dirs);
        let mut keys: Vec<ProcKey> = Vec::new();
        let mut seen = std::collections::HashSet::<(u64, u64)>::new();

        for line in text.lines() {
            let Some((name, key, full_path)) = parse_process_pattern_line(line) else { continue; };
            // 只处理信任进程，跳过信任目录
            if name.starts_with("trueDir_") {
                continue;
            }
            if key.is_empty() {
                continue;
            }

            if full_path {
                // match_full_path=1：key 是完整路径，直接 stat
                match stat_path_to_proc_key(key) {
                    Some(dk) => {
                        let (dk_dev, dk_ino) = (dk.dev, dk.inode);
                        if seen.insert((dk_dev as u64, dk_ino)) {
                            log_info!("[EbpfBackend] 信任进程白名单 ✅ {} (full) -> dev={} inode={}",
                                key, dk_dev, dk_ino);
                            keys.push(dk);
                        }
                    }
                    None => log_info!("[EbpfBackend] 信任进程白名单 ⚠️ {} (full) 未解析到 dev/inode（文件不存在或非普通文件）", key),
                }
            } else {
                // 子串/裸名：取 basename，在 $PATH + 系统目录中搜索
                let basename = key.rsplit('/').next().unwrap_or(key);
                if basename.is_empty() {
                    continue;
                }
                let mut hit = false;
                for dir in &search_dirs {
                    let cand = format!("{}/{}", dir, basename);
                    if let Some(dk) = stat_path_to_proc_key(&cand) {
                        if seen.insert((dk.dev as u64, dk.inode)) {
                            /*log_info!("[EbpfBackend] 信任进程白名单 ✅ {} (basename={}) -> {} dev={} inode={}",
                                key, basename, cand, dk.dev, dk.inode);*/
                            keys.push(dk);
                        }
                        hit = true;
                    }
                }
                if !hit {
                    log_info!("[EbpfBackend] 信任进程白名单 ⚠️ {} (basename={}) 在 search_dirs 中未找到", key, basename);
                }
            }
        }

        let mut written = 0usize;
        let mut tracked: Vec<ProcKey> = Vec::new();
        for dk in &keys {
            match self.add_proc_rule_by_inode(dk.dev as u32, dk.inode, 0 /*allow*/, 0 /*inherit*/) {
                Ok(_) => {
                    written += 1;
                    tracked.push(*dk);
                }
                Err(e) => {
                    let (dk_dev, dk_ino) = (dk.dev, dk.inode);
                    warn!(
                        "[EbpfBackend] 信任进程白名单写入失败 dev={} inode={}: {}",
                        dk_dev, dk_ino, e
                    );
                }
            }
        }
        *self.active_proc_whitelist.lock().unwrap() = tracked;
        log_info!("[EbpfBackend] 🛡️ 信任进程白名单: 解析 {} 条, 写入 proc_rules {} 条", keys.len(), written);
    }

    /// 信任进程搜索目录：$PATH + 常见系统目录（去重）。
    fn trusted_process_search_dirs(&self) -> Vec<String> {
        let mut dirs: Vec<String> = Vec::new();
        if let Ok(path) = std::env::var("PATH") {
            for d in path.split(':') {
                let d = d.trim();
                if !d.is_empty() {
                    dirs.push(d.to_string());
                }
            }
        }
        for d in [
            "/sbin", "/usr/sbin", "/bin", "/usr/bin",
            "/usr/local/sbin", "/usr/local/bin",
            "/usr/lib/systemd", "/lib/systemd", "/usr/lib", "/lib",
        ] {
            let d = d.to_string();
            if !dirs.contains(&d) {
                dirs.push(d);
            }
        }
        dirs
    }

    // ── DPI → dir_policies BPF map ──

    /// Remove all entries from the dir_policies BPF map.
    fn clear_dir_policies_bpf(&self) {
        let mut keys = self.active_dir_keys.lock().unwrap();
        if keys.is_empty() {
            return;
        }
        let mut loader = match self.loader.lock() {
            Ok(l) => l,
            Err(_) => return,
        };
        let bpf = match loader.file_bpf_mut() {
            Some(b) => b,
            None => return,
        };
        let map_data = match bpf.map_mut("dir_policies") {
            Some(m) => m,
            None => return,
        };
        let mut dir_policies = match AyaHashMap::<_, DirKey, DirPolicy>::try_from(map_data) {
            Ok(m) => m,
            Err(_) => return,
        };
        for key in keys.iter() {
            let _ = dir_policies.remove(key);
        }
        keys.clear();
    }

    /// Write a single DirPolicy entry to the dir_policies BPF map.
    fn write_dir_policy_bpf(&self, key: DirKey, policy: DirPolicy) {
        let mut loader = match self.loader.lock() {
            Ok(l) => l,
            Err(e) => { warn!("[EbpfBackend] DPI lock error: {}", e); return; }
        };
        let bpf = match loader.file_bpf_mut() {
            Some(b) => b,
            None => { warn!("[EbpfBackend] DPI: file_bpf not loaded"); return; }
        };
        let map_data = match bpf.map_mut("dir_policies") {
            Some(m) => m,
            None => { warn!("[EbpfBackend] DPI: dir_policies map unavailable"); return; }
        };
        let mut dir_policies = match AyaHashMap::<_, DirKey, DirPolicy>::try_from(map_data) {
            Ok(m) => m,
            Err(e) => { warn!("[EbpfBackend] DPI: try_from failed: {}", e); return; }
        };
        match dir_policies.insert(key, policy, 0) {
            Ok(_) => {
                self.active_dir_keys.lock().unwrap().push(key);
                info!("[EbpfBackend] DPI: wrote dir_policy dev={} inode={} ops_mask={} action={} rec={} ft={}",
                    key.dev, key.inode, policy.ops_mask, policy.action, policy.recursive, policy.filter_type);
            }
            Err(e) => warn!("[EbpfBackend] DPI: insert dir_policy failed: {}", e),
        }
    }

    /// Parse accumulated patterns+rules, match them, resolve directories,
    /// and write DirPolicy entries to the BPF map.
    fn commit_dpi_to_bpf(&self) -> Result<(), String> {
        let pat_text = self.dpi_pat_buffer.lock().unwrap().clone();
        let rule_text = self.dpi_rule_buffer.lock().unwrap().clone();
        if pat_text.is_empty() && rule_text.is_empty() {
            return Ok(());
        }

        let patterns = dpi_parser::parse_patterns(&pat_text);
        let rules = dpi_parser::parse_rules(&rule_text);
        info!("[EbpfBackend] DPI commit: {} patterns, {} rules parsed", patterns.len(), rules.len());

        let entries = dpi_parser::match_patterns_to_rules(&patterns, &rules);
        info!("[EbpfBackend] DPI commit: {} dir_policy entries resolved", entries.len());

        for entry in &entries {
            self.write_dir_policy_bpf(entry.key, entry.policy);
        }
        Ok(())
    }

    /// 按 hash 删除 proc_rule（从 proc_rules map 中移除所有匹配 inode）
    fn remove_proc_rule_by_hash(&self, hash: &str) -> anyhow::Result<()> {
        let md5_map = self.md5_map.read().unwrap();
        if let Some(entries) = md5_map.get(hash) {
            let mut loader = self.loader.lock().unwrap();
            let bpf = loader.proc_bpf_mut().ok_or_else(|| anyhow::anyhow!("Proc agent not loaded"))?;
            let mut proc_rules: AyaHashMap<_, ProcKey, ProcRuleVal> =
                AyaHashMap::try_from(bpf.map_mut("proc_rules").unwrap())?;
            for e in entries {
                proc_rules.remove(&ProcKey { dev: e.dev as u32, inode: e.inode })?;
            }
        }
        Ok(())
    }

    /// 不明进程首次命中时，通过 (dev,inode) → MD5 → 全量黑白名单表查找，
    /// 若命中则即时补写 proc_rules 并同步 BPF。
    /// 查找优先级：pending_rules → process_cache (白名单→黑名单) → 真未知
    /// 返回 Some(action): 0=白名单, 1=黑名单（已同步 BPF，不应重复上报 autoupload）
    /// 返回 None: 真正的不明进程（需正常上报 + autoupload）
    fn try_resolve_pending_rule(&self, key: (u64, u64), hash: &str, path: &str) -> Option<u8> {
        // 1. 优先查 pending_rules（尚未 applied 的增量规则）
        let action = {
            let guard = match self.pending_rules.lock() {
                Ok(g) => g,
                Err(e) => {
                    log::error!("[EbpfBackend] ❌ pending_rules mutex poisoned! recovering... err={}", e);
                    e.into_inner()
                }
            };
            guard.get(hash).copied()
        };
        let (pending_len, cache_white_len, cache_black_len) = {
            let pr = match self.pending_rules.lock() {
                Ok(g) => g,
                Err(e) => { log::error!("[EbpfBackend] ❌ pending_rules mutex poisoned (len) err={}", e); e.into_inner() }
            };
            let pc = match self.process_cache.lock() {
                Ok(g) => g,
                Err(e) => { log::error!("[EbpfBackend] ❌ process_cache mutex poisoned (len) err={}", e); e.into_inner() }
            };
            (pr.len(), pc.0.len(), pc.1.len())
        };
        log::info!("[EbpfBackend] 🔎 try_resolve: hash={} path={} pending_hit={:?} pending_len={} cache_white_len={} cache_black_len={}",
            hash, path, action, pending_len, cache_white_len, cache_black_len);

        // 2. pending 中没有 → 查 process_cache 全量黑白名单
        let action = match action {
            Some(a) => Some(a),
            None => {
                let cache = match self.process_cache.lock() {
                    Ok(g) => g,
                    Err(e) => {
                        log::error!("[EbpfBackend] ❌ process_cache mutex poisoned! recovering... err={}", e);
                        e.into_inner()
                    }
                };
                if cache.0.iter().any(|h| h == hash) {
                    Some(0u8) // 白名单
                } else if cache.1.iter().any(|h| h == hash) {
                    Some(1u8) // 黑名单
                } else {
                    None // 真未知
                }
            }
        };

        let action = match action {
            Some(a) => a,
            None => return None, // 不在任何名单：真正的不明进程
        };

        // 3. 命中黑白名单 → 把同 MD5 的所有已知 (dev,inode) 都补写入 BPF proc_rules
        //    不仅当前命中这对，md5_map 中同一 MD5 的其他 (dev,inode) 也必须覆盖，
        //    否则同一二进制在不同 mount ns / overlay 路径执行时仍会被当作未知进程。
        let (dev, inode) = key;
        let mode = if self.proc_protect { 2u8 } else { 1u8 };
        if let Err(e) = self.add_proc_rule_by_inode(dev as u32, inode, action, mode) {
            log::warn!("[EbpfBackend] 补写 proc_rules 失败 (当前 key): {}", e);
        }
        // 先把当前 (dev,inode) 写入 md5_map，再读取全量条目一次性补写
        if !path.is_empty() {
            let clean_path = {
                let mut slash_count = 0u32;
                let mut cut_pos = 0usize;
                for (i, c) in path.char_indices() {
                    if c == '/' {
                        slash_count += 1;
                        if slash_count == 4 {
                            cut_pos = i + 1;
                            break;
                        }
                    }
                }
                if cut_pos > 0 && cut_pos < path.len() {
                    path[cut_pos..].to_string()
                } else {
                    path.to_string()
                }
            };
            match self.md5_map.write() {
                Ok(mut map) => {
                    map.entry(hash.to_string()).or_insert_with(Vec::new)
                        .push(Md5Entry { inode, dev, path: clean_path.clone() });
                }
                Err(e) => {
                    log::error!("[EbpfBackend] ❌ md5_map mutex poisoned! recovering... err={}", e);
                    let mut map = e.into_inner();
                    map.entry(hash.to_string()).or_insert_with(Vec::new)
                        .push(Md5Entry { inode, dev, path: clean_path.clone() });
                }
            }
            local_store::md5_inode_cache::persist_if_enabled(hash, &clean_path);
        }
        // 读取 md5_map 中该 MD5 的全部 (dev,inode)，批量补写 BPF proc_rules
        {
            let md5_map = match self.md5_map.read() {
                Ok(g) => g,
                Err(e) => { log::error!("[EbpfBackend] ❌ md5_map read poisoned (batch补写), recovering"); e.into_inner() }
            };
            if let Some(entries) = md5_map.get(hash) {
                let mut written = 0;
                for entry in entries {
                    if entry.dev as u64 == dev && entry.inode == inode {
                        continue; // 当前 key 已写过，跳过
                    }
                    if let Err(err) = self.add_proc_rule_by_inode(entry.dev as u32, entry.inode, action, mode) {
                        log::warn!("[EbpfBackend] 批量补写 proc_rules 失败: dev={} inode={} err={}", entry.dev, entry.inode, err);
                    } else {
                        written += 1;
                    }
                }
                if written > 0 {
                    log::info!("[EbpfBackend] 🔎 同 MD5 批量补写 {} 条 proc_rules (hash={})", written, &hash[..8.min(hash.len())]);
                }
            }
        }
        {
            let mut pr = match self.pending_rules.lock() {
                Ok(g) => g,
                Err(e) => { log::error!("[EbpfBackend] ❌ pending_rules mutex poisoned (remove) err={}", e); e.into_inner() }
            };
            pr.remove(hash);
        }
        {
            let mut ar = match self.applied_rules.lock() {
                Ok(g) => g,
                Err(e) => { log::error!("[EbpfBackend] ❌ applied_rules mutex poisoned (insert) err={}", e); e.into_inner() }
            };
            ar.insert(hash.to_string(), action);
        }

        let kind = if action == 0 { "白名单" } else { "黑名单" };
        log::info!("[EbpfBackend] ✅ 不明进程命中{}，即时补写 proc_rules: dev={} inode={} path={} action={}",
            kind, dev, inode, path, action);
        Some(action)
    }

    /// 将 pending_rules 中已有 md5_map 的条目重新下发，
    /// 同时扫描 applied_rules：若某 MD5 在 md5_map 中有新增 (dev,inode) 但尚未写入 BPF，也补写。
    fn replay_pending_rules(&self) {
        let mut pending = match self.pending_rules.lock() {
            Ok(g) => g,
            Err(e) => { log::error!("[EbpfBackend] ❌ pending_rules mutex poisoned (replay), recovering"); e.into_inner() }
        };
        let md5_map = match self.md5_map.read() {
            Ok(g) => g,
            Err(e) => { log::error!("[EbpfBackend] ❌ md5_map mutex poisoned (replay), recovering"); e.into_inner() }
        };
        let mode = if self.proc_protect { 2u8 } else { 1u8 };

        // 1. 处理 pending_rules（之前 md5_map 里没有的 MD5）
        let mut replayed = 0;
        let to_remove: Vec<String> = pending.iter()
            .filter_map(|(hash, action)| {
                if let Some(entries) = md5_map.get(hash.as_str()) {
                    for e in entries {
                        let _ = self.add_proc_rule_by_inode(e.dev as u32, e.inode, *action, mode);
                    }
                    replayed += 1;
                    Some(hash.clone())
                } else { None }
            })
            .collect();
        for h in &to_remove { pending.remove(h); }

        // 2. 扫描 applied_rules：同一 MD5 新增的 (dev,inode) 也要补写 BPF
        //    场景：规则下发时 md5_map 只有部分映射，后续扫描/运行时发现同一二进制的新身份
        let mut patched = 0u32;
        {
            let applied = match self.applied_rules.lock() {
                Ok(g) => g,
                Err(e) => { log::error!("[EbpfBackend] ❌ applied_rules mutex poisoned (replay), recovering"); e.into_inner() }
            };
            for (hash, &action) in applied.iter() {
                if let Some(entries) = md5_map.get(hash.as_str()) {
                    for e in entries {
                        if self.add_proc_rule_by_inode(e.dev as u32, e.inode, action, mode).is_ok() {
                            patched += 1;
                        }
                    }
                }
            }
        }

        drop(md5_map);

        if replayed > 0 || patched > 0 {
            info!("[EbpfBackend] replay_pending_rules: pending补写 {} 条 (剩余 {} 条), applied补写 {} 条",
                replayed, pending.len(), patched);
        }
        self.enable_proc_detection();
    }

    /// 启动时枚举所有运行中进程（含容器/其它 mount ns 进程），用 /proc/<pid>/exe
    /// 拿到每个进程可执行文件的 (dev,inode) 与内容 MD5，预填 inode_md5_map。
    /// 这样容器里已运行的二进制，后续 exec 时能直接命中缓存，不再依赖
    /// /proc/<pid>/root 的瞬时进程时序（瞬时进程秒退时可能读不到）。
    /// 只补空位，不覆盖扫描目录/DB 已填的宿主条目。
    pub fn scan_running_processes(&self) -> anyhow::Result<usize> {
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;
        let mut recs: Vec<((u64, u64), InodeMd5Rec)> = Vec::new();
        for entry in std::fs::read_dir("/proc")?.flatten() {
            let pid: u32 = match entry.file_name().to_string_lossy().parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            // 进程全路径：readlink 只取路径字符串，不据此取 inode/dev。
            let exe_link = format!("/proc/{}/exe", pid);
            let full_path = match std::fs::read_link(&exe_link) {
                Ok(p) => p.to_string_lossy().into_owned(),
                Err(_) => continue, // 内核线程/无权限/已退出
            };
            if !full_path.starts_with('/') {
                continue;
            }

            // 先按宿主路径 stat，再按进程命名空间 stat（/proc/<pid>/root/<full_path>）：
            // 二者 (dev,inode) 相同 → 宿主机；不同 → 容器/其它 ns（路径只是容器 root 的后缀）。
            let host_meta = std::fs::metadata(&full_path).ok();
            let ns_path = format!("/proc/{}/root{}", pid, full_path);
            let ns_meta = std::fs::metadata(&ns_path).ok();

            // 选定「真正的那份文件」的来源路径，并标记是否容器（容器条目 mtime=0，不参与失效校验）。
            // 存储路径统一为容器内逻辑路径（如 /bin/ls），不含 /proc/<pid>/root 前缀。
            let (src_path, is_container, store_path) = match (&host_meta, &ns_meta) {
                (Some(h), Some(n)) if (h.dev(), h.ino()) == (n.dev(), n.ino()) => {
                    (full_path.as_str(), false, full_path.clone())
                }
                (_, Some(_)) => {
                    // 容器进程：full_path 已是容器内逻辑路径（readlink 返回 ns 视角）
                    (ns_path.as_str(), true, full_path.clone())
                }
                (Some(_), None) => (full_path.as_str(), false, full_path.clone()),
                _ => continue,
            };

            // 在选定路径上 open 一次，fstat + read 用同一个 fd，避免 stat 与 read 之间竞态。
            let mut f = match std::fs::File::open(src_path) {
                Ok(f) => f,
                Err(_) => continue,
            };
            let meta = match f.metadata() {
                Ok(m) if m.is_file() => m,
                _ => continue,
            };
            let key = (meta.dev(), meta.ino());
            if self.inode_md5_map.read().unwrap().contains_key(&key) {
                continue; // 目录扫描已覆盖
            }
            let mut data = Vec::new();
            if f.read_to_end(&mut data).is_err() {
                continue;
            }
            let hash = hex::encode(md5::compute(&data).0);
            let mtime = if is_container {
                0
            } else {
                meta.modified().ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs()).unwrap_or(0)
            };
            recs.push((key, InodeMd5Rec { md5: hash, mtime, path: store_path }));
        }
        let mut added = 0usize;
        {
            let mut imap = self.inode_md5_map.write().unwrap();
            for (k, rec) in recs {
                if !imap.contains_key(&k) {
                    imap.insert(k, rec);
                    added += 1;
                }
            }
        }
        info!("[EbpfBackend] 枚举运行进程，预填 inode_md5_map {} 条", added);
        Ok(added)
    }

    pub fn scan_executables(&self, dirs: &[String], recursive: bool) -> anyhow::Result<usize> {
        use std::os::unix::fs::MetadataExt;
        // 先在本地累积，最后一次性批量入表：避免整个扫描期间持有写锁，
        // 阻塞进程事件路径上的 inode_md5_map 查表。
        let mut md5_entries: Vec<(String, Md5Entry)> = Vec::new();
        let mut inode_recs: Vec<((u64, u64), InodeMd5Rec)> = Vec::new();
        let mut path_cache_entries: Vec<(String, (String, u64))> = Vec::new();
        let mut count = 0usize;
        for dir in dirs {
            let walker = if recursive { walkdir::WalkDir::new(dir) } else { walkdir::WalkDir::new(dir).max_depth(1) };
            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                let path = entry.path();
                if !path.is_file() { continue; }
                let path_str = path.to_string_lossy().to_string();
                if let Ok(data) = std::fs::read(path) {
                    if data.len() < 4 || &data[..4] != b"\x7fELF" { continue; }
                } else { continue; }
                if let Ok(data) = std::fs::read(path) {
                    let hash = hex::encode(md5::compute(&data).0);
                    let meta = match std::fs::metadata(path) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    let mtime = meta.modified().ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d: std::time::Duration| d.as_secs())
                        .unwrap_or(0);
                    let key = (meta.dev(), meta.ino());
                    path_cache_entries.push((path_str.clone(), (hash.clone(), mtime)));
                    md5_entries.push((hash.clone(), Md5Entry { inode: key.1, dev: key.0, path: path_str.clone() }));
                    inode_recs.push((key, InodeMd5Rec { md5: hash, mtime, path: path_str }));
                    count += 1;
                }
            }
        }
        // 批量入表（短临界区）
        {
            let mut map = self.md5_map.write().unwrap();
            for (hash, entry) in &md5_entries {
                map.entry(hash.clone()).or_insert_with(Vec::new).push(entry.clone());
            }
            let mut imap = self.inode_md5_map.write().unwrap();
            for (key, rec) in inode_recs {
                imap.insert(key, rec);
            }
            let mut path_cache = self.path_hash_cache.write().unwrap();
            for (p, v) in path_cache_entries {
                path_cache.insert(p, v);
            }
        }
        info!("[EbpfBackend] Scanned {} executables, {} unique MD5s, {} unique inodes",
            count, self.md5_map.read().unwrap().len(), self.inode_md5_map.read().unwrap().len());
        self.replay_pending_rules();
        Ok(count)
    }

    /// 启动时从 DB 加载历史「非扫描目录」可执行文件，重建 md5_map。
    /// 对每条 hash→path 重新 stat 得到当前 (dev,inode)，并重新校验文件 MD5 仍等于 hash，
    /// 避免文件被升级替换后沿用旧 hash 误放行。加载完调用 replay_pending_rules 补写待下发规则。
    pub fn load_md5_inode_cache(&self) -> anyhow::Result<usize> {
        let entries = local_store::md5_inode_cache::load_if_enabled();
        if entries.is_empty() {
            return Ok(0);
        }

        let mut map = self.md5_map.write().unwrap();
        let mut path_cache = self.path_hash_cache.write().unwrap();
        let mut count = 0usize;
        for (hash, path) in entries {
            if !path.starts_with('/') {
                continue; // 相对路径无法可靠重建，跳过
            }
            let Ok(data) = std::fs::read(&path) else { continue; };
            if data.len() < 4 || &data[..4] != b"\x7fELF" {
                continue; // 非 ELF，跳过
            }
            let actual = hex::encode(md5::compute(&data).0);
            if actual != hash {
                continue; // 文件内容已变化，跳过避免误放行
            }
            use std::os::unix::fs::MetadataExt;
            let Ok(md) = std::fs::metadata(&path) else { continue; };
            let mtime = md.modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d: std::time::Duration| d.as_secs())
                .unwrap_or(0);
            path_cache.insert(path.clone(), (hash.clone(), mtime));
            map.entry(hash.clone()).or_insert_with(Vec::new)
                .push(Md5Entry { inode: md.ino(), dev: md.dev(), path: path.clone() });
            self.inode_md5_map.write().unwrap()
                .insert((md.dev(), md.ino()), InodeMd5Rec { md5: hash, mtime, path });
            count += 1;
        }
        drop(map); // 释放写锁，让 replay_pending_rules 可以获取读锁
        drop(path_cache);

        if count > 0 {
            info!("[EbpfBackend] 从 DB 加载 {} 条非扫描目录可执行文件到 md5_map", count);
            self.replay_pending_rules();
        }
        Ok(count)
    }

    /// 容器进程按需补扫：300 秒内不重复扫描，防止高频触发。
    /// 扫描结果回写 md5_map/inode_md5_map，后续同容器进程 exec 直接命中缓存。
    pub fn maybe_rescan_container_overlays(&self) {
        use std::sync::atomic::Ordering;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let last = self.last_overlay_rescan.load(Ordering::Relaxed);
        if now.saturating_sub(last) < 300 {
            return; // 5 分钟内已扫过，跳过
        }
        self.last_overlay_rescan.store(now, Ordering::Relaxed);
        match self.scan_container_overlays() {
            Ok(0) => {}
            Ok(n) => info!("[EbpfBackend] 按需补扫容器 overlay: {} 个文件", n),
            Err(e) => warn!("[EbpfBackend] 按需补扫容器 overlay 失败: {}", e),
        }
    }

    /// 扫描容器 overlay rootfs 中的可执行文件，计算 MD5 填充 md5_map + inode_md5_map。
    /// 路径存储为容器内逻辑路径（如 /bin/ls），不含 overlay 前缀。
    /// 枚举 Docker overlay2 + Podman/cri-o overlay 目录下所有 merged/ 子目录。
    pub fn scan_container_overlays(&self) -> anyhow::Result<usize> {
        use std::os::unix::fs::MetadataExt;

        // 容器 overlay 根目录模式
        let overlay_roots: &[&str] = &[
            "/var/lib/docker/overlay2",
            "/var/lib/containers/storage/overlay",
            "/var/lib/containerd/io.containerd.snapshot.v1.overlayfs/snapshots",
        ];

        let mut merged_dirs: Vec<String> = Vec::new();
        for root in overlay_roots {
            if let Ok(entries) = std::fs::read_dir(root) {
                for entry in entries.flatten() {
                    // Docker: overlay2/<id>/merged (union mount point, 可读)
                    let merged = entry.path().join("merged");
                    if merged.is_dir() {
                        merged_dirs.push(merged.to_string_lossy().into_owned());
                    }
                    // containerd: snapshots/<id>/fs/ (可读)
                    let fs_dir = entry.path().join("fs");
                    if fs_dir.is_dir() {
                        merged_dirs.push(fs_dir.to_string_lossy().into_owned());
                    }
                    // 注意: Podman/CRI-O 的 diff 目录只是 upper layer，
                    // 不含 lower layer 的文件（如 busybox 二进制），跳过。
                }
            }
        }

        if merged_dirs.is_empty() {
            info!("[EbpfBackend] 未发现容器 overlay 目录，跳过容器扫描");
            return Ok(0);
        }

        info!("[EbpfBackend] 发现 {} 个容器 rootfs 目录，开始扫描", merged_dirs.len());
        for (i, d) in merged_dirs.iter().enumerate() {
            info!("[EbpfBackend]   容器[{}]: {}", i, d);
        }

        // 宿主标准扫描目录前缀（容器内也有这些目录，避免重复）
        let std_subdirs: &[&str] = &["bin", "sbin", "usr/bin", "usr/sbin", "usr/local/bin"];

        let mut md5_entries: Vec<(String, Md5Entry)> = Vec::new();
        let mut inode_recs: Vec<((u64, u64), InodeMd5Rec)> = Vec::new();
        let mut path_cache_entries: Vec<(String, (String, u64))> = Vec::new();
        let mut count = 0usize;
        let mut host_dup_count = 0usize; // 与宿主机 MD5 相同的文件数

        for merged_dir in &merged_dirs {
            // 打印容器 overlay 下的目录结构，便于排查
            if let Ok(entries) = std::fs::read_dir(merged_dir) {
                let dirs: Vec<String> = entries.flatten()
                    .filter(|e| e.path().is_dir())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect();
                info!("[EbpfBackend]   容器 {} 下的目录: {:?}", merged_dir, dirs);
            }
            for subdir in std_subdirs {
                let scan_dir = format!("{}/{}", merged_dir, subdir);
                if !std::path::Path::new(&scan_dir).is_dir() {
                    continue;
                }
                let walker = walkdir::WalkDir::new(&scan_dir)
                    .follow_links(false)
                    .max_depth(3);
                for entry in walker.into_iter().filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if !path.is_file() { continue; }
                    // 只保留 ELF 文件
                    if let Ok(data) = std::fs::read(path) {
                        if data.len() < 4 || &data[..4] != b"\x7fELF" { continue; }
                    } else { continue; }

                    let full_path_str = path.to_string_lossy().to_string();

                    // 计算 MD5
                    let Ok(data) = std::fs::read(path) else { continue; };
                    let hash = hex::encode(md5::compute(&data).0);

                    // 取 (dev, inode)
                    let Ok(meta) = std::fs::metadata(path) else { continue; };
                    let key = (meta.dev(), meta.ino());

                    // 路径 strip: 去掉 overlay 前缀，保留容器内逻辑路径
                    // /var/lib/docker/overlay2/xxx/merged/bin/ls → /bin/ls
                    let container_path = merged_dirs.iter()
                        .find_map(|md| full_path_str.strip_prefix(md))
                        .unwrap_or(&full_path_str);

                    // 检测与宿主机 MD5 重复（md5_map 已有此 hash）
                    let md5_map = self.md5_map.read().unwrap();
                    let is_host_dup = md5_map.contains_key(&hash);
                    drop(md5_map);

                    if is_host_dup {
                        host_dup_count += 1;
                        info!("[EbpfBackend]   🔗 容器文件与宿主机 MD5 相同: {} hash={} dev={} inode={}",
                            container_path, hash, key.0, key.1);
                    }

                    let mtime = 0; // 容器条目 mtime=0，不参与失效校验

                    md5_entries.push((hash.clone(), Md5Entry {
                        inode: key.1, dev: key.0, path: container_path.to_string(),
                    }));
                    inode_recs.push((key, InodeMd5Rec {
                        md5: hash.clone(), mtime, path: container_path.to_string(),
                    }));
                    path_cache_entries.push((full_path_str, (hash, mtime)));
                    count += 1;
                }
            }
        }

        // 批量入表
        {
            let mut map = self.md5_map.write().unwrap();
            for (hash, entry) in &md5_entries {
                map.entry(hash.clone()).or_insert_with(Vec::new).push(entry.clone());
            }
            let mut imap = self.inode_md5_map.write().unwrap();
            for (key, rec) in inode_recs {
                imap.insert(key, rec);
            }
            let mut path_cache = self.path_hash_cache.write().unwrap();
            for (p, v) in path_cache_entries {
                path_cache.insert(p, v);
            }
        }

        info!("[EbpfBackend] 容器 overlay 扫描完成: {} 个文件, {} 个 unique MD5, {} 个与宿主机重复",
            count, self.md5_map.read().unwrap().len(), host_dup_count);
        self.replay_pending_rules();
        Ok(count)
    }

    /// 上报自保目录保护告警（/opt/osec 等自保目录被操作）。
    /// 自保事件仅在自保开关开启且命中保护目录时产生，固定 n_level=3（保护）。
    /// 复用现有 AuditLogInfo 上报链路（broadcast + HTTP /v1/alertupload）。
    fn report_self_protect_event(&self, path: &str, comm: &str, pid: u32, uid: u32, op_type: u8) {
        let type_idx = Self::op_type_to_idx(op_type);
        let n_type = WARN_LOG_TYPE[1][1][type_idx]; // 目录保护 → 210x
        let md5_hash = self.get_md5_cached(path);
        let log = reporter::AuditLogInfo {
            file_path: Some(path.to_string()),
            md5: md5_hash,
            n_type,
            n_level: 3,
            n_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
            rename_dir: None,
            notice_remark: Some(format!("eBPF自保保护: pid={} uid={} op=0x{:02X}", pid, uid, op_type)),
            exception_process: Some(comm.to_string()),
            peripheral_name: None, peripheral_remark: None, peripheral_eid: None,
            p_param: Some(path.to_string()),
        };
        log::warn!("[EbpfBackend] 🛡️ 自保目录命中: path={} comm={} pid={} op_type=0x{:02X} n_type={}",
            path, comm, pid, op_type, n_type);
        reporter::broadcast_audit_log(&log);
        reporter::send_to_http_upload(&log);
    }

    /// 自保专用目录保护（与 DPI dir_policies 完全独立）。
    fn write_self_protect_dirs(&self, enabled: bool) -> Result<(), String> {
        let mut loader = self.loader.lock().map_err(|e| e.to_string())?;
        let bpf = loader.file_bpf_mut()
            .ok_or_else(|| "file_agent not loaded".to_string())?;
        let map_data = bpf.map_mut("self_protect_dirs")
            .ok_or_else(|| "self_protect_dirs map unavailable".to_string())?;
        let mut map = AyaHashMap::<_, DirKey, SelfProtectRule>::try_from(map_data)
            .map_err(|e| e.to_string())?;

        for (path, whole_dir, prefixes) in SELF_PROTECT_DIRS {
            let key = match dpi_parser::resolve_dir_to_key(path) {
                Some(k) => k,
                None => { warn!("[EbpfBackend] 自保目录不存在，跳过: {}", path); continue; }
            };
            if enabled {
                let rule = if *whole_dir { SelfProtectRule::whole_dir() }
                           else { SelfProtectRule::with_prefixes(prefixes) };
                map.insert(key, rule, 0).map_err(|e| e.to_string())?;
                info!("[EbpfBackend] 🛡️ 自保目录保护: {} dev={} inode={} whole_dir={}",
                    path, key.dev, key.inode, whole_dir);
            } else {
                let _ = map.remove(&key);
                info!("[EbpfBackend] 自保目录保护移除: {}", path);
            }
        }
        Ok(())
    }
}

// ── SecurityBackend impl ──

impl SecurityBackend for EbpfBackend {
    fn is_active(&self) -> bool { self.file_loaded || self.proc_loaded || self.net_loaded }
    fn name(&self) -> &str { "ebpf" }

    // 进程
    fn add_md5_rules(&self, data: &str) -> Result<(), String> {
        // data 格式: "{hash}=0\n" (白) / "{hash}=1\n" (黑) / "del 0 {hash}\n" (删白) / "del 1 {hash}\n" (删黑)
        // eBPF 模式下，path 字段实际存的是 MD5 hash，需要查 md5_map 转换为 inode 后写入 BPF map
        // 注意：批处理可能混合「新增 + 删除 + 黑↔白互转」，必须逐行解析 action，不能按整批判断黑白。
        // mode: 1=监控(MONITOR) 2=保护(PROTECT)，由 PROC_PROTECT/FILE_PROTECT 控制
        let mode = if self.proc_protect { 2u8 } else { 1u8 };
        let md5_map = self.md5_map.read().unwrap();
        let mut applied = 0;
        let mut pending = 0;

        for raw in data.lines() {
            let line = raw.trim();
            if line.is_empty() { continue; }

            // 删除: "del 0 {hash}" / "del 1 {hash}"
            if let Some(stripped) = line.strip_prefix("del ") {
                let mut parts = stripped.split_whitespace();
                let which = parts.next(); // "0"=白, "1"=黑
                let Some(h) = parts.next() else { continue; };
                let _ = self.remove_proc_rule_by_hash(h);
                self.pending_rules.lock().unwrap().remove(h);
                self.applied_rules.lock().unwrap().remove(h);
                let mut cache = self.process_cache.lock().unwrap();
                if which == Some("0") { cache.0.retain(|x| x != h); }
                else { cache.1.retain(|x| x != h); }
                continue;
            }

            // 新增/覆盖: "{hash}=0" (白) / "{hash}=1" (黑)
            let Some(idx) = line.find('=') else { continue; };
            let hash = &line[..idx];
            let action = if line[idx + 1..].starts_with('0') { 0u8 } else { 1u8 };

            if let Some(entries) = md5_map.get(hash) {
                for e in entries {
                    let _ = self.add_proc_rule_by_inode(e.dev as u32, e.inode, action, mode);
                }
                self.applied_rules.lock().unwrap().insert(hash.to_string(), action);
                applied += 1;
            } else {
                // md5_map 尚未包含此 hash，暂存到 pending_rules，等扫描填充后补写
                self.pending_rules.lock().unwrap().insert(hash.to_string(), action);
                pending += 1;
            }

            // 同步 process_cache（追加，不整体覆盖）
            if action == 0 {
                self.process_cache.lock().unwrap().0.push(hash.to_string());
            } else {
                self.process_cache.lock().unwrap().1.push(hash.to_string());
            }
        }

        //log::info!("[EbpfBackend] add_md5_rules: 已下发 {} 条, 待扫描 {} 条", applied, pending);
        // 有规则真正写入 proc_rules（在线 push 且 md5_map 已就绪）→ 首次加载完成，开启进程检测
        if applied > 0 {
            self.enable_proc_detection();
        }
        Ok(())
    }

    fn notify_process_update(&self) -> Result<(), String> {
        // 进程策略「加载/应用」完成信号：此刻若没有任何待补写规则（pending_rules 空），
        // 说明要么是空策略、要么规则已直接写入 proc_rules（在线且 md5_map 就绪），
        // 可立即开启进程检测。非空离线策略此时 pending 非空，等扫描后 replay_pending_rules 再开。
        let pending_empty = self.pending_rules.lock().unwrap().is_empty();
        if pending_empty {
            self.enable_proc_detection();
        }
        Ok(())
    }

    fn get_process_whitelist(&self) -> Vec<String> {
        self.process_cache.lock().unwrap().0.clone()
    }
    fn get_process_blacklist(&self) -> Vec<String> {
        self.process_cache.lock().unwrap().1.clone()
    }

    fn query_process_rule(&self, path: &str, dev: u64, inode: u64) -> Result<common::backend::ProcRuleQueryResult, String> {
        let mut result = common::backend::ProcRuleQueryResult { action: -1, ..Default::default() };

        // 1. 确定 (dev, inode)：显式 dev/inode 优先，否则从 path 解析（相对路径先 canonicalize）
        let key = if dev != 0 || inode != 0 {
            ProcKey { dev: dev as u32, inode }
        } else {
            let resolved = std::fs::canonicalize(path)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| path.to_string());
            result.resolved_path = resolved.clone();
            match stat_path_to_proc_key(&resolved) {
                Some(k) => k,
                None => {
                    result.message = format!("无法 stat 路径（不存在或非普通文件）: {}", resolved);
                    return Ok(result);
                }
            }
        };
        if result.resolved_path.is_empty() {
            result.resolved_path = path.to_string();
        }
        result.dev = key.dev as u64;
        result.inode = key.inode;

        // 2. 查 proc_rules map（key=(dev,inode)，value.action: 0=allow/白, 1=deny/黑）
        let mut loader = self.loader.lock().map_err(|e| e.to_string())?;
        let bpf = loader.proc_bpf_mut().ok_or_else(|| "Proc agent not loaded".to_string())?;
        let map_data = bpf.map_mut("proc_rules").ok_or_else(|| "proc_rules map not found".to_string())?;
        let proc_rules = AyaHashMap::<_, ProcKey, ProcRuleVal>::try_from(map_data)
            .map_err(|e| e.to_string())?;
        let (k_dev, k_ino) = (key.dev, key.inode);
        match proc_rules.get(&key, 0) {
            Ok(val) => {
                result.found = true;
                result.action = val.action() as i32;
                result.mode = val.mode() as i32;
                let kind = if val.action() == 0 { "白名单(allow)" } else { "黑名单(deny)" };
                result.message = format!("命中 {} dev={} inode={} mode={}", kind, k_dev, k_ino, val.mode());
            }
            Err(aya::maps::MapError::KeyNotFound) => {
                result.message = format!("未命中 proc_rules dev={} inode={}", k_dev, k_ino);
            }
            Err(e) => return Err(format!("查询 proc_rules 失败: {}", e)),
        }
        Ok(result)
    }

    fn lookup_hash_paths(&self, hash: &str) -> Vec<String> {
        let md5_map = self.md5_map.read().unwrap();
        md5_map.get(hash)
            .map(|entries| entries.iter().map(|e| e.path.clone()).collect())
            .unwrap_or_default()
    }

    fn get_executable_overlay_roots(&self) -> Vec<String> {
        let overlay_roots: &[&str] = &[
            "/var/lib/docker/overlay2",
            "/var/lib/containers/storage/overlay",
            "/var/lib/containerd/io.containerd.snapshot.v1.overlayfs/snapshots",
        ];
        let mut merged_dirs = Vec::new();
        for root in overlay_roots {
            if let Ok(entries) = std::fs::read_dir(root) {
                for entry in entries.flatten() {
                    let merged = entry.path().join("merged");
                    if merged.is_dir() {
                        merged_dirs.push(merged.to_string_lossy().into_owned());
                    }
                    let fs_dir = entry.path().join("fs");
                    if fs_dir.is_dir() {
                        merged_dirs.push(fs_dir.to_string_lossy().into_owned());
                    }
                }
            }
        }
        merged_dirs
    }

    fn trigger_overlay_rescan(&self) {
        self.maybe_rescan_container_overlays();
    }

    // 网络
    fn write_tcp_force_ecn(&self, enable: bool) -> Result<(), String> {
        let mut loader = self.loader.lock().unwrap();
        let bpf = loader.net_bpf_mut().ok_or_else(|| "Net agent not loaded".to_string())?;
        let mut pkt_mod_rules: AyaHashMap<_, PktModKey, PktModValue> =
            AyaHashMap::try_from(bpf.map_mut("pkt_mod_rules").unwrap()).map_err(|e| format!("{}", e))?;

        let key = PktModKey { protocol: 6, direction: 2, padding: [0;2], dst_ip: 0, src_port: 0, dst_port: 0 };
        if enable {
            pkt_mod_rules.insert(key, PktModValue { tcp_flags_enable: 1, tcp_set_ecn_echo: 1, ..Default::default() }, 0).map_err(|e| e.to_string())?;
            info!("[EbpfBackend] ECN-Echo ON");
        } else {
            let _ = pkt_mod_rules.remove(&key);
            info!("[EbpfBackend] ECN-Echo OFF");
        }
        Ok(())
    }

    fn write_ipv4_block_policies(&self, ips: &[String]) -> Result<(), String> {
        // 全量替换语义（对齐驱动 'c' 清空+重写）：本次列表即全部阻断项
        *self.saddr_latest.lock().unwrap() = ips.to_vec();
        self.apply_saddr_blocks()
    }

    fn write_ipv6_block_policies(&self, _ips: &[String]) -> Result<(), String> {
        warn!("[EbpfBackend] IPv6 block not yet supported");
        Ok(())
    }

    /// 网络规则文本下发。
    /// 支持 VIR_OPEN_PORT 行（端口虚开/重定向）与 vir_open_port_switch 总闸，
    /// 语义对齐驱动 net_rules_cmd_parse()；其余行暂不支持，忽略并告警。
    fn write_net_rules(&self, rules: &str) -> Result<(), String> {
        let mut result = Ok(());
        for line in rules.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with("VIR_OPEN_PORT ") {
                match parse_vir_open_port_line(line) {
                    Some((index, total, rule)) => {
                        // 攒批：index==0 重置缓冲（对应驱动 INIT_LIST_HEAD）
                        let flush = {
                            let mut st = self.vir_port_state.lock().unwrap();
                            if index == 0 {
                                st.pending.clear();
                            }
                            st.expect_total = total;
                            if let Some(r) = rule {
                                st.pending.push(r);
                            }
                            total > 0 && index + 1 == total
                        };
                        // index+1==total：整批生效（对应驱动 splice 到 gListTcpPolicy）
                        if flush {
                            let mut st = self.vir_port_state.lock().unwrap();
                            st.latest = std::mem::take(&mut st.pending);
                        }
                        if let Err(e) = self.apply_vir_port_rules() {
                            result = Err(e);
                        }
                    }
                    None => warn!("[EbpfBackend] VIR_OPEN_PORT 行解析失败: {}", line),
                }
                continue;
            }
            if let Some(v) = line.strip_prefix("vir_open_port_switch ") {
                let on = v.trim() != "0";
                self.vir_port_state.lock().unwrap().enabled = Some(on);
                info!("[EbpfBackend] vir_open_port_switch={}", on as u8);
                if let Err(e) = self.apply_vir_port_rules() {
                    result = Err(e);
                }
                continue;
            }
            warn!("[EbpfBackend] write_net_rules 忽略不支持的规则行: {}", line);
        }
        result
    }

    /// 动态阻断总开关（对应驱动 net_block_enable）：0=清空阻断表，1=按最近列表恢复
    fn write_netblock_switch(&self, value: &str) -> Result<(), String> {
        let on = value.trim() != "0";
        self.netblock_enabled.store(on, Ordering::SeqCst);
        info!("[EbpfBackend] write_netblock_switch={}", on as u8);
        self.apply_saddr_blocks()
    }
    fn write_defense_switch(&self, _rule_type: &str, _value: &str) -> Result<(), String> { Ok(()) }

    // DPI — parse pattern/rule text strings, resolve directories to (dev,inode),
    // and write DirPolicy entries into the file_agent's dir_policies BPF map.
    fn write_dpi_file_patterns(&self, data: &str, clear: bool, build: bool) -> Result<(), String> {
        if clear {
            self.dpi_pat_buffer.lock().unwrap().clear();
            self.dpi_rule_buffer.lock().unwrap().clear();
            self.clear_dir_policies_bpf();
        }
        if !data.is_empty() {
            self.dpi_pat_buffer.lock().unwrap().push_str(data);
        }
        if build {
            self.commit_dpi_to_bpf()?;
        }
        Ok(())
    }

    fn write_dpi_rules(&self, data: &str, clear: bool) -> Result<(), String> {
        if clear {
            self.dpi_rule_buffer.lock().unwrap().clear();
        }
        if !data.is_empty() {
            self.dpi_rule_buffer.lock().unwrap().push_str(data);
        }
        Ok(())
    }

    fn write_process_dpi_patterns(&self, data: &str, clear: bool, build: bool) -> Result<(), String> {
        log_info!("[EbpfBackend] write_process_dpi_patterns: clear={} build={} data_len={}",
            clear, build, data.len());
        if clear {
            self.proc_pat_buffer.lock().unwrap().clear();
            self.clear_proc_whitelist_bpf();
        }
        if !data.is_empty() {
            self.proc_pat_buffer.lock().unwrap().push_str(data);
        }
        if build {
            self.commit_proc_whitelist_bpf();
        }
        Ok(())
    }

    fn write_process_dpi_rules(&self, _data: &str, _clear: bool) -> Result<(), String> {
        // 进程信任白名单在 eBPF 模式全部是 ACTION_ALLOW，rule 文本（type=0/1）无额外语义，忽略。
        Ok(())
    }

    fn write_dpi_true_process(&self, data: &str, clear: bool) -> Result<(), String> {
        if clear {
            self.dpi_tp_buffer.lock().unwrap().clear();
        }
        if !data.is_empty() {
            self.dpi_tp_buffer.lock().unwrap().push_str(data);
        }
        Ok(())
    }

    // ── 运行时开关同步到 BPF maps ──
    fn sync_switches(&self, file_switch: bool, proc_switch: bool,
                     file_protect: bool, proc_protect: bool) -> Result<(), String> {
        self.sync_runtime_switches(file_switch, proc_switch, file_protect, proc_protect);
        Ok(())
    }

    // 其他
    fn emit_docker_event(&self, _kind: u8, _flag: u8, _pid: i32) -> Result<(), String> { Ok(()) }
    fn clear_docker_rt(&self) -> Result<(), String> { Ok(()) }
    fn write_business_ports(&self, _ports: &[u16]) -> Result<(), String> { Ok(()) }
    /// 自保开关：防 kill（protected_pids）+ 自保目录保护（self_protect_dirs）。
    /// 自保目录保护走专用 self_protect_dirs map，与 DPI dir_policies 完全独立，
    /// 不依赖 file_switch，也不依赖 token/GLOBAL_PATTERN_MGR。
    fn write_self_protection(&self, num: u32) -> Result<(), String> {
        let enabled = num != 0;
        let agent_pid = std::process::id();
        {
            let mut loader = self.loader.lock().unwrap();
            if let Some(bpf) = loader.proc_bpf_mut() {
                if enabled {
                    ModularLoader::add_protected_pid(bpf, agent_pid)
                        .map_err(|e| format!("protected_pids add failed: {}", e))?;
                    info!("[EbpfBackend] 🛡️ 自保防 kill 已启用: agent PID {} 已加入保护列表", agent_pid);
                } else {
                    ModularLoader::remove_protected_pid(bpf, agent_pid)
                        .map_err(|e| format!("protected_pids remove failed: {}", e))?;
                    info!("[EbpfBackend] 自保防 kill 已禁用: agent PID {} 已移出保护列表", agent_pid);
                }
            }
        }
        self.write_self_protect_dirs(enabled)
    }

    /// 退出清理：显式卸载 XDP/TC 网络管控 eBPF（TC filter 内核态持有 prog 引用，
    /// 不显式卸载会残留并持续拦截流量），再还原 NET_AGENT 挂载时修改的 sysctl
    /// （accept_local / ip_forward）
    fn shutdown(&self) {
        {
            let mut loader = self.loader.lock().unwrap();
            loader.detach_net_programs();
        }
        let st = self.net_sysctl_state.lock().unwrap();
        if let Some(ref s) = *st {
            restore_net_sysctls(s);
        }
    }
}
