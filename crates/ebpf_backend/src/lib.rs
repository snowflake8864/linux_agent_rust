use aya::maps::HashMap as AyaHashMap;
use aya::maps::RingBuf;
use log::{info, warn};
use logging::log_info;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

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
    proc_switch: bool,
    /// 防护模式 (对应 *_PROTECT 配置): false=监控, true=保护
    file_protect: bool,
    proc_protect: bool,
    pub interface: String,
    pub engine: String,
    /// MD5 → [(dev, inode, path)] 映射（后台扫描填充）
    pub md5_map: Arc<RwLock<std::collections::HashMap<String, Vec<Md5Entry>>>>,
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
}

#[derive(Debug, Clone)]
pub struct Md5Entry {
    pub inode: u64,
    pub dev: u64,
    pub path: String,
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
    Some(ProcKey { dev: meta.st_dev(), inode: meta.st_ino() })
}

impl EbpfBackend {
    pub fn new(
        bpf_dir: &str,
        file_enabled: bool, file_switch: bool, file_protect: bool,
        proc_enabled: bool, proc_switch: bool, proc_protect: bool,
        net_enabled: bool,
        interface: &str,
        engine: &str,
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
                loader.load_proc_agent(&path)?;
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
            file_switch, proc_switch,
            file_protect, proc_protect,
            interface: interface.to_string(),
            engine: engine.to_string(),
            md5_map: Arc::new(RwLock::new(std::collections::HashMap::new())),
            process_cache: Arc::new(Mutex::new((Vec::new(), Vec::new()))),
            pending_rules: Arc::new(Mutex::new(std::collections::HashMap::new())),
            applied_rules: Arc::new(Mutex::new(std::collections::HashMap::new())),
            proc_ringbuf: Arc::new(Mutex::new(None)),
            file_ringbuf: Arc::new(Mutex::new(None)),
            path_hash_cache: Arc::new(RwLock::new(std::collections::HashMap::new())),
            dpi_pat_buffer: Arc::new(Mutex::new(String::new())),
            dpi_rule_buffer: Arc::new(Mutex::new(String::new())),
            dpi_tp_buffer: Arc::new(Mutex::new(String::new())),
            active_dir_keys: Arc::new(Mutex::new(Vec::new())),
            proc_pat_buffer: Arc::new(Mutex::new(String::new())),
            active_proc_whitelist: Arc::new(Mutex::new(Vec::new())),
        })
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
            // 启用 proc feature switch (index 1)
            if let Some(bpf) = loader.proc_bpf_mut() {
                ModularLoader::enable_feature(bpf, 1, self.proc_switch)?;
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
            loader.attach_net_programs(&self.interface, &self.engine)?;
            // 启用 net feature switch (index 2) — net_agent 可能没有 feature_switches map，容错
            if let Some(bpf) = loader.net_bpf_mut() {
                ModularLoader::enable_feature(bpf, 2, true)?;
            }
            info!("[EbpfBackend] ✅ Net agent 挂载完成 ({}@{})", self.interface, self.engine);
        } else {
            info!("[EbpfBackend] net_loaded=false，跳过 net agent 挂载");
        }

        info!("[EbpfBackend] ===== 所有 eBPF 程序挂载完毕 =====");
        Ok(())
    }

    pub fn is_file_loaded(&self) -> bool { self.file_loaded }
    pub fn is_proc_loaded(&self) -> bool { self.proc_loaded }
    pub fn is_net_loaded(&self) -> bool { self.net_loaded }

    /// 运行时更新 feature_switches + global_modes + 刷新已有 proc_rules
    pub fn sync_runtime_switches(&self, file_switch: bool, proc_switch: bool,
                                  file_protect: bool, proc_protect: bool) {
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
                    let _ = ModularLoader::enable_feature(bpf, 1, proc_switch);
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
        let applied = self.applied_rules.lock().unwrap();
        let md5_map = self.md5_map.read().unwrap();
        let mut refreshed = 0;

        for (hash, &action) in applied.iter() {
            if let Some(entries) = md5_map.get(hash) {
                for e in entries {
                    let _ = self.add_proc_rule_by_inode(e.dev, e.inode, action, mode);
                }
                refreshed += 1;
            }
        }
        log::info!("[EbpfBackend] 🔄 模式切换: 已刷新 {} 条 proc_rules (mode={})", refreshed,
            if protect { "PROTECT" } else { "MONITOR" });
    }

    /// 从 ringbuf 中读取所有待处理事件（epoll + 同步读取）
    fn drain_ringbuf(ringbuf_mutex: &Arc<Mutex<Option<RingBuf<aya::maps::MapData>>>>) -> Vec<Vec<u8>> {
        let mut guard = ringbuf_mutex.lock().unwrap();
        if let Some(ref mut ringbuf) = *guard {
            let fd = ringbuf.as_raw_fd();
            let epoll_fd = unsafe { libc::epoll_create1(0) };
            if epoll_fd < 0 { return Vec::new(); }
            let mut ev = libc::epoll_event { events: (libc::EPOLLIN | libc::EPOLLHUP) as u32, u64: 0 };
            unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, fd, &mut ev); }
            let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
            let n = unsafe { libc::epoll_wait(epoll_fd, events.as_mut_ptr(), 1, 500) };
            unsafe { libc::close(epoll_fd); }

            if n > 0 {
                let mut items: Vec<Vec<u8>> = Vec::new();
                while let Some(item) = ringbuf.next() {
                    items.push(item.to_vec());
                }
                items
            } else {
                Vec::new()
            }
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
            loop {
                let items = Self::drain_ringbuf(&rb);
                for data in &items {
                    if let Some((event, path, comm)) = Self::parse_event(data) {
                        let is_black = event.event_type == 2; // EVENT_PROC
                        let is_unknown = event.event_type == 3; // EVENT_PROC_UNKNOWN
                        if event.blocked == 1 {
                            let n_type = if is_black { 1102 } else { 1101 };
                            log::warn!("[EbpfBackend] 🚫 {}命中(保护): path={}, comm={}, pid={}, uid={}",
                                if is_black { "黑名单" } else { "不明进程" },
                                path, comm, event.pid, event.uid);
                            backend.report_process_event(event, &path, &comm, n_type, "拦截");
                        } else if is_black {
                            // 黑名单+监控：打印本地日志 + 上报
                            log::info!("[EbpfBackend] 👀 黑名单命中(监控): path={}, comm={}, pid={}",
                                path, comm, event.pid);
                            backend.report_process_event(event, &path, &comm, 1002, "监控");
                        } else {
                            // 不明进程+监控：只上报不打印
                            backend.report_process_event(event, &path, &comm, 1001, "监控");
                        }
                    }
                }
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
        let md5_hash = self.get_md5_cached(path);
        // 不明进程命中时，若其 MD5 已在待下发白/黑名单(pending_rules)中，即时补写 proc_rules，
        // 让下一次 exec 能按名单放行/拦截（否则 /opt 等未扫描路径的白名单永远不生效）。
        // 只处理绝对路径：相对路径(如 ./script/x.sh)会相对 agent 自身 CWD 解析，读到错误文件、
        // 写出错误 inode，所以跳过（相对路径继续走"不明→拦截→上报"，由服务器/名单侧处理）。
        let mut in_server_list = false;
        if matches!(n_type, 1001 | 1101) && path.starts_with('/') {
            if let Some(h) = md5_hash.as_deref() {
                in_server_list = self.try_resolve_pending_rule(path, h);
            }
        }
        // level 由事件自身的 blocked 状态决定（n_type>=1100 即被拦截），
        // 不依赖 self.proc_protect：该字段仅在构造时赋值，运行时切保护模式不会同步更新，会导致误报 level。
        let log = reporter::AuditLogInfo {
            file_path: Some(path.to_string()),
            md5: md5_hash.clone(),
            n_type,
            n_level: if n_type >= 1100 { 3 } else { 2 },
            n_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
            rename_dir: None,
            notice_remark: Some(format!("eBPF进程{}: pid={} uid={}", action, event.pid, event.uid)),
            exception_process: Some(comm.to_string()),
            peripheral_name: None, peripheral_remark: None, peripheral_eid: None,
            p_param: Some(path.to_string()),
        };
        reporter::broadcast_audit_log(&log);   // gRPC 推送
        reporter::send_to_http_upload(&log);    // HTTP 上报到服务器

        // 只有真正不在服务器黑白名单里的"不明进程"才上报 /v1/autouploadprocess，
        // 让服务器有机会把它加白/黑；已在名单里的（上面已即时补写 proc_rules）不再重复上报。
        if matches!(n_type, 1001 | 1101) && !in_server_list {
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
                str_executable_path: path.to_string(),
                str_user: reporter::get_user_name(event.uid),
                hash: md5_hash.unwrap_or_default(),
                map_depends: vec![],
            });
        }
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

    fn add_proc_rule_by_inode(&self, dev: u64, inode: u64, action: u8, mode: u8) -> anyhow::Result<()> {
        let mut loader = self.loader.lock().unwrap();
        let bpf = loader.proc_bpf_mut().ok_or_else(|| anyhow::anyhow!("Proc agent not loaded"))?;
        let mut proc_rules: AyaHashMap<_, ProcKey, ProcRuleVal> =
            AyaHashMap::try_from(bpf.map_mut("proc_rules").unwrap())?;
        proc_rules.insert(ProcKey { dev, inode }, ProcRuleVal { action, mode, reserved: [0; 6] }, 0)?;
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
                        if seen.insert((dk.dev, dk.inode)) {
                            log_info!("[EbpfBackend] 信任进程白名单 ✅ {} (full) -> dev={} inode={}",
                                key, dk.dev, dk.inode);
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
                        if seen.insert((dk.dev, dk.inode)) {
                            log_info!("[EbpfBackend] 信任进程白名单 ✅ {} (basename={}) -> {} dev={} inode={}",
                                key, basename, cand, dk.dev, dk.inode);
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
            match self.add_proc_rule_by_inode(dk.dev, dk.inode, 0 /*allow*/, 0 /*inherit*/) {
                Ok(_) => {
                    written += 1;
                    tracked.push(*dk);
                }
                Err(e) => warn!(
                    "[EbpfBackend] 信任进程白名单写入失败 dev={} inode={}: {}",
                    dk.dev, dk.inode, e
                ),
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
                proc_rules.remove(&ProcKey { dev: e.dev, inode: e.inode })?;
            }
        }
        Ok(())
    }

    /// 不明进程首次命中时，若其 MD5 已在待下发规则(pending_rules)中，立即解析 (dev,inode) 补写 proc_rules。
    /// 解决扫描目录(/bin /usr/bin /usr/sbin /usr/local/bin /usr/lib/systemd)未覆盖第三方路径
    /// （如 /opt/vigilixav/sbin/vigilixd）时，白名单 hash 永远无法解析成 inode 的问题。
    /// 返回是否在服务器黑白名单(pending_rules)中：true=已在名单（不重复上报），false=真正的不明进程。
    fn try_resolve_pending_rule(&self, path: &str, hash: &str) -> bool {
        let action = match self.pending_rules.lock().unwrap().get(hash) {
            Some(a) => *a,
            None => return false, // 不在待下发名单：真正的不明进程
        };
        use std::os::unix::fs::MetadataExt;
        let (dev, inode) = match std::fs::metadata(path) {
            Ok(md) => (md.dev(), md.ino()),
            Err(_) => return true, // 在名单但解析失败（服务器已决定，不重复上报）
        };
        let mode = if self.proc_protect { 2u8 } else { 1u8 };
        if let Err(e) = self.add_proc_rule_by_inode(dev, inode, action, mode) {
            log::warn!("[EbpfBackend] 补写 proc_rules 失败: {}", e);
            return true;
        }
        self.md5_map.write().unwrap()
            .entry(hash.to_string()).or_insert_with(Vec::new)
            .push(Md5Entry { inode, dev, path: path.to_string() });
        // 持久化 hash→path 到 DB：重启后 md5_map 只从标准目录重建，/opt 等非扫描路径
        // 若不落库，重启会再次拦截一次、再走一遍即时补写。
        local_store::md5_inode_cache::persist_if_enabled(hash, path);
        self.pending_rules.lock().unwrap().remove(hash);
        self.applied_rules.lock().unwrap().insert(hash.to_string(), action);
        log::info!("[EbpfBackend] ✅ 不明进程命中白/黑名单，即时补写 proc_rules: path={} action={}", path, action);
        true
    }

    /// 将 pending_rules 中已有 md5_map 的条目重新下发
    fn replay_pending_rules(&self) {
        let mut pending = self.pending_rules.lock().unwrap();
        if pending.is_empty() { return; }

        let md5_map = self.md5_map.read().unwrap();
        let mode = if self.proc_protect { 2u8 } else { 1u8 };
        let mut replayed = 0;
        let to_remove: Vec<String> = pending.iter()
            .filter_map(|(hash, action)| {
                if let Some(entries) = md5_map.get(hash.as_str()) {
                    for e in entries {
                        let _ = self.add_proc_rule_by_inode(e.dev, e.inode, *action, mode);
                    }
                    replayed += 1;
                    Some(hash.clone())
                } else { None }
            })
            .collect();
        for h in &to_remove { pending.remove(h); }
        if replayed > 0 {
            info!("[EbpfBackend] replay_pending_rules: 补写 {} 条 (剩余 {} 条)", replayed, pending.len());
        }
    }

    pub fn scan_executables(&self, dirs: &[String], recursive: bool) -> anyhow::Result<usize> {
        let mut map = self.md5_map.write().unwrap();
        let mut path_cache = self.path_hash_cache.write().unwrap();
        let mut count = 0;
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
                    let mtime = std::fs::metadata(path)
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d: std::time::Duration| d.as_secs())
                        .unwrap_or(0);
                    path_cache.insert(path_str.clone(), (hash.clone(), mtime));
                    use std::os::unix::fs::MetadataExt;
                    if let Ok(md) = std::fs::metadata(path) {
                        map.entry(hash).or_insert_with(Vec::new).push(Md5Entry {
                            inode: md.ino(), dev: md.dev(), path: path_str,
                        });
                        count += 1;
                    }
                }
            }
        }
        info!("[EbpfBackend] Scanned {} executables, {} unique MD5s", count, map.len());
        drop(map); // 释放写锁，让 replay_pending_rules 可以获取读锁
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
                .push(Md5Entry { inode: md.ino(), dev: md.dev(), path });
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
                    let _ = self.add_proc_rule_by_inode(e.dev, e.inode, action, mode);
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
        Ok(())
    }

    fn notify_process_update(&self) -> Result<(), String> { Ok(()) }

    fn get_process_whitelist(&self) -> Vec<String> {
        self.process_cache.lock().unwrap().0.clone()
    }
    fn get_process_blacklist(&self) -> Vec<String> {
        self.process_cache.lock().unwrap().1.clone()
    }

    fn lookup_hash_paths(&self, hash: &str) -> Vec<String> {
        let md5_map = self.md5_map.read().unwrap();
        md5_map.get(hash)
            .map(|entries| entries.iter().map(|e| e.path.clone()).collect())
            .unwrap_or_default()
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
        let mut loader = self.loader.lock().unwrap();
        let bpf = loader.net_bpf_mut().ok_or_else(|| "Net agent not loaded".to_string())?;
        let mut pkt_mod_rules: AyaHashMap<_, PktModKey, PktModValue> =
            AyaHashMap::try_from(bpf.map_mut("pkt_mod_rules").unwrap()).map_err(|e| format!("{}", e))?;

        for ip in ips {
            if let Ok(addr) = ip.parse::<Ipv4Addr>() {
                let key = PktModKey { protocol: 6, direction: 1, padding: [0;2],
                    dst_ip: u32::from(addr).to_be(), src_port: 0, dst_port: 0 };
                let _ = pkt_mod_rules.insert(key, PktModValue::default(), 0);
            }
        }
        Ok(())
    }

    fn write_ipv6_block_policies(&self, _ips: &[String]) -> Result<(), String> {
        warn!("[EbpfBackend] IPv6 block not yet supported");
        Ok(())
    }

    fn write_net_rules(&self, _rules: &str) -> Result<(), String> {
        warn!("[EbpfBackend] net_rules not yet supported via eBPF");
        Ok(())
    }

    fn write_netblock_switch(&self, _value: &str) -> Result<(), String> { Ok(()) }
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
}
