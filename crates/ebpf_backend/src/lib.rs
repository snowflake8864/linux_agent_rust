use aya::maps::HashMap as AyaHashMap;
use aya::maps::RingBuf;
use log::{info, warn};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

pub mod loader;
pub mod types;
pub mod capability;
use loader::ModularLoader;
use types::*;
use common::backend::SecurityBackend;

/// Size of the UnifiedEvent struct in eBPF = 90 bytes
const UNIFIED_EVENT_SIZE: usize = 90;

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
}

#[derive(Debug, Clone)]
pub struct Md5Entry {
    pub inode: u64,
    pub dev: u64,
    pub path: String,
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

    /// 解析 ringbuf 事件
    fn parse_event(data: &[u8]) -> Option<(&UnifiedEvent, String, String)> {
        if data.len() < UNIFIED_EVENT_SIZE { return None; }
        let event: &UnifiedEvent = unsafe { &*(data.as_ptr() as *const UnifiedEvent) };
        let path = String::from_utf8_lossy(&event.path).trim_end_matches('\0').to_string();
        let comm = String::from_utf8_lossy(&event.comm).trim_end_matches('\0').to_string();
        Some((event, path, comm))
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
                    if let Some((event, path, comm)) = Self::parse_event(data) {
                        if event.blocked == 1 {
                            log::warn!("[EbpfBackend] 🚫 文件操作被拦截: path={}, comm={}, pid={}",
                                path, comm, event.pid);
                            backend.report_file_event(event, &path, &comm, 3101, "拦截");
                        } else {
                            backend.report_file_event(event, &path, &comm, 3001, "监控");
                        }
                    }
                }
                if items.is_empty() {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        });
    }

    /// 上报进程告警（拦截: n_type=1101, 监控: n_type=1001）
    fn report_process_event(&self, event: &UnifiedEvent, path: &str, comm: &str, n_type: u16, action: &str) {
        let log = reporter::AuditLogInfo {
            file_path: Some(path.to_string()),
            md5: None,
            n_type,
            n_level: if n_type >= 1100 { 2 } else { 1 },
            n_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
            rename_dir: None,
            notice_remark: Some(format!("eBPF进程{}: pid={} uid={}", action, event.pid, event.uid)),
            exception_process: Some(comm.to_string()),
            peripheral_name: None, peripheral_remark: None, peripheral_eid: None, p_param: None,
        };
        reporter::broadcast_audit_log(&log);
    }

    /// 上报文件告警（拦截: n_type=3101, 监控: n_type=3001）
    fn report_file_event(&self, event: &UnifiedEvent, path: &str, comm: &str, n_type: u16, action: &str) {
        let log = reporter::AuditLogInfo {
            file_path: Some(path.to_string()),
            md5: None,
            n_type,
            n_level: if n_type >= 3100 { 2 } else { 1 },
            n_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
            rename_dir: None,
            notice_remark: Some(format!("eBPF文件{}: pid={}", action, event.pid)),
            exception_process: Some(comm.to_string()),
            peripheral_name: None, peripheral_remark: None, peripheral_eid: None, p_param: None,
        };
        reporter::broadcast_audit_log(&log);
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

    /// 从 data 行中提取 hash 列表
    fn extract_hashes(&self, data: &str) -> Vec<String> {
        data.lines()
            .filter_map(|line| {
                if line.starts_with("del ") { None }
                else { line.find('=').map(|i| line[..i].to_string()) }
            })
            .collect()
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

    /// 将 pending_rules 中已有 md5_map 的条目重新下发
    fn replay_pending_rules(&self) {
        let mut pending = self.pending_rules.lock().unwrap();
        if pending.is_empty() { return; }

        let md5_map = self.md5_map.read().unwrap();
        let mode = 2u8;
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
        let mut count = 0;
        for dir in dirs {
            let walker = if recursive { walkdir::WalkDir::new(dir) } else { walkdir::WalkDir::new(dir).max_depth(1) };
            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                let path = entry.path();
                if !path.is_file() { continue; }
                if let Ok(data) = std::fs::read(path) {
                    if data.len() < 4 || &data[..4] != b"\x7fELF" { continue; }
                } else { continue; }
                if let Ok(data) = std::fs::read(path) {
                    let hash = hex::encode(md5::compute(&data).0);
                    use std::os::unix::fs::MetadataExt;
                    if let Ok(md) = std::fs::metadata(path) {
                        map.entry(hash).or_insert_with(Vec::new).push(Md5Entry {
                            inode: md.ino(), dev: md.dev(), path: path.to_string_lossy().to_string(),
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
}

// ── SecurityBackend impl ──

impl SecurityBackend for EbpfBackend {
    fn is_active(&self) -> bool { self.file_loaded || self.proc_loaded || self.net_loaded }
    fn name(&self) -> &str { "ebpf" }

    // 进程
    fn add_md5_rules(&self, data: &str) -> Result<(), String> {
        // data 格式: "{hash}=0\n" (白) / "{hash}=1\n" (黑) / "del 0 {hash}\n"
        // eBPF 模式下，path 字段实际存的是 MD5 hash，需要查 md5_map 转换为 inode 后写入 BPF map
        let is_white = data.contains("=0");
        let action = if is_white { 0u8 } else { 1u8 };
        // mode: 1=监控(MONITOR) 2=保护(PROTECT)，由 PROC_PROTECT/FILE_PROTECT 控制
        let mode = if self.proc_protect { 2u8 } else { 1u8 };
        let md5_map = self.md5_map.read().unwrap();
        let mut applied = 0;
        let mut pending = 0;

        for line in data.lines() {
            let hash = if let Some(stripped) = line.strip_prefix("del ") {
                // eBPF 模式删除: 从 pending_rules 移除
                let h = if let Some(idx) = stripped.find(' ') { &stripped[idx+1..] } else { stripped };
                let _ = self.remove_proc_rule_by_hash(h);
                self.pending_rules.lock().unwrap().remove(h);
                self.applied_rules.lock().unwrap().remove(h);
                continue;
            } else if let Some(idx) = line.find('=') {
                &line[..idx]
            } else { continue; };

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
                log::warn!("[EbpfBackend] hash {} 不在 md5_map 中，暂存为待下发规则 (action={})", hash, action);
            }
        }

        // 同步 process_cache
        let mut cache = self.process_cache.lock().unwrap();
        if is_white { cache.0 = self.extract_hashes(data); }
        else { cache.1 = self.extract_hashes(data); }

        log::info!("[EbpfBackend] add_md5_rules: 已下发 {} 条, 待扫描 {} 条", applied, pending);
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

    // DPI (stub)
    fn write_dpi_file_patterns(&self, _data: &str, _clear: bool, _build: bool) -> Result<(), String> {
        warn!("[EbpfBackend] DPI file patterns not supported");
        Ok(())
    }
    fn write_dpi_rules(&self, _data: &str, _clear: bool) -> Result<(), String> {
        warn!("[EbpfBackend] DPI rules not supported");
        Ok(())
    }
    fn write_process_dpi_patterns(&self, _data: &str, _clear: bool, _build: bool) -> Result<(), String> {
        warn!("[EbpfBackend] Process DPI patterns not supported");
        Ok(())
    }
    fn write_process_dpi_rules(&self, _data: &str, _clear: bool) -> Result<(), String> {
        warn!("[EbpfBackend] Process DPI rules not supported");
        Ok(())
    }
    fn write_dpi_true_process(&self, _data: &str, _clear: bool) -> Result<(), String> {
        warn!("[EbpfBackend] DPI true process not supported");
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
    fn write_self_protection(&self, _num: u32) -> Result<(), String> { Ok(()) }
}
