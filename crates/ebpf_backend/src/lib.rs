use aya::maps::HashMap as AyaHashMap;
use log::{info, warn};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

pub mod loader;
pub mod types;
pub mod capability;
use loader::ModularLoader;
use types::*;
use common::backend::SecurityBackend;

/// eBPF 后端 — 按需加载 proc/file/net 模块，通过 BPF maps 下发规则
pub struct EbpfBackend {
    loader: Arc<Mutex<ModularLoader>>,
    file_loaded: bool,
    proc_loaded: bool,
    net_loaded: bool,
    pub interface: String,
    pub engine: String,
    /// MD5 → [(dev, inode, path)] 映射（后台扫描填充）
    pub md5_map: Arc<RwLock<std::collections::HashMap<String, Vec<Md5Entry>>>>,
    /// 进程规则缓存 (whitelist, blacklist)
    process_cache: Arc<Mutex<(Vec<String>, Vec<String>)>>,
    /// 待下发规则缓存: hash → action (0=white, 1=black), 用于 md5_map 尚未包含该 hash 时暂存
    pending_rules: Arc<Mutex<std::collections::HashMap<String, u8>>>,
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
        file_protect: bool,
        proc_protect: bool,
        net_enabled: bool,
        interface: &str,
        engine: &str,
    ) -> anyhow::Result<Self> {
        let mut loader = ModularLoader::new();
        let mut file_loaded = false;
        let mut proc_loaded = false;
        let mut net_loaded = false;

        if file_protect {
            let path = format!("{}/file_agent.bpf.o", bpf_dir);
            if Path::new(&path).exists() {
                loader.load_file_agent(&path)?;
                file_loaded = true;
            } else {
                warn!("[EbpfBackend] {} not found, skip file agent", path);
            }
        }
        if proc_protect {
            let path = format!("{}/proc_agent.bpf.o", bpf_dir);
            if Path::new(&path).exists() {
                loader.load_proc_agent(&path)?;
                proc_loaded = true;
            } else {
                warn!("[EbpfBackend] {} not found, skip proc agent", path);
            }
        }
        if net_enabled {
            let path = format!("{}/net_agent.bpf.o", bpf_dir);
            if Path::new(&path).exists() {
                loader.load_net_agent(&path)?;
                net_loaded = true;
            } else {
                warn!("[EbpfBackend] {} not found, skip net agent", path);
            }
        }

        Ok(Self {
            loader: Arc::new(Mutex::new(loader)),
            file_loaded,
            proc_loaded,
            net_loaded,
            interface: interface.to_string(),
            engine: engine.to_string(),
            md5_map: Arc::new(RwLock::new(std::collections::HashMap::new())),
            process_cache: Arc::new(Mutex::new((Vec::new(), Vec::new()))),
            pending_rules: Arc::new(Mutex::new(std::collections::HashMap::new())),
        })
    }

    pub fn init(&self) -> anyhow::Result<()> {
        let mut loader = self.loader.lock().unwrap();
        if self.file_loaded {
            loader.attach_file_programs()?;
            info!("[EbpfBackend] File agent initialized");
        }
        if self.proc_loaded {
            loader.attach_proc_programs()?;
            info!("[EbpfBackend] Proc agent initialized");
        }
        if self.net_loaded {
            loader.attach_net_programs(&self.interface, &self.engine)?;
            info!("[EbpfBackend] Net agent initialized on {} ({})", self.interface, self.engine);
        }
        Ok(())
    }

    pub fn is_file_loaded(&self) -> bool { self.file_loaded }
    pub fn is_proc_loaded(&self) -> bool { self.proc_loaded }
    pub fn is_net_loaded(&self) -> bool { self.net_loaded }

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
        let md5_map = self.md5_map.blocking_read();
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

        let md5_map = self.md5_map.blocking_read();
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

    pub async fn scan_executables(&self, dirs: &[String], recursive: bool) -> anyhow::Result<usize> {
        use tokio::fs;
        let mut map = self.md5_map.write().await;
        let mut count = 0;
        for dir in dirs {
            let walker = if recursive { walkdir::WalkDir::new(dir) } else { walkdir::WalkDir::new(dir).max_depth(1) };
            for entry in walker.into_iter().filter_map(|e| e.ok()) {
                let path = entry.path();
                if !path.is_file() { continue; }
                if let Ok(data) = std::fs::read(path) {
                    if data.len() < 4 || &data[..4] != b"\x7fELF" { continue; }
                } else { continue; }
                if let Ok(data) = fs::read(path).await {
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
        let mode = 2u8; // protect
        let md5_map = self.md5_map.blocking_read();
        let mut applied = 0;
        let mut pending = 0;

        for line in data.lines() {
            let hash = if let Some(stripped) = line.strip_prefix("del ") {
                // eBPF 模式删除: 从 pending_rules 移除
                let h = if let Some(idx) = stripped.find(' ') { &stripped[idx+1..] } else { stripped };
                let _ = self.remove_proc_rule_by_hash(h);
                self.pending_rules.lock().unwrap().remove(h);
                continue;
            } else if let Some(idx) = line.find('=') {
                &line[..idx]
            } else { continue; };

            if let Some(entries) = md5_map.get(hash) {
                for e in entries {
                    let _ = self.add_proc_rule_by_inode(e.dev, e.inode, action, mode);
                }
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

    // 其他
    fn emit_docker_event(&self, _kind: u8, _flag: u8, _pid: i32) -> Result<(), String> { Ok(()) }
    fn clear_docker_rt(&self) -> Result<(), String> { Ok(()) }
    fn write_business_ports(&self, _ports: &[u16]) -> Result<(), String> { Ok(()) }
    fn write_self_protection(&self, _num: u32) -> Result<(), String> { Ok(()) }
}
