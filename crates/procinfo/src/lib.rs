// crates/procinfo/src/lib.rs

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use core::ptr::null_mut; // 用于 libc::time(*mut)
use serde::Serialize;

use process_mgr::get_md5_global;
use nix::unistd::{Uid, User};
use time::macros::format_description;
use time::OffsetDateTime;
use logging::{log_info,log_error};

// ============================================================================
// 内核进程事件缓存
// ============================================================================
/// 内核通过 UIO (map3) 推送的进程执行事件。
/// 用于补充 /proc 轮询无法捕获的短生命周期进程。
#[derive(Debug, Clone)]
pub struct KernelProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    pub uid: i32,
    pub exe_path: String,
    pub hash: String,
    pub inserted_at_secs: u64,
}

struct KernelProcessCache {
    entries: HashMap<u32, KernelProcessEntry>, // key = pid
    max_entries: usize,
    ttl_secs: u64,
}

impl KernelProcessCache {
    fn new(max_entries: usize, ttl_secs: u64) -> Self {
        Self { entries: HashMap::new(), max_entries, ttl_secs }
    }

    /// 插入或更新一个内核进程事件（按 pid 去重，保留最新的）
    fn insert(&mut self, entry: KernelProcessEntry) {
        // 超过容量限制时，清理过期条目
        if self.entries.len() >= self.max_entries {
            self.evict_expired();
        }
        // 仍超容量则删最旧的
        if self.entries.len() >= self.max_entries {
            if let Some(oldest_pid) = self.entries.iter()
                .min_by_key(|(_, e)| e.inserted_at_secs)
                .map(|(pid, _)| *pid)
            {
                self.entries.remove(&oldest_pid);
            }
        }
        self.entries.insert(entry.pid, entry);
    }

    /// 获取最近 ttl_secs 内的所有记录，同时清理过期条目
    fn get_recent(&mut self, now_secs: u64) -> Vec<KernelProcessEntry> {
        self.evict_expired();
        self.entries.values().cloned().collect()
    }

    fn evict_expired(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.entries.retain(|_, e| now - e.inserted_at_secs < self.ttl_secs);
    }
}

/// 全局内核进程事件缓存：最多 2000 条，存活 60 秒
pub static KERNEL_PROCESS_CACHE: LazyLock<Mutex<KernelProcessCache>> = LazyLock::new(|| {
    Mutex::new(KernelProcessCache::new(2000, 60))
});

/// 插入一条内核进程事件到全局缓存（供 reporter 调用）
pub fn insert_kernel_process(entry: KernelProcessEntry) {
    if let Ok(mut cache) = KERNEL_PROCESS_CACHE.lock() {
        cache.insert(entry);
    }
}

/// 合并内核缓存的进程（短生命周期进程）到 /proc 结果中。
/// 按 pid 去重：/proc 已有的保留 /proc 数据，仅追加 /proc 中不存在的 pid。
pub fn merge_kernel_processes(proc_list: &mut Vec<ProcessInfo>) {
    let existing_pids: HashSet<u32> = proc_list.iter().map(|p| p.pid).collect();

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let kernel_entries = {
        let mut cache = match KERNEL_PROCESS_CACHE.lock() {
            Ok(c) => c,
            Err(_) => return,
        };
        cache.get_recent(now_secs)
    };

    for entry in kernel_entries {
        if existing_pids.contains(&entry.pid) {
            continue; // /proc 中已有此 pid，跳过
        }
        // 从路径提取进程名
        let name = Path::new(&entry.exe_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let user = User::from_uid(Uid::from_raw(entry.uid as u32))
            .ok()
            .flatten()
            .map(|u| u.name)
            .unwrap_or_else(|| format!("uid_{}", entry.uid));

        proc_list.push(ProcessInfo {
            timestamp: entry.inserted_at_secs as i64,
            name,
            vendor: "unknown".to_string(),
            package: "unknown".to_string(),
            pid: entry.pid,
            ppid: entry.ppid,
            priority: 0,
            thread_count: 0,
            memory_rss_kb: 0,
            start_time: String::new(),
            exe_path: entry.exe_path,
            user,
            hash: entry.hash,
            dependencies: Vec::new(),
        });
    }
}

// ============================================================================
// ProcessInfo
// ============================================================================

#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub timestamp: i64,
    pub name: String,
    pub vendor: String,
    pub package: String,
    pub pid: u32,
    pub ppid: u32,
    pub priority: i32,
    pub thread_count: i32,
    pub memory_rss_kb: i64,
    pub start_time: String,
    pub exe_path: String,
    pub user: String,
    pub hash: String,
    pub dependencies: Vec<String>,
}

pub fn get_running_process_infos() -> Result<Vec<ProcessInfo>, ProcessInfoError> {
    let mut processes = Vec::new();
    let proc_dir = fs::read_dir("/proc").map_err(|e| ProcessInfoError::Io(e, "/proc".into()))?;

    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let pid_str = file_name.to_string_lossy();

        if !pid_str.chars().next().map_or(false, |c| c.is_ascii_digit()) {
            continue;
        }

        let pid: u32 = match pid_str.parse() {
            Ok(pid) => pid,
            Err(_) => continue,
        };

        match build_process_info(pid) {
            Ok(proc) => {
                if !should_skip(&proc) {
                    processes.push(proc);
                }
            }
            Err(e) => {/*log_error!("Failed to collect PID {}: {}", pid, e);*/},
        }
    }

    Ok(processes)
}

fn build_process_info(pid: u32) -> Result<ProcessInfo, ProcessInfoError> {
    let pid_path = |file: &str| PathBuf::from("/proc").join(pid.to_string()).join(file);

    let exe_path = pid_path("exe");
    let cmdline_path = pid_path("cmdline");
    let status_path = pid_path("status");
    let comm_path = pid_path("comm");
    let stat_path = pid_path("stat");

    let name = get_name(&comm_path, &exe_path, &cmdline_path, &stat_path)?;
    let exe_path_str = get_executable_path(&exe_path, &cmdline_path, &pid_path("cwd"), &name)?;

    if exe_path_str.is_empty() || !Path::new(&exe_path_str).exists() || is_magicarmor_path(&exe_path_str) {
        return Err(ProcessInfoError::InvalidExecutable(exe_path_str));
    }

    let memory = get_memory_rss(&status_path)?;
    let user = get_user(&status_path)?;
    let ppid = get_ppid(&stat_path)?;
    let priority = get_priority(&stat_path)?;
    let threads = get_thread_count(&stat_path)?;
    let start_time = get_start_time(&stat_path)?;
    let hash = get_md5_global(&exe_path_str)
        .map_err(|e| ProcessInfoError::Other(format!("计算 MD5 失败: {}", e)))?;

    Ok(ProcessInfo {
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64,
        name,
        vendor: get_vendor(),
        package: get_package(),
        pid,
        ppid,
        priority,
        thread_count: threads,
        memory_rss_kb: memory,
        start_time,
        exe_path: exe_path_str,
        user,
        hash,
        dependencies: Vec::new(),
    })
}

// ==================== Name Resolution ====================

fn get_name(
    comm_path: &Path,
    exe_path: &Path,
    cmdline_path: &Path,
    stat_path: &Path,
) -> Result<String, ProcessInfoError> {
    if let Ok(name) = read_to_string_with_context(comm_path) {
        let name = name.trim();
        if !name.is_empty() {
            return Ok(name.to_owned());
        }
    }

    if let Ok(target) = read_symlink(exe_path) {
        if let Some(name) = Path::new(&target).file_name().and_then(|s| s.to_str()) {
            return Ok(name.to_owned());
        }
    }

    if let Ok(args) = read_cmdline(&cmdline_path) {
        if let Some(first) = args.first() {
            return Ok(Path::new(first)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or(first)
                .to_owned());
        }
    }

    if let Ok(stat) = read_to_string_with_context(stat_path) {
        if let Some(start) = stat.find('(') {
            if let Some(end) = stat[start + 1..].find(')') {
                return Ok(stat[start + 1..start + 1 + end].to_owned());
            }
        }
    }

    Ok(format!("unknown_{}", pid_from_path(exe_path).unwrap_or(0)))
}

fn pid_from_path(p: &Path) -> Option<u32> {
    p.parent()?.file_name()?.to_str()?.parse().ok()
}

// ==================== Executable Path Logic ====================

fn get_executable_path(
    exe_path: &Path,
    cmdline_path: &Path,
    cwd_path: &Path,
    name: &str,
) -> Result<String, ProcessInfoError> {
    if let Ok(interpreter) = read_symlink(exe_path) {
        if is_interpreter(&interpreter) {
            if let Ok(args) = read_cmdline(cmdline_path) {
                if args.len() > 1 {
                    let script = &args[1];
                    let cwd = read_symlink(cwd_path).unwrap_or_default();
                    let abs = if script.starts_with('/') {
                        PathBuf::from(script)
                    } else {
                        PathBuf::from(&cwd).join(script)
                    };

                    if abs.exists() {
                        return Ok(abs.to_string_lossy().into_owned());
                    }
                }
            }
        }
    }

    read_symlink(exe_path).or_else(|_| Ok(name.to_owned()))
}

fn is_interpreter(path: &str) -> bool {
    matches!(
        path,
        "/bin/sh" | "/bin/bash" | "/bin/dash"
        | "/usr/bin/sh" | "/usr/bin/bash" | "/usr/bin/dash"
        | "/usr/bin/python" | "/usr/bin/python3" | "/usr/bin/perl" | "/usr/bin/ruby"
    )
}

// ==================== File & Symlink Helpers ====================

fn read_symlink(path: &Path) -> Result<String, ProcessInfoError> {
    fs::read_link(path)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| ProcessInfoError::Io(e, path.display().to_string()))
}

fn read_cmdline(path: &Path) -> Result<Vec<String>, ProcessInfoError> {
    let data = fs::read(path).map_err(|e| ProcessInfoError::Io(e, path.display().to_string()))?;
    Ok(data.split(|b| *b == 0)
        .filter_map(|s| String::from_utf8(s.to_vec()).ok())
        .filter(|s| !s.is_empty())
        .collect())
}

// ==================== Safe File Reader ====================

fn read_to_string_with_context<P: AsRef<Path>>(path: P) -> Result<String, ProcessInfoError> {
    let path = path.as_ref();
    fs::read_to_string(path).map_err(|e| ProcessInfoError::Io(e, path.display().to_string()))
}

// ==================== Status & Stat Parsers ====================

fn get_memory_rss(status_path: &Path) -> Result<i64, ProcessInfoError> {
    for line in read_to_string_with_context(status_path)?.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim() == "VmRSS" {
                return Ok(v.trim()
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0));
            }
        }
    }
    Ok(0)
}



fn get_user(status_path: &Path) -> Result<String, ProcessInfoError> {
    for line in read_to_string_with_context(status_path)?.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim() == "Uid" {
                let uid_str = v.trim().split_whitespace().next().unwrap_or("0");
                let uid: u32 = uid_str.parse().map_err(|_| ProcessInfoError::Parse("Uid"))?;

                return Ok(User::from_uid(Uid::from_raw(uid))
                    .map_err(|_| ProcessInfoError::Other("nix user lookup failed".into()))?
                    .map(|u| u.name)  //  name 是 String，直接取走
                    .unwrap_or_else(|| format!("uid_{}", uid)));
            }
        }
    }
    Ok("unknown".to_string())
}
fn get_ppid(stat_path: &Path) -> Result<u32, ProcessInfoError> {
    let stat = read_to_string_with_context(stat_path)?;
    let parts: Vec<&str> = stat.split_whitespace().collect();
    if parts.len() >= 4 {
        Ok(parts[3].parse().map_err(|_| ProcessInfoError::Parse("PPid"))?)
    } else {
        Ok(0)
    }
}

fn get_priority(stat_path: &Path) -> Result<i32, ProcessInfoError> {
    let stat = read_to_string_with_context(stat_path)?;
    let parts: Vec<&str> = stat.split_whitespace().collect();
    if parts.len() >= 18 {
        Ok(parts[17].parse().map_err(|_| ProcessInfoError::Parse("Priority"))?)
    } else {
        Ok(0)
    }
}

fn get_thread_count(stat_path: &Path) -> Result<i32, ProcessInfoError> {
    let stat = read_to_string_with_context(stat_path)?;
    let parts: Vec<&str> = stat.split_whitespace().collect();
    if parts.len() >= 20 {
        Ok(parts[19].parse().map_err(|_| ProcessInfoError::Parse("Threads"))?)
    } else {
        Ok(1)
    }
}

fn get_start_time(stat_path: &Path) -> Result<String, ProcessInfoError> {
    let stat = read_to_string_with_context(stat_path)?;
    let parts: Vec<&str> = stat.split_whitespace().collect();
    if parts.len() < 22 {
        return Ok("unknown".to_string());
    }

    let start_jiffies: u64 = parts[21].parse().map_err(|_| ProcessInfoError::Parse("Start time"))?;
    let uptime_data = read_to_string_with_context("/proc/uptime")?;
    let uptime_sec = uptime_data
        .split('.')
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    let hz = 100;
    let boot_jiffies = uptime_sec * hz;
    let boot_time = unsafe { libc::time(null_mut()) };
    let process_start = boot_time - ((boot_jiffies - start_jiffies) / hz) as i64;

    Ok(format_timestamp(process_start))
}

fn format_timestamp(secs: i64) -> String {
    let fmt = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    OffsetDateTime::from_unix_timestamp(secs)
        .map(|t| t.format(&fmt).unwrap_or_else(|_| secs.to_string()))
        .unwrap_or_else(|_| secs.to_string())
}

// ==================== Filters ====================

fn should_skip(info: &ProcessInfo) -> bool {
    info.exe_path.is_empty() || !Path::new(&info.exe_path).exists() || is_magicarmor_path(&info.exe_path)
}

fn is_magicarmor_path(path: &str) -> bool {
    path.contains("magicarmor")
}

// ==================== Placeholders ====================

fn get_vendor() -> String { "unknown".to_string() }
fn get_package() -> String { "unknown".to_string() }

// ==================== Error Type ====================

#[derive(Debug)]
pub enum ProcessInfoError {
    Io(std::io::Error, String),
    Parse(&'static str),
    InvalidExecutable(String),
    Other(String),
}

impl std::fmt::Display for ProcessInfoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessInfoError::Io(e, path) => write!(f, "IO error on {}: {}", path, e),
            ProcessInfoError::Parse(context) => write!(f, "Parse error: {}", context),
            ProcessInfoError::InvalidExecutable(path) => write!(f, "Invalid executable path: {}", path),
            ProcessInfoError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ProcessInfoError {}

// 实现 From 以便 ? 能自动转换
impl From<std::io::Error> for ProcessInfoError {
    fn from(e: std::io::Error) -> Self {
        ProcessInfoError::Io(e, "unknown".to_string())
    }
}

#[derive(Serialize)]
struct ProcessEntry {
    id: u32,
    user: String,
    dir: String,
    hash: String,
    module_number: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    module: Option<Vec<ModuleEntry>>,
}

#[derive(Serialize)]
struct ModuleEntry {
    name: String,
    hash: String,
    attribute: &'static str, // 这个是字面量，可以用 &'static str
}
/*
pub fn build_process_list_json(
    process_info: &[ProcessInfo],
    str_json: &mut String,
    nfinish: Option<i32>,
) -> Result<(), String> {
    let mut proclist = Vec::new();

    for p in process_info {
        // 计算进程 hash
        let hash = if p.hash.is_empty() {
            get_md5_global(&p.exe_path).unwrap_or_default()
        } else {
            p.hash.clone()
        };

        // 构建 module 列表
        let mut modules = Vec::new();
        let mut module_count = 0;

        for module_path in &p.dependencies {
            if module_path.is_empty() {
                continue;
            }

            let module_hash = match get_md5_global(module_path) {
                Ok(h) if !h.is_empty() => h,
                _ => continue,
            };

            modules.push(ModuleEntry {
                name: module_path.clone(),
                hash: module_hash, 
                attribute: "GNU/Linux",
            });
            module_count += 1;
        }

        let process_entry = ProcessEntry {
            id: p.pid,
            user: p.user.clone(),
            dir: p.exe_path.clone(),
            hash, 
            module_number: module_count,
            module: if module_count > 0 { Some(modules) } else { None },
        };

        proclist.push(process_entry);
    }

    // 序列化 proclist 为字符串
    let proclist_json = serde_json::to_string(&proclist)
        .map_err(|e| format!("序列化 proclist 失败: {}", e))?;

    // 构建最终 JSON 对象
    let mut final_json = serde_json::Map::new();

    if let Some(finish) = nfinish {
        if finish == 0 || finish == 100 {
            final_json.insert("finish".to_string(), serde_json::Value::Number(finish.into()));
        }
    }

    final_json.insert("proclist".to_string(), serde_json::Value::String(proclist_json));

    *str_json = serde_json::to_string(&final_json)
        .map_err(|e| format!("最终 JSON 序列化失败: {}", e))?;

    Ok(())
}
*/
pub fn build_process_list_json(
    process_info: &[ProcessInfo],
    str_json: &mut String,
    nfinish: Option<i32>,
) -> Result<(), String> {
    let mut proclist = Vec::new();

    for p in process_info {
        // 计算进程 hash
        let hash = if p.hash.is_empty() {
            get_md5_global(&p.exe_path).unwrap_or_default()
        } else {
            p.hash.clone()
        };

        let mut modules = Vec::new();
        let mut module_count = 0;

        for module_path in &p.dependencies {
            if module_path.is_empty() {
                continue;
            }

            let module_hash = match get_md5_global(module_path) {
                Ok(h) if !h.is_empty() => h,
                _ => continue,
            };

            modules.push(ModuleEntry {
                name: module_path.clone(),
                hash: module_hash,
                attribute: "GNU/Linux",
            });
            module_count += 1;
        }

        proclist.push(ProcessEntry {
            id: p.pid,
            user: p.user.clone(),
            dir: p.exe_path.clone(),
            hash,
            module_number: module_count,
            module: if module_count > 0 { Some(modules) } else { None },
        });
    }

    let proclist_json = serde_json::to_string(&proclist)
        .map_err(|e| format!("序列化 proclist 失败: {}", e))?;

    // 构建最终 JSON 对象
    let mut final_json = serde_json::Map::new();

    if let Some(finish) = nfinish {
        if finish == 0 || finish == 100 {
            final_json.insert("finish".to_string(), serde_json::Value::Number(finish.into()));
        }
    }

    final_json.insert("proclist".to_string(), serde_json::Value::String(proclist_json));

    *str_json = serde_json::to_string(&final_json)
        .map_err(|e| format!("最终 JSON 序列化失败: {}", e))?;

    Ok(())
}
