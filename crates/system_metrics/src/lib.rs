use sysinfo::{DiskExt, Pid, ProcessExt, System, SystemExt, UserExt, Uid};
use serde::Serialize;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use std::sync::{Arc, Mutex};
use md5::{Md5, Digest};
use hex;
use std::collections::HashMap;
use logging::log_info;

#[derive(Clone, Default)]
struct CpuUseState {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
    guest: u64,
    guest_nice: u64,
}

struct CpuState {
    last: CpuUseState,
    initialized: bool,
}

lazy_static::lazy_static! {
    static ref CPU_STATE: Arc<Mutex<CpuState>> = Arc::new(Mutex::new(CpuState {
        last: CpuUseState::default(),
        initialized: false,
    }));
    static ref SYSTEM: Arc<Mutex<System>> = Arc::new(Mutex::new(System::new_all()));
}

#[derive(Serialize)]
pub struct ProcessInfo {
    id: String,
    dir: String,
    hash: String,
    cpu_usage: String,
    mem_size: String,
    user: String,
}

#[derive(Serialize)]
pub struct SelfInfo {
    mem_size: String,
    cpu_usage: String,
}

#[derive(Serialize)]
pub struct SystemInfo {
    hd_size: String,
    hd_usage: String,
    cpu_number: String,
    cpu_usage: String,
    cpu_tops: Vec<ProcessInfo>,
    mem_size: String,
    mem_usage: String,
    mem_tops: Vec<ProcessInfo>,
    #[serde(rename = "self")]
    self_info: SelfInfo,
}

fn get_cpu_use_state() -> io::Result<CpuUseState> {
    let file = File::open("/proc/stat")?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let mut cpu_state = CpuUseState::default();
    let mut parts = line.split_whitespace();
    parts.next(); // 跳过 "cpu" 字段

    if let (Some(user), Some(nice), Some(system), Some(idle), Some(iowait), Some(irq), Some(softirq), Some(steal), Some(guest), Some(guest_nice)) = (
        parts.next().and_then(|s| s.parse().ok()),
        parts.next().and_then(|s| s.parse().ok()),
        parts.next().and_then(|s| s.parse().ok()),
        parts.next().and_then(|s| s.parse().ok()),
        parts.next().and_then(|s| s.parse().ok()),
        parts.next().and_then(|s| s.parse().ok()),
        parts.next().and_then(|s| s.parse().ok()),
        parts.next().and_then(|s| s.parse().ok()),
        parts.next().and_then(|s| s.parse().ok()),
        parts.next().and_then(|s| s.parse().ok()),
    ) {
        cpu_state.user = user;
        cpu_state.nice = nice;
        cpu_state.system = system;
        cpu_state.idle = idle;
        cpu_state.iowait = iowait;
        cpu_state.irq = irq;
        cpu_state.softirq = softirq;
        cpu_state.steal = steal;
        cpu_state.guest = guest;
        cpu_state.guest_nice = guest_nice;
        Ok(cpu_state)
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, "Failed to parse /proc/stat"))
    }
}

fn calc_cpu_use_state(o: &CpuUseState, n: &CpuUseState) -> f32 {
    let od = o.user + o.nice + o.system + o.idle;
    let nd = n.user + n.nice + n.system + n.idle;

    let id = n.user.saturating_sub(o.user);
    let sd = n.system.saturating_sub(o.system);

    if nd == od {
        0.0
    } else {
        ((id + sd) as f32 * 100.0) / (nd - od) as f32
    }
}

fn get_memory_from_proc_meminfo() -> Option<(u64, u64)> {
    let file = File::open("/proc/meminfo").ok()?;
    let reader = BufReader::new(file);

    let mut total_kb: Option<u64> = None;
    let mut mem_free: Option<u64> = None;
    let mut mem_buffer: Option<u64> = None;
    let mut mem_cache: Option<u64> = None;

    for line in reader.lines().map(|l| l.ok()).flatten() {
        if line.starts_with("MemTotal:") {
            total_kb = line.split_whitespace().nth(1)?.parse().ok();
        } else if line.starts_with("MemFree:") {
            mem_free = line.split_whitespace().nth(1)?.parse().ok();
        } else if line.starts_with("Buffers:") {
            mem_buffer = line.split_whitespace().nth(1)?.parse().ok();
        } else if line.starts_with("Cached:") {
            mem_cache = line.split_whitespace().nth(1)?.parse().ok();
        }
        if total_kb.is_some() && mem_free.is_some() && mem_buffer.is_some() && mem_cache.is_some() {
            break;
        }
    }

    match (total_kb, mem_free, mem_buffer, mem_cache) {
        (Some(total), Some(free), Some(buffer), Some(cache)) => {
            let used = total
                .saturating_sub(free)
                .saturating_sub(buffer)
                .saturating_sub(cache);
            Some((total, used))
        }
        _ => None,
    }
}

fn compute_process_md5(file_path: &str) -> String {
    if file_path.is_empty() || !Path::new(file_path).exists() {
        return String::new();
    }

    // 计算文件的 MD5 校验和
    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => return String::new(),
    };
    let mut file_contents = Vec::new();
    if let Err(_) = file.read_to_end(&mut file_contents) {
        return String::new();
    }

    // 创建 Md5 哈希生成器
    let mut hasher = Md5::new();
    hasher.update(&file_contents);  // 更新哈希计算器
    let result = hasher.finalize();  // 获取哈希结果

    // 将 MD5 哈希值转换为十六进制字符串并返回
    hex::encode(result)
}

pub fn get_system_metrics() -> Option<String> {
    // 获取当前 CPU 状态
    let now_use = match get_cpu_use_state() {
        Ok(state) => state,
        Err(e) => {
            eprintln!("获取 CPU 使用信息失败: {}", e);
            return None;
        }
    };

    // 计算 CPU 使用率
    let mut cpu_state = CPU_STATE.lock().unwrap();
    let cpu_usage = if cpu_state.initialized {
        let usage = calc_cpu_use_state(&cpu_state.last, &now_use);
        usage
    } else {
        cpu_state.initialized = true;
        0.0
    };
    cpu_state.last = now_use;

    // 获取系统信息
    let mut sys = SYSTEM.lock().unwrap();
    sys.refresh_all(); // 刷新所有信息，包括进程和用户

    // 预构建用户映射
    let mut user_map: HashMap<Uid, String> = HashMap::new();
    let users = sys.users();
    if users.is_empty() {
        eprintln!("警告: 用户列表为空，sysinfo 可能无法获取用户数据");
    }
    for user in users {
        let uid = user.id().clone(); // 使用 .clone() 消除警告
//        eprintln!("调试: UID = {}, 用户名 = {}", uid, user.name());
        user_map.insert(uid, user.name().to_string());
    }

    // CPU 核心数
    let cpu_number = sys.cpus().len().to_string();
/*
    // 内存信息
    let total_memory = sys.total_memory(); // 单位：KB
    let used_memory = sys.used_memory();
    let mem_size = format!("{}KB", total_memory);
    log_info!("内存总量: {}, 已用内存: {}", mem_size,used_memory);
    let mem_usage = if total_memory > 0 {
        ((used_memory as f32 / total_memory as f32) * 100.0).to_string()
    } else {
        "0".to_string()
    };
*/
    let bytes_to_kb = |bytes: u64| (bytes + 1023) / 1024; // 四舍五入

    let (total_memory_kb, used_memory_kb) = get_memory_from_proc_meminfo().unwrap_or({
        let total = bytes_to_kb(sys.total_memory());
        let used = bytes_to_kb(sys.used_memory());
        (total, used)
    });

    let available_memory_kb = bytes_to_kb(sys.available_memory());
    let free_memory_kb = bytes_to_kb(sys.free_memory());

    let mem_size = format!("{}KB", total_memory_kb); // 或转为 MiB 显示
    let mem_usage = if total_memory_kb > 0 {
        ((used_memory_kb as f32 / total_memory_kb as f32) * 100.0).to_string()
    } else {
        "0".to_string()
    };

    // 日志用 MiB 显示更直观
    let kb_to_mib = |kb: u64| kb as f64 / 1024.0;
/*
    log_info!(
        "内存总量: {:.2}MiB, 实际已用: {:.2}MiB, 可用: {:.2}MiB (free: {:.2}MiB), 使用率: {}%",
        kb_to_mib(total_memory_kb),
        kb_to_mib(used_memory_kb),
        kb_to_mib(available_memory_kb),
        kb_to_mib(free_memory_kb),
        mem_usage
        );
*/

    // 磁盘信息
    let mut total_disk = 0;
    let mut used_disk = 0;
    for disk in sys.disks() {
        total_disk += disk.total_space();
        used_disk += disk.total_space() - disk.available_space();
    }
    let hd_size = format!("{}MB", total_disk / 1_048_576); // 转换为 MB
    let hd_usage = if total_disk > 0 {
        ((used_disk as f32 / total_disk as f32) * 100.0).to_string()
    } else {
        "0".to_string()
    };

    // 进程信息
    let mut processes: Vec<_> = sys.processes().iter().collect();
    // 按 CPU 使用率排序（Top 5）
    processes.sort_by(|a, b| b.1.cpu_usage().partial_cmp(&a.1.cpu_usage()).unwrap_or(std::cmp::Ordering::Equal));
    let cpu_tops: Vec<ProcessInfo> = processes.iter().take(5).map(|(&pid, proc)| {
        let user = proc.user_id().map(|uid| {
            user_map.get(&uid).cloned().unwrap_or_else(|| {
                eprintln!("用户未找到，UID: {:?}", uid);
                "unknown".to_string()
            })
        }).unwrap_or_else(|| {
            eprintln!("进程 {} 没有有效的 UID", pid);
            "unknown".to_string()
        });
        ProcessInfo {
            id: pid.to_string(),
            dir: proc.exe().to_string_lossy().into_owned(),
            hash: compute_process_md5(&proc.exe().to_string_lossy()),
            cpu_usage: proc.cpu_usage().to_string(),
            mem_size: format!("{}KB", proc.memory()),
            user,
        }
    }).collect();

    // 按内存使用量排序（Top 5）
    processes.sort_by(|a, b| b.1.memory().partial_cmp(&a.1.memory()).unwrap_or(std::cmp::Ordering::Equal));
    let mem_tops: Vec<ProcessInfo> = processes.iter().take(5).map(|(&pid, proc)| {
        let user = proc.user_id().map(|uid| {
            user_map.get(&uid).cloned().unwrap_or_else(|| {
                eprintln!("用户未找到，UID: {:?}", uid);
                "unknown".to_string()
            })
        }).unwrap_or_else(|| {
            eprintln!("进程 {} 没有有效的 UID", pid);
            "unknown".to_string()
        });
        ProcessInfo {
            id: pid.to_string(),
            dir: proc.exe().to_string_lossy().into_owned(),
            hash: compute_process_md5(&proc.exe().to_string_lossy()),
            cpu_usage: proc.cpu_usage().to_string(),
            mem_size: format!("{}KB", proc.memory()),
            user,
        }
    }).collect();

    // 当前进程信息
    let self_pid = Pid::from(std::process::id() as usize);
    let self_info = sys.process(self_pid).map_or(SelfInfo {
        mem_size: "0KB".to_string(),
        cpu_usage: "0".to_string(),
    }, |proc| SelfInfo {
        mem_size: format!("{}KB", proc.memory()),
        cpu_usage: proc.cpu_usage().to_string(),
    });

    // 构建 SystemInfo
    let system_info = SystemInfo {
        hd_size,
        hd_usage,
        cpu_number,
        cpu_usage: cpu_usage.to_string(),
        cpu_tops,
        mem_size,
        mem_usage,
        mem_tops,
        self_info,
    };

    // 序列化 SystemInfo 为字符串
    let info_str = serde_json::to_string(&system_info).unwrap_or_else(|e| {
        eprintln!("序列化 SystemInfo 失败: {}", e);
        String::new()
    });

    // 构建最终的 JSON 对象，info 字段为字符串
    let final_json = serde_json::json!({
        "info": info_str
    }).to_string();

    Some(final_json)
}
