use serde_json::Value;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use logging::log_info;

// Define IP policy structure
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct IpPolicy {
    pub direction: u32,    // Block direction
    pub ip: String,        // IP address (IPv4 or IPv6)
    pub duration: u64,     // Duration in seconds, 0 means permanent
    pub is_ipv6: bool,     // Whether it is an IPv6 address
}

// Define global maps for IP policies and expiry tasks
lazy_static::lazy_static! {
    pub static ref IP_POLICIES: Arc<RwLock<HashMap<String, IpPolicy>>> = Arc::new(RwLock::new(HashMap::new()));
    pub static ref IP_EXPIRY_TASKS: Arc<RwLock<HashMap<String, JoinHandle<()>>>> = Arc::new(RwLock::new(HashMap::new()));
}

// 清理内核 IP 封禁列表（先清空再重写，确保已删除的条目被移除）
fn clear_block_lists() -> Result<(), String> {
    let paths = [
        "/proc/osec/osec_conn/block_saddr_rt",
        "/proc/osec/osec_conn/block_saddr_rt_v6",
    ];
    for path in &paths {
        std::fs::write(path, "c\n")
            .map_err(|e| format!("clear_block_lists: write 'c\\n' to {} failed: {}", path, e))?;
    }
    log_info!("[netblock] 已清理内核封禁列表");
    Ok(())
}

// Update global map and write to kernel
pub async fn update_and_write_policies(policies: Vec<IpPolicy>) -> Result<(), String> {
    let mut global_policies = IP_POLICIES.write().await;
    let mut expiry_tasks = IP_EXPIRY_TASKS.write().await;

    // 全量替换：先清空旧策略和旧过期任务
    for (ip, task) in expiry_tasks.drain() {
        task.abort();
        log_info!("[netblock] 取消 IP {} 的过期任务（全量替换）", ip);
    }
    global_policies.clear();

    // 写入新策略并管理过期任务
    for policy in &policies {
        let ip = policy.ip.clone();

        let duration = policy.duration;
        if duration > 0 {
            let ip_for_task = ip.clone();
            let policies_map = Arc::clone(&IP_POLICIES);
            let tasks_map = Arc::clone(&IP_EXPIRY_TASKS);
            let task = tokio::spawn(async move {
                sleep(Duration::from_secs(duration)).await;
                let mut policies = policies_map.write().await;
                policies.remove(&ip_for_task);
                let mut tasks = tasks_map.write().await;
                tasks.remove(&ip_for_task);
                // 过期后重写内核
                if let Err(e) = write_policies_to_proc(&mut policies).await {
                    eprintln!("[netblock] IP {} 过期后重写内核失败: {}", ip_for_task, e);
                }
            });
            expiry_tasks.insert(ip.clone(), task);
        }

        global_policies.insert(ip, policy.clone());
    }

    // Log merged policies
    log_info!("Global IP policies: {:?}", *global_policies);

    // Write policies to kernel while holding write lock
    write_policies_to_proc(&mut global_policies).await
}

// Write policies to /proc files（先清理内核列表再全量重写）
async fn write_policies_to_proc(global_policies: &mut HashMap<String, IpPolicy>) -> Result<(), String> {
    clear_block_lists()?;
    log_info!("write_policies_to_proc: Global policies: {:?}", *global_policies);
    log_info!("write_policies_to_proc: Number of policies: {}", global_policies.len());

    // Separate IPv4 and IPv6 policies
    let mut ipv4_policies: Vec<&IpPolicy> = Vec::new();
    let mut ipv6_policies: Vec<&IpPolicy> = Vec::new();
    for policy in global_policies.values() {
        log_info!("Processing policy for IP {}: is_ipv6 = {}", policy.ip, policy.is_ipv6);
        if policy.is_ipv6 {
            ipv6_policies.push(policy);
        } else {
            ipv4_policies.push(policy);
        }
    }
    log_info!("IPv4 policies: {:?}", ipv4_policies);
    log_info!("IPv6 policies: {:?}", ipv6_policies);

    // Write IPv4 policies to /proc/osec/osec_conn/block_saddr_rt
    let ipv4_proc_path = "/proc/osec/osec_conn/block_saddr_rt";
    let mut ipv4_file = match OpenOptions::new()
        .write(true)
        .open(ipv4_proc_path)
    {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open {}: {}", ipv4_proc_path, e);
            return Err(format!("Failed to open {}: {}", ipv4_proc_path, e));
        }
    };
    // Write IPv4 addresses (先校验格式，过滤非法 IP)
    for policy in ipv4_policies {
        if policy.ip.parse::<std::net::Ipv4Addr>().is_err() {
            eprintln!("[netblock] 跳过非法 IPv4: {}", policy.ip);
            continue;
        }
        let ip_line = format!("{}\n", policy.ip);
        if let Err(e) = ipv4_file.write_all(ip_line.as_bytes()) {
            eprintln!("Failed to write IP {} to {}: {}", policy.ip, ipv4_proc_path, e);
            return Err(format!("Failed to write IP {} to {}: {}", policy.ip, ipv4_proc_path, e));
        }
    }

    // Write IPv6 policies to /proc/osec/osec_conn/block_saddr_rt_v6
    let ipv6_proc_path = "/proc/osec/osec_conn/block_saddr_rt_v6";
    let mut ipv6_file = match OpenOptions::new()
        .write(true)
        .open(ipv6_proc_path)
    {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open {}: {}", ipv6_proc_path, e);
            return Err(format!("Failed to open {}: {}", ipv6_proc_path, e));
        }
    };
    // Write IPv6 addresses (先校验格式，过滤非法 IP)
    for policy in ipv6_policies {
        if policy.ip.parse::<std::net::Ipv6Addr>().is_err() {
            eprintln!("[netblock] 跳过非法 IPv6: {}", policy.ip);
            continue;
        }
        let ip_line = format!("{}\n", policy.ip);
        if let Err(e) = ipv6_file.write_all(ip_line.as_bytes()) {
            eprintln!("Failed to write IP {} to {}: {}", policy.ip, ipv6_proc_path, e);
            return Err(format!("Failed to write IP {} to {}: {}", policy.ip, ipv6_proc_path, e));
        }
    }

    Ok(())
}

// Helper function to check if IP is IPv6
pub fn is_ipv6(ip: &str) -> bool {
    ip.parse::<IpAddr>()
        .map(|addr| matches!(addr, IpAddr::V6(_)))
        .unwrap_or(false)
}
