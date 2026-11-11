use std::collections::HashMap;
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
    pub static ref NETBLOCK_POLICIES: Arc<RwLock<HashMap<String, IpPolicy>>> = Arc::new(RwLock::new(HashMap::new()));
    pub static ref IP_EXPIRY_TASKS: Arc<RwLock<HashMap<String, JoinHandle<()>>>> = Arc::new(RwLock::new(HashMap::new()));
}

pub async fn update_and_write_policies(
    policies: Vec<IpPolicy>,
    source: &str,
) -> Result<(), String> {
    let mut global_policies = IP_POLICIES.write().await;
    let mut netblock_policies = NETBLOCK_POLICIES.write().await;
    let mut expiry_tasks = IP_EXPIRY_TASKS.write().await;

    match source {
        "policies" => {
            // 来自policies，清空并重设全局IP策略
            for (_, task) in expiry_tasks.drain() { task.abort(); }
            global_policies.clear();
            for policy in policies {
                let ip = policy.ip.clone();
                if policy.duration > 0 {
                    let ip_clone = ip.clone();
                    let p_map = Arc::clone(&IP_POLICIES);
                    let t_map = Arc::clone(&IP_EXPIRY_TASKS);
                    let task = tokio::spawn(async move {
                        sleep(Duration::from_secs(policy.duration)).await;
                        p_map.write().await.remove(&ip_clone);
                        t_map.write().await.remove(&ip_clone);
                    });
                    expiry_tasks.insert(ip.clone(), task);
                }
                global_policies.insert(ip, policy);
            }
        }
        "netblocks" => {
            // 来自netblocks，清空并重设网段策略
            netblock_policies.clear();
            for policy in policies {
                netblock_policies.insert(policy.ip.clone(), policy);
            }
        }
        _ => return Err(format!("unknown source: {}", source)),
    }

    // 合并写入
    let mut merged: HashMap<String, IpPolicy> = HashMap::new();
    merged.extend(global_policies.iter().map(|(k, v)| (k.clone(), v.clone())));
    merged.extend(netblock_policies.iter().map(|(k, v)| (k.clone(), v.clone())));

    write_policies_to_proc(&mut merged).await
}

// Write policies to /proc files
async fn write_policies_to_proc(global_policies: &mut HashMap<String, IpPolicy>) -> Result<(), String> {
    log_info!("write_policies_to_proc: Number of policies: {}", global_policies.len());

    // Separate IPv4 and IPv6
    let mut ipv4: Vec<String> = Vec::new();
    let mut ipv6: Vec<String> = Vec::new();
    for policy in global_policies.values() {
        if policy.is_ipv6 {
            ipv6.push(policy.ip.clone());
        } else {
            ipv4.push(policy.ip.clone());
        }
    }

    // 通过 SecurityBackend（驱动写 /proc/osec，ebpf 写 BPF map）
    common::backend::with_backend(|b| b.write_ipv4_block_policies(&ipv4))?;
    common::backend::with_backend(|b| b.write_ipv6_block_policies(&ipv6))?;
    Ok(())
}

// Helper function to check if IP is IPv6
pub fn is_ipv6(ip: &str) -> bool {
    ip.parse::<IpAddr>()
        .map(|addr| matches!(addr, IpAddr::V6(_)))
        .unwrap_or(false)
}

/// 同步版本：供 policy_store 在非 async 的 reload 路径中调用。
/// 使用 try_write，避免在 async 运行时内阻塞；短暂竞争时让出 CPU 重试。
pub fn apply_policies_sync(policies: Vec<IpPolicy>, source: &str) -> Result<(), String> {
    fn write_lock<'a, T>(
        lock: &'a RwLock<T>,
    ) -> Result<tokio::sync::RwLockWriteGuard<'a, T>, String> {
        for _ in 0..2000 {
            if let Ok(g) = lock.try_write() {
                return Ok(g);
            }
            std::thread::yield_now();
        }
        Err("netblock: 获取写锁超时".to_string())
    }

    let mut global_policies = write_lock(&IP_POLICIES)?;
    let mut netblock_policies = write_lock(&NETBLOCK_POLICIES)?;
    let mut expiry_tasks = write_lock(&IP_EXPIRY_TASKS)?;

    match source {
        "policies" => {
            for (_, task) in expiry_tasks.drain() {
                task.abort();
            }
            global_policies.clear();
            for policy in policies {
                let ip = policy.ip.clone();
                if policy.duration > 0 {
                    if let Ok(handle) = tokio::runtime::Handle::try_current() {
                        let ip_clone = ip.clone();
                        let p_map = Arc::clone(&IP_POLICIES);
                        let t_map = Arc::clone(&IP_EXPIRY_TASKS);
                        let duration = policy.duration;
                        let task = handle.spawn(async move {
                            sleep(Duration::from_secs(duration)).await;
                            p_map.write().await.remove(&ip_clone);
                            t_map.write().await.remove(&ip_clone);
                        });
                        expiry_tasks.insert(ip.clone(), task);
                    }
                }
                global_policies.insert(ip, policy);
            }
        }
        "netblocks" => {
            netblock_policies.clear();
            for policy in policies {
                netblock_policies.insert(policy.ip.clone(), policy);
            }
        }
        _ => return Err(format!("unknown source: {}", source)),
    }

    let mut merged: HashMap<String, IpPolicy> = HashMap::new();
    merged.extend(global_policies.iter().map(|(k, v)| (k.clone(), v.clone())));
    merged.extend(netblock_policies.iter().map(|(k, v)| (k.clone(), v.clone())));

    write_policies_to_proc_sync(&merged)
}

fn write_policies_to_proc_sync(policies: &HashMap<String, IpPolicy>) -> Result<(), String> {
    log_info!("write_policies_to_proc_sync: Number of policies: {}", policies.len());

    let mut ipv4: Vec<String> = Vec::new();
    let mut ipv6: Vec<String> = Vec::new();
    for policy in policies.values() {
        if policy.is_ipv6 {
            ipv6.push(policy.ip.clone());
        } else {
            ipv4.push(policy.ip.clone());
        }
    }

    common::backend::with_backend(|b| b.write_ipv4_block_policies(&ipv4))?;
    common::backend::with_backend(|b| b.write_ipv6_block_policies(&ipv6))?;
    Ok(())
}
