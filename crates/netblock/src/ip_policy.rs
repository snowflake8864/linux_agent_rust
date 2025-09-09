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

// Update global map and write to kernel
pub async fn update_and_write_policies(policies: Vec<IpPolicy>) -> Result<(), String> {
    let mut global_policies = IP_POLICIES.write().await;
    let mut expiry_tasks = IP_EXPIRY_TASKS.write().await;

    // Update global map and manage expiry tasks
    for policy in policies {
        let ip = policy.ip.clone();
        let has_task = expiry_tasks.contains_key(&ip);

        // If duration == 0 and task exists, cancel it
        if policy.duration == 0 && has_task {
            if let Some(task) = expiry_tasks.remove(&ip) {
                task.abort();
                log_info!("IP {} duration set to 0, cancelled expiry task", ip);
            }
        }
        // If duration > 0 and no task, create new task
        else if policy.duration > 0 && !has_task {
            let ip_for_task = ip.clone(); // Clone ip for task
            let policies_map = Arc::clone(&IP_POLICIES);
            let tasks_map = Arc::clone(&IP_EXPIRY_TASKS);
            let task = tokio::spawn(async move {
                // Wait for duration seconds
                sleep(Duration::from_secs(policy.duration)).await;
                // Remove expired IP
                let mut policies = policies_map.write().await;
                policies.remove(&ip_for_task);
                log_info!("IP {} expired and removed, current policies: {:?}", ip_for_task, *policies);
                // Remove task handle
                let mut tasks = tasks_map.write().await;
                tasks.remove(&ip_for_task);
                // Write updated policies
                if let Err(e) = write_policies_to_proc(&mut policies).await {
                    eprintln!("Failed to re-write policies in expiry task for IP {}: {}", ip_for_task, e);
                }
            });
            // Store task handle
            expiry_tasks.insert(ip.clone(), task);
            log_info!("Created expiry task for IP {}, duration: {}", ip, policy.duration);
        }
        // If duration > 0 and task exists, keep existing task, update policy
        else if policy.duration > 0 && has_task {
            log_info!("IP {} has existing expiry task, skipped creating new task, updated duration: {}", ip, policy.duration);
        }

        // Update IP_POLICIES
        global_policies.insert(ip, policy);
    }

    // Log merged policies
    log_info!("Global IP policies: {:?}", *global_policies);

    // Write policies to kernel while holding write lock
    write_policies_to_proc(&mut global_policies).await
}

// Write policies to /proc files
async fn write_policies_to_proc(global_policies: &mut HashMap<String, IpPolicy>) -> Result<(), String> {
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
    // Write "c\n" to clear
    if let Err(e) = ipv4_file.write_all(b"c\n") {
        eprintln!("Failed to write 'c\\n' to {}: {}", ipv4_proc_path, e);
        return Err(format!("Failed to write 'c\\n' to {}: {}", ipv4_proc_path, e));
    }
    // Write IPv4 addresses
    for policy in ipv4_policies {
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
    // Write "c\n" to clear
    if let Err(e) = ipv6_file.write_all(b"c\n") {
        eprintln!("Failed to write 'c\\n' to {}: {}", ipv6_proc_path, e);
        return Err(format!("Failed to write 'c\\n' to {}: {}", ipv6_proc_path, e));
    }
    // Write IPv6 addresses
    for policy in ipv6_policies {
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
