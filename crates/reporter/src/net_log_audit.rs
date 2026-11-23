//! eBPF 模式下对内/对外通信日志的上报队列与 worker。
//!
//! 与驱动模式 `net_service_log.rs` 对齐：
//! - 对内(log_type=3)：按业务端口反查业务进程，补全 pid/path/hash；
//! - 对外(log_type=2)：pid/comm 由 BPF kprobe 在 connect 时采集；
//! - 最终批量 POST `/v1/putsyslog`（不做 gRPC 广播，与驱动路径一致）。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use common::manager::boot::BootManager;
use hostinfo::net_app::model::get_port_from_state;
use logging::{log_error, log_warn};
use net_client::core::NetClient;
use process_mgr::get_md5_global;
use tokio::time::Duration;

use crate::build_json::build_batch_syslog_net_json;
use crate::SysNetLog;

/// 全局对内/对外通信日志队列：eBPF 后端直接 push，worker 批量 POST。
pub static NET_LOG_QUEUE: OnceLock<StdMutex<VecDeque<SysNetLog>>> = OnceLock::new();

/// eBPF 后端的同步接口：推入一条通信日志（队列上限 1000 条防洪）。
pub fn push_net_log(log: SysNetLog) {
    let q = NET_LOG_QUEUE.get_or_init(|| StdMutex::new(VecDeque::new()));
    if let Ok(mut g) = q.lock() {
        if g.len() >= 1000 {
            g.pop_front();
            log_warn!("[netlog] 队列满，丢弃最旧条目");
        }
        g.push_back(log);
    }
}

fn drain_net_logs() -> Vec<SysNetLog> {
    let q = NET_LOG_QUEUE.get_or_init(|| StdMutex::new(VecDeque::new()));
    match q.lock() {
        Ok(mut g) => g.drain(..).collect(),
        Err(_) => Vec::new(),
    }
}

/// 对内通信补全业务进程信息（pid/path/hash），与驱动 `handle_internal_communication_log` 一致。
fn enrich_inner(log: &mut SysNetLog) {
    let business = get_port_from_state(log.rs_port)
        .or_else(|| get_port_from_state(log.source_port));
    let Some(business) = business else { return };

    if business.pid > 0 {
        log.p_id = business.pid;
    }
    if !business.process_path.is_empty() {
        log.p_dir = Some(business.process_path.clone());
        if business.process_path != "--" {
            match get_md5_global(&business.process_path) {
                Ok(md5) => log.hash = Some(md5),
                Err(_) => log.hash = None,
            }
        }
    }
}

/// 对内/对外通信日志上报 worker：每 2 秒批量取队列并 POST `/v1/putsyslog`。
/// main.rs 在启动时 spawn；eBPF 后端只管 push_net_log，无需感知网络配置。
pub async fn run_net_log_worker(boot_manager: Arc<BootManager>) {
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    loop {
        interval.tick().await;
        let mut logs = drain_net_logs();
        if logs.is_empty() {
            continue;
        }

        for log in logs.iter_mut() {
            if log.log_type == 3 {
                enrich_inner(log);
            }
        }

        let base_url = boot_manager.get_base_url();
        let client = match NetClient::new(Some(base_url.clone()), true) {
            Ok(c) => c,
            Err(err) => {
                log_error!("[netlog] 创建 NetClient 失败: {}", err);
                continue;
            }
        };
        let url = format!("{}/v1/putsyslog", base_url);
        let mut json_str = String::new();
        match build_batch_syslog_net_json(&logs, &mut json_str) {
            Ok(()) => {
                /*
                log_info!(
                    "[netlog] 准备上报 {} 条, log_types={:?}, payload={}",
                    logs.len(),
                    log_types,
                    json_str
                );
                */
                let token = boot_manager.get_token().await;
                match client
                    .post_data_async(&url, &json_str, Duration::from_secs(10), token.as_deref())
                    .await
                {
                    // Ok(_) => log_info!(
                    //     "[netlog] 上报 {} 条通信日志成功, log_types={:?}",
                    //     logs.len(),
                    //     log_types
                    // ),
                    Ok(_) => {}
                    Err(err) => log_error!("[netlog] 上报 {} 条失败: {}", logs.len(), err),
                }
            }
            Err(e) => log_error!("[netlog] 构建 JSON 失败: {}", e),
        }
    }
}
