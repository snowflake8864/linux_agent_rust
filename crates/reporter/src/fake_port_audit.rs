
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::collections::VecDeque;
use std::sync::{Arc, OnceLock, Mutex as StdMutex};
use crate::netlink_msg::NetlinkNetlog;
use logging::{log_error, log_info, log_warn};
use std::mem;
use std::ptr;
use zcopy_mgr::{OsecOpenportReport, ZcopyMgr, IpAddrUnion};
use crate::{OpenPortLog, build_open_port_json};
use net_client::core::NetClient;
use tokio::time::Duration;
use common::manager::boot::BootManager;

/// 全局虚开端口告警队列：eBPF 后端等直接 push，worker 批量 POST /v1/upOpenPort
/// （对齐驱动模式 netlink/zcopy → FakePortAuditHandler 的上报路径）
pub static OPEN_PORT_QUEUE: OnceLock<StdMutex<VecDeque<OpenPortLog>>> = OnceLock::new();

/// eBPF 等后端的同步接口：推入虚开端口命中告警（队列上限 500 条防洪）
pub fn push_open_port_log(log: OpenPortLog) {
    let q = OPEN_PORT_QUEUE.get_or_init(|| StdMutex::new(VecDeque::new()));
    if let Ok(mut g) = q.lock() {
        if g.len() >= 500 {
            g.pop_front();
            log_warn!("[openport] 告警队列满，丢弃最旧条目");
        }
        g.push_back(log);
    }
}

/// 批量取走积压的虚开端口告警（worker 用）
fn drain_open_port_logs() -> Vec<OpenPortLog> {
    let q = OPEN_PORT_QUEUE.get_or_init(|| StdMutex::new(VecDeque::new()));
    match q.lock() {
        Ok(mut g) => g.drain(..).collect(),
        Err(_) => Vec::new(),
    }
}

/// 虚开端口告警上报 worker：每 2 秒批量取队列并 POST /v1/upOpenPort。
/// main.rs 在启动时 spawn；eBPF 后端只管 push_open_port_log，无需感知网络配置。
pub async fn run_open_port_audit_worker(boot_manager: Arc<BootManager>) {
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    loop {
        interval.tick().await;
        let logs = drain_open_port_logs();
        if logs.is_empty() { continue; }

        let base_url = boot_manager.get_base_url();
        let client = match NetClient::new(Some(base_url.clone()), true) {
            Ok(c) => c,
            Err(err) => {
                log_error!("[openport] 创建 NetClient 失败: {}", err);
                continue;
            }
        };
        let url = format!("{}/v1/upOpenPort", base_url);
        let mut json_str = String::new();
        match build_open_port_json(&logs, &mut json_str) {
            Ok(()) => {
                let token = boot_manager.get_token().await;
                match client.post_data_async(&url, &json_str, Duration::from_secs(10), token.as_deref()).await {
                    Ok(_) => {}, //log_info!("[openport] 上报 {} 条成功", logs.len()),
                    Err(err) => log_error!("[openport] 上报 {} 条失败: {}", logs.len(), err),
                }
            }
            Err(e) => log_error!("[openport] 构建 JSON 失败: {}", e),
        }
    }
}

#[derive(Clone)]
pub struct FakePortAuditHandler {
    zcopy_mgr: Arc<ZcopyMgr>,
    boot_manager: Arc<BootManager>,
}

impl FakePortAuditHandler {
    pub fn new(zcopy_mgr: Arc<ZcopyMgr>, boot_manager: Arc<BootManager>) -> Self {
        FakePortAuditHandler { zcopy_mgr, boot_manager }
    }

    pub async fn handle_fake_port_zcopy_oper(
        &self,
        data: &[u8],
        data_len: u32,
    ) -> Result<(), String> {
        if data_len < mem::size_of::<NetlinkNetlog>() as u32 {
            return Err(format!(
                "数据长度太小，期望至少 {} 字节，实际是 {} 字节",
                mem::size_of::<NetlinkNetlog>(),
                data_len
            ));
        }

        let netlog: NetlinkNetlog = unsafe {
            ptr::read_unaligned(data.as_ptr() as *const NetlinkNetlog)
        };

        //log_info!("收到 NetlinkNetlog: {:?}", netlog);

        if !self.zcopy_mgr.process_audit_succeed {
            return Err("ZcopyMgr file audit not initialized".to_string());
        }

        let mut logVec: Vec<OpenPortLog> = Vec::new();

        // 内部处理函数调用
        let mut iterate = |start: u32, end: u32| {
            for idx in start..end {
                if let Some(report) = self.zcopy_mgr.get_openport_log_audit_data(idx as usize) {

                    process_one(report, &mut logVec);
                } else {
                    log_error!("无法获取索引 {} 的进程审计数据", idx);
                }
            }
        };

        if netlog.max_idx == 0 {
            if netlog.start_idx >= netlog.end_idx {
                return Err(format!(
                    "无效索引范围: start_idx={} >= end_idx={}",
                    netlog.start_idx, netlog.end_idx
                ));
            }
            /*
            log_info!(
                "file audit, start_idx={}, end_idx={}",
                netlog.start_idx,
                netlog.end_idx
            );
            */
            iterate(netlog.start_idx, netlog.end_idx);
        } else {
            iterate(0, netlog.start_idx);
            iterate(netlog.end_idx, netlog.max_idx);
        }
        let net_client = match NetClient::new(Some(self.boot_manager.get_base_url()), true) {
            Ok(client) => client,
            Err(err) => {
                eprintln!("创建 NetClient 失败: {}", err);
                return Err("创建 NetClient 失败".to_string());
            }
        };

        
        if logVec.len() > 0 {
            let url = format!("{}/v1/upOpenPort", net_client.get_base_url().unwrap_or_default());
            let mut json_str = String::new();
            match build_open_port_json(&logVec, &mut json_str) {
                Ok(()) => {
                    //log_info!("生成 JSON: {}", json_str);
                    match net_client.post_data_async(
                        &url,
                        &json_str,
                        Duration::from_secs(10),
                        self.boot_manager.get_token().await.as_deref(),
                    ).await {
                        Ok(response) => {},//{log_info!("服务器响应: {}", response)},
                        Err(err) => eprintln!("发送指标失败: {}", err),
                    }

                }
                Err(e) => {
                    log_error!("构建 JSON 失败: {}", e);
                }
            }
            logVec.clear();
        }
        
        // 此处可后续传入 processvec, loginfo, edr_logs 到处理逻辑
        Ok(())
    }
}



fn process_one(
    report: &OsecOpenportReport,
    log_vec: &mut Vec<OpenPortLog>,
) {

    // 安全提取 IP 字符串
    let (attack_ip, destination_ip, redirect_ip) = unsafe {
        let src_is_v4 = ip46_address_is_ip4(&report.src_ip);
        let dest_is_v4 = ip46_address_is_ip4(&report.dest_ip);

        let attack_ip = if src_is_v4 {
            let ip4 = u32::from_be(report.src_ip.v4.ip4);
            Ipv4Addr::from(ip4).to_string()
        } else {
            let ip = to_ipaddr_host_order(&report.src_ip);
            ip.to_string()
        };

        let destination_ip = if ip46_address_is_ip4(&report.attack_dest_ip) {
            let ip4 = u32::from_be(report.attack_dest_ip.v4.ip4);
            Ipv4Addr::from(ip4).to_string()
        } else {
            let ip = to_ipaddr_host_order(&report.attack_dest_ip);
            ip.to_string()
        };

        let redirect_ip = if dest_is_v4 {
            let ip4 = u32::from_be(report.dest_ip.v4.ip4);
            let ip_str = Ipv4Addr::from(ip4).to_string();
            if ip_str == "255.255.255.255" {
                "".to_string()
            } else {
                ip_str
            }
        } else {
            let ip = to_ipaddr_host_order(&report.dest_ip);
            let ip_str = ip.to_string();
            if ip_str == "::" {
                "".to_string()
            } else {
                ip_str
            }
        };

        (attack_ip, destination_ip, redirect_ip)
    };

    let open_port_log = OpenPortLog {
        weight: report.type_ as i32,
        time: 1692760326,
        attack_ip,
        destination_ip,
        open_port: report.src_port as i32,
        redirect_ip,
        redirect_port: report.dest_port as i32,
    };

    log_vec.push(open_port_log);
}
fn ip46_address_is_ip4(addr: &IpAddrUnion) -> bool {
    unsafe {
        addr.as_u8[0..12].iter().all(|&b| b == 0)
    }
}

pub fn to_ipaddr_host_order(addr: &IpAddrUnion) -> IpAddr {
    unsafe {
        if ip46_address_is_ip4(addr) {
            let ip4 = u32::from_be(addr.v4.ip4); // 转为主机序 u32
            IpAddr::V4(Ipv4Addr::from(ip4))
        } else {
            let bytes = addr.as_u8;
            IpAddr::V6(Ipv6Addr::from(bytes)) // from 已经处理字节序
        }
    }
}
