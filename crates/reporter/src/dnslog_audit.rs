
use std::net::Ipv6Addr;
use crate::netlink_msg::NetlinkNetlog;
use logging::{log_error, log_info};
use std::mem;
use std::ptr;
use std::sync::Arc;
use zcopy_mgr::{OsecDnsReport, ZcopyMgr};
use crate::DnsLog;
use net_client::core::NetClient;
use tokio::time::Duration;
use common::manager::boot::BootManager;

#[derive(Clone)]
pub struct DnsLogAuditHandler {
    zcopy_mgr: Arc<ZcopyMgr>,
    boot_manager: Arc<BootManager>,
}

impl DnsLogAuditHandler {
    pub fn new(zcopy_mgr: Arc<ZcopyMgr>, boot_manager: Arc<BootManager>) -> Self {
        DnsLogAuditHandler { zcopy_mgr, boot_manager }
    }

    pub async fn handle_dns_zcopy_oper(
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

        if !self.zcopy_mgr.dns_netlog_audit_succeed {
            return Err("ZcopyMgr dns audit not initialized".to_string());
        }

        let mut log_vec: Vec<DnsLog> = Vec::new();
        let mut iterate = |start: u32, end: u32| {
            for idx in start..end {
                if let Some(report) = self.zcopy_mgr.get_dns_log_audit_data(idx as usize) {
                    process_one(report, &mut log_vec);
                } else {
                    log_error!("无法获取索引 {} 的DNS审计数据", idx);
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
        if log_vec.len() > 0 {
            //log_info!("log_vec:{:?}", log_vec);
            let url = format!("{}/v1/putsyslog", net_client.get_base_url().unwrap_or_default());
            let mut json_str = String::new();
            match crate::build_dns_log_json(&log_vec, &mut json_str) {
                Ok(()) => {
                    log_info!("上报DNS日志, url={}, json={}", url, json_str);
                    match net_client.post_data_async(
                        &url,
                        &json_str,
                        Duration::from_secs(10),
                        self.boot_manager.get_token().await.as_deref(),
                    ).await {
                        Ok(_response) => {},
                        Err(err) => eprintln!("发送DNS日志失败: {}", err),
                    }
                }
                Err(e) => {
                    log_error!("构建 DNS JSON 失败: {}", e);
                }
            }
            log_vec.clear();
        }

        Ok(())
    }
}

fn process_one(
    report: &OsecDnsReport,
    log_vec: &mut Vec<DnsLog>,
) {
    // 跳过 ip_cnt == 0 的空记录
    if report.ip_cnt() == 0 {
        return;
    }

    // 提取 dns_name 为 C 字符串
    let dns_name = {
        let len = report.dns_name.iter().position(|&c| c == 0).unwrap_or(255);
        String::from_utf8_lossy(&report.dns_name[..len]).to_string()
    };
    // 跳过反向 DNS 查询 (.in-addr.arpa / .ip6.arpa)
    if dns_name.contains(".in-addr.arpa") || dns_name.contains(".ip6.arpa") {
        return;
    }
    // 跳过空域名
    if dns_name.is_empty() {
        return;
    }
    // 提取 comm 为 C 字符串
    let comm = {
        let len = report.comm.iter().position(|&c| c == 0).unwrap_or(128);
        String::from_utf8_lossy(&report.comm[..len]).to_string()
    };

    // 构建 res_ip 字符串（分号分隔的IP列表）
    let mut res_ip = String::new();
    unsafe {
        if !report.is_ipv6() {
            // IPv4: ip_addrs.ipv4[i] 为网络字节序 u32
            for i in 0..report.ip_cnt() as usize {
                if i >= 12 {
                    break;
                }
                let raw = report.ip_addrs.ipv4[i];
                if raw == 0 {
                    break;
                }
                let addr = u32::from_be(raw);
                res_ip.push_str(&format!(
                    "{}.{}.{}.{};",
                    (addr >> 24) as u8,
                    (addr >> 16) as u8,
                    (addr >> 8) as u8,
                    addr as u8,
                ));
            }
        } else {
            // IPv6: 每 16 字节一个地址
            for i in 0..report.ip_cnt() as usize {
                let offset = i * 16;
                if offset + 16 > 48 {
                    break;
                }
                // 检查是否全零（结束标记）
                let slice = &report.ip_addrs.ipv6[offset..offset + 16];
                if slice.iter().all(|&b| b == 0) {
                    break;
                }
                let addr = Ipv6Addr::from(
                    <[u8; 16]>::try_from(slice).unwrap()
                );
                res_ip.push_str(&format!("{};", addr));
            }
        }
    }

    let dns_log = DnsLog {
        uid: None,
        p_id: report.pid as i32,
        p_dir: if comm.is_empty() { None } else { Some(comm) },
        domain_name: Some(dns_name),
        res_ip: if res_ip.is_empty() { Some("-".to_string()) } else { Some(res_ip) },
        time: 1692760326,
        log_type: 1,
        hash: None,
    };
/* 
    log_info!("DNS audit record: pid={}, comm={}, domain={}, res_ip={}",
        dns_log.p_id,
        dns_log.p_dir.as_deref().unwrap_or("-"),
        dns_log.domain_name.as_deref().unwrap_or("-"),
        dns_log.res_ip.as_deref().unwrap_or("-"));
*/
    log_vec.push(dns_log);
}
