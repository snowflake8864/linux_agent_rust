use std::ffi::CStr;
use std::mem;
use std::ptr;
use std::sync::Arc;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};
use net_client::core::NetClient;
use crate::build_json::build_batch_syslog_net_json;
use crate::netlink_msg::NetlinkNetlog;
use logging::{log_error, log_info};
use zcopy_mgr::{OsecNetworkReport, ZcopyMgr, IpAddrUnion};
use process_mgr::get_md5_global;
use hostinfo::net_app::model::{get_port_from_state};
use tokio::time::Duration;
use crate::SysNetLog;
use common::manager::boot::BootManager;

fn ip46_address_is_ip4(addr: &IpAddrUnion) -> bool {
    unsafe {
        addr.as_u8[0..12].iter().all(|&b| b == 0)
    }
}

fn ip_addr_union_to_ipaddr(addr: &IpAddrUnion) -> IpAddr {
    unsafe {
        if ip46_address_is_ip4(addr) {
            let ip4 = addr.v4.ip4.to_be_bytes();
            IpAddr::V4(Ipv4Addr::new(ip4[0], ip4[1], ip4[2], ip4[3]))
        } else {
            let bytes = addr.as_u8;
            IpAddr::V6(Ipv6Addr::new(
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
                u16::from_be_bytes([bytes[4], bytes[5]]),
                u16::from_be_bytes([bytes[6], bytes[7]]),
                u16::from_be_bytes([bytes[8], bytes[9]]),
                u16::from_be_bytes([bytes[10], bytes[11]]),
                u16::from_be_bytes([bytes[12], bytes[13]]),
                u16::from_be_bytes([bytes[14], bytes[15]]),
            ))
        }
    }
}
pub fn to_ipaddr_host_order(addr: &IpAddrUnion) -> IpAddr {
    unsafe {
        if ip46_address_is_ip4(addr) {
            let ip4 = u32::from_be(addr.v4.ip4).to_be_bytes();
            IpAddr::V4(Ipv4Addr::from(ip4))
        } else {
            let bytes = addr.as_u8;
            IpAddr::V6(Ipv6Addr::from(bytes))
        }

    }
}
fn is_change(last: &OsecNetworkReport, current: &OsecNetworkReport) -> bool {
    unsafe {
        let src_changed = last.src.as_u64[0] != current.src.as_u64[0] ||
                         last.src.as_u64[1] != current.src.as_u64[1];
        let dst_changed = last.dst.as_u64[0] != current.dst.as_u64[0] ||
                         last.dst.as_u64[1] != current.dst.as_u64[1];
        let src_port_changed = last.src_port.to_be() != current.src_port.to_be();
        let dest_port_changed = last.dest_port.to_be() != current.dest_port.to_be();
        let pid_changed = last.pid != current.pid;

        src_changed || dst_changed || src_port_changed || dest_port_changed || pid_changed
    }
}

#[derive(Clone)]
pub struct NetServiceLogHandler {
    zcopy_mgr: Arc<ZcopyMgr>,
    boot_manager: Arc<BootManager>,
}

impl NetServiceLogHandler {
    pub fn new(zcopy_mgr: Arc<ZcopyMgr>, boot_manager: Arc<BootManager>) -> Self {
        NetServiceLogHandler {
            zcopy_mgr,
            boot_manager,
        }
    }

    pub async fn handle_internal_communication_log(
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

        if !self.zcopy_mgr.file_audit_succeed {
            return Err("ZcopyMgr file audit not initialized".to_string());
        }

        let mut vec_net_log: Vec<SysNetLog> = Vec::new();
        let mut pre_report: Option<&OsecNetworkReport> = None;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i32)
            .unwrap_or(0);

        if netlog.max_idx == 0 {
            if netlog.start_idx >= netlog.end_idx {
                return Err(format!(
                    "无效索引范围: start_idx={} >= end_idx={}",
                    netlog.start_idx,
                    netlog.end_idx
                ));
            }


            for idx in netlog.start_idx..netlog.end_idx {
                if let Some(report) = self.zcopy_mgr.get_in_netlog_audit_data(idx as usize) {
                    if let Some(pre) = pre_report {
                        if !is_change(&report, pre) {
                            //log_info!("net is not change for index {}", idx);
                            continue;
                        }
                    }
                    pre_report = Some(report);
/*
                    let comm = unsafe {
                        CStr::from_ptr(report.comm.as_ptr() as *const u8)
                            .to_string_lossy()
                            .into_owned()
                    };
*/
                    let comm = unsafe {
                        let comm_ptr = report.comm.as_ptr() as *const std::os::raw::c_char;
                        CStr::from_ptr(comm_ptr)
                            .to_string_lossy()
                            .into_owned()
                    };
                    let mut sys_log = SysNetLog {
                        uid: None,
                        p_id: report.pid as i32,
                        p_dir: Some(comm.clone()),
                        res_ip: Some(to_ipaddr_host_order(&report.dst).to_string()),
                        rs_port: report.dest_port.to_be(),
                        proto: 6,
                        time: current_time,
                        log_type: 3,
                        hash: None,
                        source_ip: Some(to_ipaddr_host_order(&report.src).to_string()),
                        source_port: report.src_port.to_be(),
                    };

                    let business_port = get_port_from_state(sys_log.source_port)
                        .or_else(|| get_port_from_state(sys_log.rs_port));

                    if let Some(business) = business_port {
                        if business.pid > 0 {
                            sys_log.p_id = business.pid;
                        }
                        sys_log.p_dir = Some(business.process_path.clone());

                        if sys_log.p_dir.as_ref().map_or(false, |s| !s.is_empty()) {
                            let p_dir = sys_log.p_dir.as_ref().unwrap();
                            match get_md5_global(p_dir) {
                                Ok(md5) => sys_log.hash = Some(md5),
                                Err(e) => {
                                    sys_log.hash = None;
                                    log_error!("Failed to get MD5 for {}: {}", p_dir, e);
                                }
                            }
                        }
                    }
                    vec_net_log.push(sys_log);
                } else {
                    log_error!("无法获取索引 {} 的文件审计数据", idx);
                }
            }
        } else {
            for idx in 0..netlog.start_idx {
                if let Some(report) = self.zcopy_mgr.get_in_netlog_audit_data(idx as usize) {
                    if let Some(pre) = pre_report {
                        if !is_change(&report, pre) {
//                            log_info!("net is not change for index {}", idx);
                            continue;
                        }
                    }
                    pre_report = Some(report);

/*
                    let comm = unsafe {
                        CStr::from_ptr(report.comm.as_ptr() as *const u8)
                            .to_string_lossy()
                            .into_owned()
                    };
*/
                    let comm = unsafe {
                        let comm_ptr = report.comm.as_ptr() as *const std::os::raw::c_char;
                        CStr::from_ptr(comm_ptr)
                            .to_string_lossy()
                            .into_owned()
                    };

                    let mut sys_log = SysNetLog {
                        uid: None,
                        p_id: report.pid as i32,
                        p_dir: Some(comm.clone()),
                        res_ip: Some(to_ipaddr_host_order(&report.dst).to_string()),
                        rs_port: report.dest_port.to_be(),
                        proto: 6,
                        time: current_time,
                        log_type: 3,
                        hash: None,
                        source_ip: Some(to_ipaddr_host_order(&report.src).to_string()),
                        source_port: report.src_port.to_be(),
                    };

                    let business_port = get_port_from_state(sys_log.source_port)
                        .or_else(|| get_port_from_state(sys_log.rs_port));

                    if let Some(business) = business_port {
                        if business.pid > 0 {
                            sys_log.p_id = business.pid;
                        }
                        sys_log.p_dir = Some(business.process_path.clone());

                        if sys_log.p_dir.as_ref().map_or(false, |s| !s.is_empty()) {
                            let p_dir = sys_log.p_dir.as_ref().unwrap();
                            match get_md5_global(p_dir) {
                                Ok(md5) => sys_log.hash = Some(md5),
                                Err(e) => {
                                    sys_log.hash = None;
                                    log_error!("Failed to get MD5 for {}: {}", p_dir, e);
                                }
                            }
                        }
                    }
                    vec_net_log.push(sys_log);
                } else {
                    log_error!("无法获取索引 {} 的文件审计数据", idx);
                }
            }

            for idx in netlog.end_idx..netlog.max_idx {
                if let Some(report) = self.zcopy_mgr.get_in_netlog_audit_data(idx as usize) {
                    if let Some(pre) = pre_report {
                        if !is_change(&report, pre) {
                            //log_info!("net is not change for index {}", idx);
                            continue;
                        }
                    }
                    pre_report = Some(report);


/*
                    let comm = unsafe {
                        CStr::from_ptr(report.comm.as_ptr() as *const u8)
                            .to_string_lossy()
                            .into_owned()
                    };
*/
                    let comm = unsafe {
                        let comm_ptr = report.comm.as_ptr() as *const std::os::raw::c_char;
                        CStr::from_ptr(comm_ptr)
                            .to_string_lossy()
                            .into_owned()
                    };

                    let mut sys_log = SysNetLog {
                        uid: None,
                        p_id: report.pid as i32,
                        p_dir: Some(comm.clone()),
                        res_ip: Some(to_ipaddr_host_order(&report.dst).to_string()),
                        rs_port: report.dest_port.to_be(),
                        proto: 6,
                        time: current_time,
                        log_type: 3,
                        hash: None,
                        source_ip: Some(to_ipaddr_host_order(&report.src).to_string()),
                        source_port: report.src_port.to_be(),
                    };

                    let business_port = get_port_from_state(sys_log.source_port)
                        .or_else(|| get_port_from_state(sys_log.rs_port));

                    if let Some(business) = business_port {
                        if business.pid > 0 {
                            sys_log.p_id = business.pid;
                        }
                        sys_log.p_dir = Some(business.process_path.clone());

                        if sys_log.p_dir.as_ref().map_or(false, |s| !s.is_empty()) {
                            let p_dir = sys_log.p_dir.as_ref().unwrap();
                            match get_md5_global(p_dir) {
                                Ok(md5) => sys_log.hash = Some(md5),
                                Err(e) => {
                                    sys_log.hash = None;
                                    log_error!("Failed to get MD5 for {}: {}", p_dir, e);
                                }
                            }
                        }
                    }
                    vec_net_log.push(sys_log);
                } else {
                    log_error!("无法获取索引 {} 的文件审计数据", idx);
                }
            }
        }

        if !vec_net_log.is_empty() {
            // self.upload_http_syslog(batch_json).await?;
            //log_info!("===={:?}",vec_net_log);

                let net_client = match NetClient::new(Some(self.boot_manager.get_base_url()), true) {
                    Ok(client) => client,
                    Err(err) => {
                        eprintln!("创建 NetClient 失败: {}", err);
                        return Err("创建 NetClient 失败".to_string());
                    }
                };

            let url = format!("{}/v1/putsyslog", net_client.get_base_url().unwrap_or_default());
            let mut json_str = String::new();
            match build_batch_syslog_net_json(&vec_net_log, &mut json_str) {
                Ok(()) => {
                    //log_info!("生成 JSON: {}", json_str);
                    match net_client.post_data_async(
                        &url,
                        &json_str,
                        Duration::from_secs(10),
                        self.boot_manager.get_token().await.as_deref(),
                    ).await {
                        Ok(response) => { for log in &vec_net_log { crate::broadcast_net_log(log); } },
                        Err(err) => eprintln!("发送指标失败: {}", err),
                    }

                }
                Err(e) => {
                    log_error!("构建 JSON 失败: {}", e);
                }
            }
            vec_net_log.clear();
        }

        Ok(())
    }

    pub async fn handle_external_communication_log(
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

//        log_info!("收到 NetlinkNetlog: {:?}", netlog);

        if !self.zcopy_mgr.file_audit_succeed {
            return Err("ZcopyMgr file audit not initialized".to_string());
        }

        let mut vec_net_log: Vec<SysNetLog> = Vec::new();
        let mut pre_report: Option<&OsecNetworkReport> = None;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i32)
            .unwrap_or(0);

        if netlog.max_idx == 0 {
            if netlog.start_idx >= netlog.end_idx {
                return Err(format!(
                    "无效索引范围: start_idx={} >= end_idx={}",
                    netlog.start_idx,
                    netlog.end_idx
                ));
            }


            for idx in netlog.start_idx..netlog.end_idx {
                if let Some(report) = self.zcopy_mgr.get_out_netlog_audit_data(idx as usize) {
                    if let Some(pre) = pre_report {
                        if !is_change(&report, pre) {
                           // log_info!("net is not change for index {}", idx);
                            continue;
                        }
                    }
                    pre_report = Some(report);
                    let comm = unsafe {
                        let comm_ptr = report.comm.as_ptr() as *const std::os::raw::c_char;
                        CStr::from_ptr(comm_ptr)
                            .to_string_lossy()
                            .into_owned()
                    };
                    let mut sys_log = SysNetLog {
                        uid: None,
                        p_id: report.pid as i32,
                        p_dir: Some(comm.clone()),
                        res_ip: Some(to_ipaddr_host_order(&report.dst).to_string()),
                        rs_port: report.dest_port.to_be(),
                        proto: 6,
                        time: current_time,
                        log_type: 2,
                        hash: None,
                        source_ip: Some(to_ipaddr_host_order(&report.src).to_string()),
                        source_port: report.src_port.to_be(),
                    };


                    if sys_log.p_dir.as_ref().map_or(false, |s| !s.is_empty()) {
                        let p_dir = sys_log.p_dir.as_ref().unwrap();
                        match get_md5_global(p_dir) {
                            Ok(md5) => sys_log.hash = Some(md5),
                            Err(e) => {
                                sys_log.hash = None;
                                log_error!("Failed to get MD5 for {}: {}", p_dir, e);
                            }
                        }
                    }

                    vec_net_log.push(sys_log);
                } else {
                    log_error!("无法获取索引 {} 的文件审计数据", idx);
                }
            }
        } else {
            for idx in 0..netlog.start_idx {
                if let Some(report) = self.zcopy_mgr.get_in_netlog_audit_data(idx as usize) {
                    if let Some(pre) = pre_report {
                        if !is_change(&report, pre) {
//                            log_info!("net is not change for index {}", idx);
                            continue;
                        }
                    }
                    pre_report = Some(report);

                    let comm = unsafe {
                        let comm_ptr = report.comm.as_ptr() as *const std::os::raw::c_char;
                        CStr::from_ptr(comm_ptr)
                            .to_string_lossy()
                            .into_owned()
                    };

                    let mut sys_log = SysNetLog {
                        uid: None,
                        p_id: report.pid as i32,
                        p_dir: Some(comm.clone()),
                        res_ip: Some(to_ipaddr_host_order(&report.dst).to_string()),
                        rs_port: report.dest_port.to_be(),
                        proto: 6,
                        time: current_time,
                        log_type: 2,
                        hash: None,
                        source_ip: Some(to_ipaddr_host_order(&report.src).to_string()),
                        source_port: report.src_port.to_be(),
                    };


                    if sys_log.p_dir.as_ref().map_or(false, |s| !s.is_empty()) {
                        let p_dir = sys_log.p_dir.as_ref().unwrap();
                        match get_md5_global(p_dir) {
                            Ok(md5) => sys_log.hash = Some(md5),
                            Err(e) => {
                                sys_log.hash = None;
                                log_error!("Failed to get MD5 for {}: {}", p_dir, e);
                            }
                        }
                    }

                    vec_net_log.push(sys_log);
                } else {
                    log_error!("无法获取索引 {} 的文件审计数据", idx);
                }
            }

            for idx in netlog.end_idx..netlog.max_idx {
                if let Some(report) = self.zcopy_mgr.get_in_netlog_audit_data(idx as usize) {
                    if let Some(pre) = pre_report {
                        if !is_change(&report, pre) {
                            //log_info!("net is not change for index {}", idx);
                            continue;
                        }
                    }
                    pre_report = Some(report);


                    let comm = unsafe {
                        let comm_ptr = report.comm.as_ptr() as *const std::os::raw::c_char;
                        CStr::from_ptr(comm_ptr)
                            .to_string_lossy()
                            .into_owned()
                    };

                    let mut sys_log = SysNetLog {
                        uid: None,
                        p_id: report.pid as i32,
                        p_dir: Some(comm.clone()),
                        res_ip: Some(to_ipaddr_host_order(&report.dst).to_string()),
                        rs_port: report.dest_port.to_be(),
                        proto: 6,
                        time: current_time,
                        log_type: 2,
                        hash: None,
                        source_ip: Some(to_ipaddr_host_order(&report.src).to_string()),
                        source_port: report.src_port.to_be(),
                    };

                    if sys_log.p_dir.as_ref().map_or(false, |s| !s.is_empty()) {
                        let p_dir = sys_log.p_dir.as_ref().unwrap();
                        match get_md5_global(p_dir) {
                            Ok(md5) => sys_log.hash = Some(md5),
                            Err(e) => {
                                sys_log.hash = None;
                                log_error!("Failed to get MD5 for {}: {}", p_dir, e);
                            }
                        }
                    }

                    vec_net_log.push(sys_log);
                } else {
                    log_error!("无法获取索引 {} 的文件审计数据", idx);
                }
            }
        }

        if !vec_net_log.is_empty() {
            // self.upload_http_syslog(batch_json).await?;
            //log_info!("===={:?}",vec_net_log);

                let net_client = match NetClient::new(Some(self.boot_manager.get_base_url()), true) {
                    Ok(client) => client,
                    Err(err) => {
                        eprintln!("创建 NetClient 失败: {}", err);
                        return Err("创建 NetClient 失败".to_string());
                    }
                };

            let url = format!("{}/v1/putsyslog", net_client.get_base_url().unwrap_or_default());
            let mut json_str = String::new();
            match build_batch_syslog_net_json(&vec_net_log, &mut json_str) {
                Ok(()) => {
                    //log_info!("生成 JSON: {}", json_str);
                    match net_client.post_data_async(
                        &url,
                        &json_str,
                        Duration::from_secs(10),
                        self.boot_manager.get_token().await.as_deref(),
                    ).await {
                        Ok(response) => { for log in &vec_net_log { crate::broadcast_net_log(log); } },
                        Err(err) => eprintln!("发送指标失败: {}", err),
                    }

                }
                Err(e) => {
                    log_error!("构建 JSON 失败: {}", e);
                }
            }
            vec_net_log.clear();
        }

        Ok(())
    }
}


