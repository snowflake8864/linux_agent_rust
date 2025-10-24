use std::ffi::CStr;
use config::net_info::NETINFO_CONFIG;
use crate::netlink_msg::NetlinkNetlog;
use logging::{log_error, log_info};
use std::mem;
use std::ptr;
use std::sync::Arc;
use zcopy_mgr::{AvProcessInfo, ZcopyMgr};
use crate::{AuditLogInfo, EdrProcessLog, AuditProcess, get_user_name, get_process_path, build_alert_log_json, build_auto_process_list_json, build_batch_process_edr_json};
use process_mgr::get_md5_global;
use net_client::core::NetClient;
use tokio::time::Duration;
use common::manager::boot::BootManager;
#[derive(Clone)]
pub struct ProcessAuditHandler {
    zcopy_mgr: Arc<ZcopyMgr>,
    boot_manager: Arc<BootManager>,
}

impl ProcessAuditHandler {
    pub fn new(zcopy_mgr: Arc<ZcopyMgr>, boot_manager: Arc<BootManager>) -> Self {
        ProcessAuditHandler { zcopy_mgr, boot_manager }
    }

    pub async fn handle_process_zcopy_oper(
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


        if !self.zcopy_mgr.process_audit_succeed {
            return Err("ZcopyMgr file audit not initialized".to_string());
        }

        //log_info!("收到 NetlinkNetlog: {:?}", netlog);
        let mut processvec: Vec<AuditProcess> = Vec::new();
        let mut loginfo: Vec<AuditLogInfo> = Vec::new();
        let mut edr_logs: Vec<EdrProcessLog> = Vec::new();

        // 内部处理函数调用
        let mut iterate = |start: u32, end: u32| {
            for idx in start..end {
                if let Some(report) = self.zcopy_mgr.get_process_audit_data(idx as usize) {
                    //log_info!("report:{:?}",report);
                    process_one(report, &mut processvec, &mut loginfo, &mut edr_logs);
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
            /*
            log_info!(
                "file audit, start_idx={}, end_idx={}, max_idx={}",
                netlog.start_idx,
                netlog.end_idx,
                netlog.max_idx
            );
            */
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

        if processvec.len() > 0 {
            let url = format!("{}/v1/autouploadprocess", net_client.get_base_url().unwrap_or_default());
            let mut json_str = String::new();
            match build_auto_process_list_json(&processvec, &mut json_str) {
                Ok(()) => {
                    //log_info!("生成 JSON: {}", json_str);
                    match net_client.post_data_async(
                        &url,
                        &json_str,
                        Duration::from_secs(10),
                        self.boot_manager.get_token().await.as_deref(),
                    ).await {
                        Ok(response) => {/*log_info!("服务器响应: {}", response)*/},
                        Err(err) => eprintln!("发送指标失败: {}", err),
                    }

                }
                Err(e) => {
                    log_error!("构建 JSON 失败: {}", e);
                }
            }
            processvec.clear();
        }
        
        if loginfo.len() > 0 {
            let url = format!("{}/v1/alertupload", net_client.get_base_url().unwrap_or_default());
            let mut json_str = String::new();
            match build_alert_log_json(&loginfo, &mut json_str) {
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
            loginfo.clear();
        }
        
        if edr_logs.len() > 0 {
//            log_info!("edr_logs{:?}", edr_logs);
            let url = format!("{}/v1/putsyslog", net_client.get_base_url().unwrap_or_default());
            let mut json_str = String::new();
            match build_batch_process_edr_json(&edr_logs, &mut json_str) {
                Ok(()) => {
                    //log_info!("生成 JSON: {}", json_str);
                    match net_client.post_data_async(
                        &url,
                        &json_str,
                        Duration::from_secs(10),
                        self.boot_manager.get_token().await.as_deref(),
                    ).await {
                        //Ok(response) => {log_info!("服务器响应: {}", response)},
                        Ok(_) => {},
                        Err(err) => eprintln!("发送指标失败: {}", err),
                    }

                }
                Err(e) => {
                    log_error!("构建 JSON 失败: {}", e);
                }
            }
            edr_logs.clear();
        }
        // 此处可后续传入 processvec, loginfo, edr_logs 到处理逻辑
        Ok(())
    }
}

fn file_exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

fn process_one(
    proc_info: &AvProcessInfo,
    processvec: &mut Vec<AuditProcess>,
    loginfo: &mut Vec<AuditLogInfo>,
    edr_logs: &mut Vec<EdrProcessLog>,
) {
    /*
let cstr = unsafe { CStr::from_ptr(proc_info.path.as_ptr() as *const u8) };
*/
let cstr = unsafe { CStr::from_ptr(proc_info.path.as_ptr() as *const std::os::raw::c_char) };


    let path_str = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return,
    };
    let cfg = NETINFO_CONFIG.lock().unwrap();
    let parts: Vec<&str> = path_str.split(';').collect();
    let p_dir = parts.get(0).unwrap_or(&"").to_string();

    //log_info!("proc_info: {:?}  p_dir: {:?}", proc_info, p_dir);
    if p_dir.is_empty() || !file_exists(&p_dir) {
        return;
    }

    let hash = match get_md5_global(&p_dir) {
        Ok(h) => h,
        Err(_) => return,
    };
    //log_info!("proc_info: {:?}  p_dir: {:?}  hash: {:?} ", proc_info, p_dir, hash);
    // 处理 AuditProcess
    if cfg.proc_switch {
        if proc_info.type_ == 1101 || proc_info.type_ == 1001 {
            processvec.push(AuditProcess {
                n_time: 1692760326 as i64,
                str_name: "".into(),
                str_vendor: "".into(),
                str_package: "".into(),
                n_process_id: proc_info.pid() as u32,
                n_parent_id: proc_info.ppid() as u32,
                n_priority: 0,
                n_thread_count: 0,
                n_working_set_size: 0,
                str_start_time: "".into(),
                str_executable_path: p_dir.clone(),
                str_user: get_user_name(proc_info.uid() as u32),
                hash: hash.clone(),
                map_depends: vec![],
            });
        }

        let flags = proc_info.flags_parsed();
        if flags.level > 0  && proc_info.type_ > 0 {
            loginfo.push(AuditLogInfo {
                file_path: Some(p_dir.clone()),
                md5: Some(hash.clone()),
                n_type: proc_info.type_ as u16,
                n_level: flags.level as u32,
                n_time: 1692760326 as u64,
                rename_dir: None,
                notice_remark: None,
                exception_process: None,
                peripheral_name: None,
                peripheral_remark: None,
                peripheral_eid: None,
                p_param: None,
            });
        }
    }

    // 处理 EdrProcessLog
    if cfg.syslog_process_switch {
        let mut pp_dir = String::new();
        let mut pp_hash = String::new();

        if parts.len() >= 2 {
            pp_dir = parts[1].to_string();
            if file_exists(&pp_dir) {
                pp_hash = match get_md5_global(&pp_dir) {
                    Ok(h) => h,
                    Err(_) => return,
                };
            }
        } else if let Some(pp) = get_process_path(proc_info.ppid() as u32) {
            if file_exists(&pp) {
                pp_hash = match get_md5_global(&pp) {
                    Ok(h) => h,
                    Err(_) => return,
                };
                pp_dir = pp;
            }
        }

        if pp_hash.is_empty() {
            return;
        }

        edr_logs.push(EdrProcessLog {
            uid: proc_info.uid().to_string(),
            hash,
            p_id: proc_info.pid(),
            p_dir,
            p_param: None,
            pp_hash,
            pp_id: proc_info.ppid(),
            pp_dir,
            pp_param: None,
            time: 1692760326 as i32,
            log_type: 4,
        });
    }
}


