// crates/reporter/src/lib.rs
use serde::Serialize;
pub mod file_audit;
pub mod process_audit;
pub mod fake_port_audit;
pub mod self_protect;
pub mod netlink_msg;
pub mod net_service_log; 
pub mod log_worker;
pub use log_worker::StartBashLog;
pub mod build_json;
pub use build_json::{build_alert_log_json,build_auto_process_list_json,build_batch_process_edr_json, build_open_port_json, build_self_protect_alert_log_json};

use std::fs;
use std::path::PathBuf;
use users::{get_user_by_uid, os::unix::UserExt};
#[repr(u32)]
#[derive(Debug, PartialEq)]
pub enum RulesType {
    SelfProtectionType = 0,
    LesouProtectionType = 1,
    TamperProtectionType = 2,
}

impl RulesType {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(RulesType::SelfProtectionType),
            1 => Some(RulesType::LesouProtectionType),
            2 => Some(RulesType::TamperProtectionType),
            _ => None,
        }
    }
}
#[derive(Serialize,  Debug)]
pub struct AuditLogInfo {
    pub file_path: Option<String>,
    pub rename_dir: Option<String>,
    pub exception_process: Option<String>,
    pub md5: Option<String>,
    pub n_type: u16,
    pub n_level: u32,
    pub n_time: u64,
    pub notice_remark: Option<String>,
    pub peripheral_name: Option<String>,
    pub peripheral_remark: Option<String>,
    pub peripheral_eid: Option<String>,
    pub p_param: Option<String>,
}

#[derive(Debug)]
pub struct EdrProcessLog {
    pub uid: String,
    pub hash: String,
    pub p_id: i32,
    pub p_dir: String,
    pub p_param: Option<String>,
    pub pp_hash: String,
    pub pp_id: i32,
    pub pp_dir: String,
    pub pp_param: Option<String>,
    pub time: i32,
    pub log_type: i32,
}

#[derive(Debug)]
pub struct AuditProcess {
    pub n_time: i64,
    pub str_name: String,
    pub str_vendor: String,
    pub str_package: String,
    pub n_process_id: u32,
    pub n_parent_id: u32,
    pub n_priority: i32,
    pub n_thread_count: i32,
    pub n_working_set_size: i64,
    pub str_start_time: String,
    pub str_executable_path: String,
    pub str_user: String,
    pub hash: String,
    pub map_depends: Vec<String>,
}


#[derive(Serialize,  Debug)]
pub struct SysNetLog {
    pub uid: Option<String>,
    pub p_id: i32,
    pub p_dir: Option<String>,
    pub res_ip: Option<String>,
    pub rs_port: u16,
    pub proto: u32,
    pub time: i32,
    pub log_type: i32,
    pub hash: Option<String>,
    pub source_ip: Option<String>,
    pub source_port: u16,
}

pub fn get_user_name(uid: u32) -> String {
    match get_user_by_uid(uid) {
        Some(user) => user.name().to_string_lossy().to_string(),
        None => "root".to_string(), // 默认 root
    }
}

/// 获取指定进程的可执行路径 `/proc/<pid>/exe`
pub fn get_process_path(pid: u32) -> Option<String> {
    let exe_path = format!("/proc/{}/exe", pid);
    match fs::read_link(&exe_path) {
        Ok(path_buf) => Some(path_buf.to_string_lossy().to_string()),
        Err(_) => None,
    }
}

#[derive(Serialize, Debug)]
pub struct OpenPortLog {
    pub weight: i32,
    pub time: i32,
    pub attack_ip: String,
    pub destination_ip: String,
    pub open_port: i32,
    pub redirect_ip: String,
    pub redirect_port: i32,
}


#[derive(Serialize,  Debug)]
pub struct SelfProtectLogInfo {
    pub file_dir: Option<String>,
    pub proc_dir: Option<String>,
    pub proc_hash: Option<String>,
    pub proc_param: Option<String>,
    pub target_dir: Option<String>,
    pub n_type: u16,
    pub n_level: u32,
    pub n_time: u64,
}

