// crates/reporter/src/lib.rs
use serde::Serialize;
pub mod file_audit;
pub mod netlink_msg;
pub mod log_worker;
pub use log_worker::StartBashLog;
pub mod build_json;
pub use build_json::build_alert_log_json;
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
/*
#[derive(Serialize,Debug)]
pub struct FileAuditLogInfo {
    pub file_path: String,
    pub rename_dir: String,
    pub exception_process: String,
    pub md5: String,
    pub n_type: u16,
    pub n_level: u32,
    pub n_time: u64,
    pub notice_remark: String,
    pub peripheral_name: String,
    pub peripheral_remark: String,
    pub peripheral_eid: String,
    pub p_param: String,
}
*/
#[derive(Serialize,  Debug)]
pub struct FileAuditLogInfo {
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
