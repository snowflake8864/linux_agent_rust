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
#[derive(Serialize, Debug, Clone)]
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

/// Convert AuditLogInfo to AlertEvent and broadcast to gRPC AlertService.
/// 只广播三类：进程告警、文件审计、USB插拔。其余 n_type 不推 gRPC。
/// SSH 登录由 broadcast_ssh_log 单独处理。
/// 先落地到 alert.db，再广播给已订阅的在线客户端。
pub fn broadcast_audit_log(log: &AuditLogInfo) {
    let alert_type = match log.n_type {
        // 进程告警
        1001..=1002 | 1101..=1104 => 1, // PROCESS_ALERT
        // 模块告警
        1201..=1202 | 1301..=1302 => 1, // PROCESS_ALERT
        // 防篹改-文件夹
        2001..=2105 => 2, // FILE_ALERT
        // 防篹改-文件
        3001..=3105 => 2, // FILE_ALERT
        // 外设告警
        9003..=9008 => 3, // DEVICE_ALERT
        // 不在白名单内的不推 gRPC
        _ => {
            log::warn!("[alert] 未广播的 n_type={}, path={:?}", log.n_type, log.file_path);
            return;
        }
    };

    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    // 1. 先持久化到 alert.db，保证客户端断线组再连可以补读历史告警
    // path:   进程/文件=可执行路径, 外设=peripheral_name
    // identifier: 进程/文件/勒索=md5, 外设=peripheral_eid
    let row = local_store::alert_log::AlertLogRow {
        id:                  0,
        alert_type:          alert_type,
        level:               log.n_level as i32,
        process:             log.exception_process.clone().unwrap_or_default(),
        path:                match alert_type {
            3 => log.peripheral_name.clone().unwrap_or_default(),
            _ => log.file_path.clone().unwrap_or_default(),
        },
        pid:                 0,
        detail:              log.notice_remark.clone().unwrap_or_default(),
        identifier:          match alert_type {
            1 | 2 | 5 => log.md5.clone().unwrap_or_default(),
            3 => log.peripheral_eid.clone().unwrap_or_default(),
            _ => String::new(),
        },
        handle_status:       local_store::alert_log::HANDLE_STATUS_PENDING,
        handle_status_label: "未处理".to_string(),
        handle_user:         String::new(),
        handled_at:          String::new(),
        created_at:          now,
        n_type:              log.n_type as u32,
    };
    if let Err(e) = local_store::alert_log::insert(&row, {
        // 读取配置中的 alert_max_rows，0 = 不限制
        config::net_info::NETINFO_CONFIG
            .lock()
            .map(|c| c.db_policy.alert_max_rows)
            .unwrap_or(0)
    }) {
        logging::log_error!("[alert] 写入 alert.db 失败: {}", e);
    }

    // 2. 广播给已订阅的在线客户端
    grpc_gateway::notify::broadcast_alert(grpc_gateway::alert::AlertEvent {
        alert_id: uuid::Uuid::new_v4().to_string(),
        r#type: alert_type,
        level: log.n_level,
        timestamp: log.n_time,
        file_path: log.file_path.clone().unwrap_or_default(),
        process_name: log.exception_process.clone().unwrap_or_default(),
        md5: log.md5.clone().unwrap_or_default(),
        remark: log.notice_remark.clone().unwrap_or_default(),
        peripheral_name: log.peripheral_name.clone().unwrap_or_default(),
        peripheral_eid: log.peripheral_eid.clone().unwrap_or_default(),
        rename_dir: log.rename_dir.clone().unwrap_or_default(),
        p_param: log.p_param.clone().unwrap_or_default(),
        n_type: log.n_type as u32,
    });
}

/// Broadcast SysNetLog (network communication log) to gRPC AlertService.
pub fn broadcast_net_log(log: &crate::SysNetLog) {
    grpc_gateway::notify::broadcast_alert(grpc_gateway::alert::AlertEvent {
        alert_id: uuid::Uuid::new_v4().to_string(),
        r#type: 4, level: 1, timestamp: log.time as u64,
        file_path: log.p_dir.clone().unwrap_or_default(),
        process_name: String::new(),
        md5: log.hash.clone().unwrap_or_default(),
        remark: format!("proto:{} {}:{}", log.proto, log.source_ip.clone().unwrap_or_default(), log.source_port),
        peripheral_name: String::new(), peripheral_eid: String::new(),
        rename_dir: String::new(), p_param: String::new(),
        n_type: log.log_type as u32,
    });
}

/// Broadcast SyslogSshLog (SSH login log) to gRPC AlertService.
pub fn broadcast_ssh_log(log: &crate::SyslogSshLog) {
    grpc_gateway::notify::broadcast_alert(grpc_gateway::alert::AlertEvent {
        alert_id: uuid::Uuid::new_v4().to_string(),
        r#type: 0, level: if log.status == 0 { 1 } else { 2 },
        timestamp: log.time as u64,
        file_path: String::new(),
        process_name: format!("ssh:{}", log.username),
        md5: String::new(),
        remark: format!("IP:{} type:{}", log.ip, log.login_type),
        peripheral_name: String::new(), peripheral_eid: String::new(),
        rename_dir: String::new(), p_param: String::new(),
        n_type: log.log_type as u32,
    });
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


#[derive(Serialize, Debug)]
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

/// SSH登录日志结构
#[derive(Serialize, Debug, Clone)]
pub struct SyslogSshLog {
    pub ip: String,
    pub username: String,
    #[serde(rename = "type")]
    pub login_type: String,
    pub status: i32,
    pub log_type: i32,
    pub time: i64,
}

