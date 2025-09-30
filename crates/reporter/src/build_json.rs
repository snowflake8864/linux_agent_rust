use serde::Serialize;
use logging::{log_info, log_error};
use serde_json;
use crate::{AuditLogInfo,AuditProcess, EdrProcessLog, SysNetLog,OpenPortLog};
use process_mgr::get_md5_global;

/*
// build_alert_log_json 函数，接受切片 &[FileAuditLogInfo]
pub fn build_alert_log_json(log_info: &[FileAuditLogInfo], str_json: &mut String) -> Result<(), String> {
    // 辅助结构体，用于序列化单个日志条目
    #[derive(Serialize)]
    struct LogEntry {
        level: u32,
        time: u64,
        #[serde(rename = "type")]
        n_type: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        dir: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        hash: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rename_dir: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        notice_remark: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        exception_process: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        peripheral_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        peripheral_remark: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        peripheral_eid: Option<String>,
        p_param: Option<String>,
    }

    // 将 FileAuditLogInfo 转换为 LogEntry
    let entries: Vec<LogEntry> = log_info
        .iter()
        .map(|log| LogEntry {
            level: log.n_level,
            time: log.n_time,
            n_type: log.n_type,
            dir: log.file_path.clone(),
            hash: log.md5.clone(),
            rename_dir: log.rename_dir.clone(),
            notice_remark: log.notice_remark.clone(),
            exception_process: log.exception_process.clone(),
            peripheral_name: log.peripheral_name.clone(),
            peripheral_remark: log.peripheral_remark.clone(),
            peripheral_eid: log.peripheral_eid.clone(),
            p_param: log.p_param.clone().or(log.file_path.clone()), // 若 p_param 为 None，使用 file_path
        })
        .collect();

    // 检查是否为空
    if entries.is_empty() {
        log_error!("没有有效的日志条目可添加到 JSON。");
        return Err("No valid log entries".to_string());
    }

    // 构建 JSON 对象
    let json_obj = serde_json::json!({
        "alert": entries
    });

    // 序列化为未格式化的字符串
    *str_json = serde_json::to_string(&json_obj)
        .map_err(|e| format!("JSON 序列化失败: {}", e))?;

    Ok(())
}
*/

pub fn build_alert_log_json(log_info: &[AuditLogInfo], str_json: &mut String) -> Result<(), String> {
    #[derive(Serialize)]
    struct LogEntry {
        level: u32,
        time: u64,
        #[serde(rename = "type")]
        n_type: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        dir: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        hash: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rename_dir: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        notice_remark: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        exception_process: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        peripheral_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        peripheral_remark: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        peripheral_eid: Option<String>,
        p_param: Option<String>,
    }

    let entries: Vec<LogEntry> = log_info
        .iter()
        .map(|log| LogEntry {
            level: log.n_level,
            time: log.n_time,
            n_type: log.n_type,
            dir: log.file_path.clone(),
            hash: log.md5.clone(),
            rename_dir: log.rename_dir.clone(),
            notice_remark: log.notice_remark.clone(),
            exception_process: log.exception_process.clone(),
            peripheral_name: log.peripheral_name.clone(),
            peripheral_remark: log.peripheral_remark.clone(),
            peripheral_eid: log.peripheral_eid.clone(),
            p_param: log.p_param.clone().or(log.file_path.clone()),
        })
        .collect();

    if entries.is_empty() {
        log_error!("没有有效的日志条目可添加到 JSON。");
        return Err("No valid log entries".to_string());
    }

    // 先序列化entries数组为字符串
    let entries_str = serde_json::to_string(&entries)
        .map_err(|e| format!("Entries序列化失败: {}", e))?;

    // 构建包含字符串形式数组的JSON对象
    let json_obj = serde_json::json!({
        "alert": entries_str
    });

    *str_json = serde_json::to_string(&json_obj)
        .map_err(|e| format!("JSON序列化失败: {}", e))?;

    Ok(())
}

pub fn serialize_alert_logs_to_json(log_info: &[AuditLogInfo], str_json: &mut String) -> Result<(), String> {
    #[derive(Serialize)]
    struct LogEntry {
        level: u32,
        time: u64,
        #[serde(rename = "type")]
        n_type: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        dir: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        hash: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        rename_dir: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        notice_remark: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        exception_process: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        peripheral_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        peripheral_remark: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        peripheral_eid: Option<String>,
        p_param: Option<String>,
    }

    let entries: Vec<LogEntry> = log_info
        .iter()
        .map(|log| LogEntry {
            level: log.n_level,
            time: log.n_time,
            n_type: log.n_type,
            dir: log.file_path.clone(),
            hash: log.md5.clone(),
            rename_dir: log.rename_dir.clone(),
            notice_remark: log.notice_remark.clone(),
            exception_process: log.exception_process.clone(),
            peripheral_name: log.peripheral_name.clone(),
            peripheral_remark: log.peripheral_remark.clone(),
            peripheral_eid: log.peripheral_eid.clone(),
            p_param: log.p_param.clone().or(log.file_path.clone()),
        })
    .collect();

    if entries.is_empty() {
        log_error!("没有有效的日志条目可添加到 JSON。");
        return Err("No valid log entries".to_string());
    }

    // 直接构建包含数组的 JSON 对象（不转成字符串！）
    let json_obj = serde_json::json!({
        "alert": entries  // ← 这里直接传入 Vec<LogEntry>，serde_json 会正确序列化为数组
    });

    *str_json = serde_json::to_string(&json_obj)
        .map_err(|e| format!("JSON序列化失败: {}", e))?;

    Ok(())
}

pub fn build_auto_process_list_json(process_info: &[AuditProcess], str_json: &mut String) -> Result<(), String> {
    #[derive(Serialize)]
    struct ProcessEntry {
        id: u32,
        user: String,
        dir: String,
        hash: String,
        copyright: &'static str,
        introduce: &'static str,
    }

    let entries: Vec<ProcessEntry> = process_info
        .iter()
        .map(|p| {
            let hash = if p.hash.is_empty() {
                get_md5_global(&p.str_executable_path).unwrap_or_default()
            } else {
                p.hash.clone()
            };

            ProcessEntry {
                id: p.n_process_id,
                user: p.str_user.clone(),
                dir: p.str_executable_path.clone(),
                hash,
                copyright: "linux gun",
                introduce: "linux",
            }
        })
        .collect();

    if entries.is_empty() {
        log_error!("没有有效的进程条目可添加到 JSON。");
        return Err("No valid process entries".to_string());
    }

    let entries_str = serde_json::to_string(&entries)
        .map_err(|e| format!("Entries序列化失败: {}", e))?;

    let json_obj = serde_json::json!({
        "proclist": entries_str
    });

    *str_json = serde_json::to_string(&json_obj)
        .map_err(|e| format!("JSON序列化失败: {}", e))?;

    Ok(())
}


pub fn build_batch_process_edr_json(logs: &[EdrProcessLog], str_json: &mut String) -> Result<(), String> {
    #[derive(Serialize)]
    struct EdrLogEntry {
        uid: String,
        hash: String,
        p_id: u32,
        p_dir: String,
        p_param: String,
        pp_hash: String,
        pp_id: u32,
        pp_dir: String,
        pp_param: String,
        log_type: u32,
        time: i32,
    }

    let entries: Vec<EdrLogEntry> = logs
        .iter()
        .map(|log| {
            EdrLogEntry {
                uid: log.uid.clone(),
                hash: log.hash.clone(),
                p_id: log.p_id as u32,
                p_dir: log.p_dir.clone(),
                p_param: log.p_param.clone().unwrap_or_else(|| log.p_dir.clone()),
                pp_hash: log.pp_hash.clone(),
                pp_id: log.pp_id as u32,
                pp_dir: log.pp_dir.clone(),
                pp_param: log.pp_param.clone().unwrap_or_default(),
                log_type: log.log_type as u32,
                time: log.time,
            }
        })
        .collect();

    if entries.is_empty() {
        log_error!("没有有效的 EDR 日志条目可添加到 JSON。");
        return Err("No valid EDR log entries".to_string());
    }

    let entries_str = serde_json::to_string(&entries)
        .map_err(|e| format!("Entries序列化失败: {}", e))?;

    let json_obj = serde_json::json!({
        "list": entries_str
    });

    *str_json = serde_json::to_string(&json_obj)
        .map_err(|e| format!("JSON序列化失败: {}", e))?;

    Ok(())
}
pub fn build_batch_syslog_net_json(logs: &[SysNetLog], str_json: &mut String) -> Result<(), String> {
    if logs.is_empty() {
        log::error!("没有有效的日志条目可添加到 JSON。");
        return Err("No valid log entries".to_string());
    }

    // 先序列化 logs 数组为 JSON 字符串
    let logs_str = serde_json::to_string(logs)
        .map_err(|e| format!("序列化日志数组失败: {}", e))?;

    // 构造最终 JSON 对象，其中 logs_str 是字符串形式的 JSON 数组
    let root_obj = serde_json::json!({
        "list": logs_str
    });

    // 最终整体序列化为字符串
    *str_json = serde_json::to_string(&root_obj)
        .map_err(|e| format!("最终 JSON 序列化失败: {}", e))?;

    Ok(())
}


pub fn build_open_port_json(logs: &[OpenPortLog], str_json: &mut String) -> Result<(), String> {
    if logs.is_empty() {
        log::error!("没有有效的虚端口日志条目可添加到 JSON。");
        return Err("No valid open port log entries".to_string());
    }

    // Step 1: 将 logs 序列化为一个 JSON 数组字符串
    let logs_json_str = match serde_json::to_string(logs) {
        Ok(s) => s,
        Err(e) => {
            log::error!("序列化虚端口日志数组失败: {}", e);
            return Err(format!("JSON serialization failed: {}", e));
        }
    };

    // Step 2: 构造外层对象：{ "alert": "原始 JSON 字符串" }
    let root = serde_json::json!({
        "alert": logs_json_str
    });

    // Step 3: 将整个对象序列化为字符串
    match serde_json::to_string(&root) {
        Ok(final_json) => {
            str_json.clear();
            str_json.push_str(&final_json);
            Ok(())
        }
        Err(e) => {
            log::error!("最终 JSON 序列化失败: {}", e);
            Err(format!("Final serialization failed: {}", e))
        }
    }
}
