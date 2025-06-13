use serde::{Serialize, Deserialize};
use std::pin::Pin;
use common::manager::boot::BootManager;
use std::future::Future;
use tokio::time::{interval, Duration};
use tokio::task::JoinHandle;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use logging::{log_info, log_error};
use serde_json;
use crate::FileAuditLogInfo;

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

pub fn build_alert_log_json(log_info: &[FileAuditLogInfo], str_json: &mut String) -> Result<(), String> {
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
