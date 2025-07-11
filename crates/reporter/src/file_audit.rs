//crates/reporter/src/file_audit.rs
use std::ffi::CStr;
use crate::netlink_msg::NetlinkNetlog;
use logging::{log_error, log_info};
use std::mem;
use std::ptr;
use std::sync::Arc;
use tokio::sync::mpsc;
use zcopy_mgr::{AvFileInfo, ZcopyMgr};
use crate::{RulesType,AuditLogInfo}; // 从 lib.rs 导入
                                         
use process_mgr::get_md5_global;
// 定义 LogInfo
#[derive(Clone)]
pub struct FileAuditHandler {
    zcopy_mgr: Arc<ZcopyMgr>,
    file_audit_log_tx: mpsc::Sender<AuditLogInfo>,
}
impl FileAuditHandler {
    pub fn new(zcopy_mgr: Arc<ZcopyMgr>, file_audit_log_tx: mpsc::Sender<AuditLogInfo>) -> Self {
        FileAuditHandler { zcopy_mgr, file_audit_log_tx}
    }

    pub async fn handle_file_zcopy_oper(
        &self,
        data: &[u8],
        data_len: u32,
    ) -> Result<(), String> {

        // 检查数据长度
        if data_len < mem::size_of::<NetlinkNetlog>() as u32 {
            return Err(format!(
                "数据长度太小，期望至少 {} 字节，实际是 {} 字节",
                mem::size_of::<NetlinkNetlog>(),
                data_len
            ));
        }

        // 安全地转换 &[u8] 到 NetlinkNetlog
        let netlog: NetlinkNetlog = unsafe {
            ptr::read_unaligned(data.as_ptr() as *const NetlinkNetlog)
        };

        log_info!("收到 NetlinkNetlog: {:?}", netlog);

        if !self.zcopy_mgr.file_audit_succeed {
            return Err("ZcopyMgr file audit not initialized".to_string());
        }

        // 收集 av_file_info 数据
        let mut reports: Vec<AvFileInfo> = Vec::new();

        if netlog.max_idx == 0 {
            // max_idx == 0，遍历 start_idx 到 end_idx
            if netlog.start_idx >= netlog.end_idx {
                return Err(format!(
                    "无效索引范围: start_idx={} >= end_idx={}",
                    netlog.start_idx, netlog.end_idx
                ));
            }

            log_info!(
                "file audit, start_idx={}, end_idx={}",
                netlog.start_idx,
                netlog.end_idx
            );
            for idx in netlog.start_idx..netlog.end_idx {
                if let Some(report) = self.zcopy_mgr.get_file_audit_data(idx as usize) {
                    reports.push(*report);
                } else {
                    log_error!("无法获取索引 {} 的文件审计数据", idx);
                }
            }
        } else {
            // max_idx != 0，遍历 0 到 start_idx 和 end_idx 到 max_idx
            log_info!(
                "file audit, start_idx={}, end_idx={}, max_idx={}",
                netlog.start_idx,
                netlog.end_idx,
                netlog.max_idx
            );

            // 0 到 start_idx
            for idx in 0..netlog.start_idx {
                if let Some(report) = self.zcopy_mgr.get_file_audit_data(idx as usize) {
                    reports.push(*report);
                } else {
                    log_error!("无法获取索引 {} 的文件审计数据", idx);
                }
            }

            // end_idx 到 max_idx
            for idx in netlog.end_idx..netlog.max_idx {
                if let Some(report) = self.zcopy_mgr.get_file_audit_data(idx as usize) {
                    reports.push(*report);
                } else {
                    log_error!("无法获取索引 {} 的文件审计数据", idx);
                }
            }
        }

        self.audit_file_oper_new(&reports)
        //Ok(())
    }

    fn audit_file_oper_new(&self, reports: &[AvFileInfo]) -> Result<(), String> {
        let mut rc = Ok(());
        let pos_upload = 0;

        for report in reports {
            let rules_type = ((report.flags >> 6) & 0xF) as u32;
            // 修复类型不匹配
            let pattern_type = RulesType::from_u32(rules_type);
            match pattern_type {
                Some(RulesType::LesouProtectionType) => {
                    let log_level = ((report.flags >> 10) & 0x7) as u32;
                    if let Err(e) = self.audit_file_oper_rename(report, log_level, pos_upload) {
                        rc = Err(e);
                    }
                }
                Some(RulesType::TamperProtectionType) => {
                    if let Err(e) = self.rename_tamper_protect_match(report) {
                        rc = Err(e);
                    }
                }
                _ => {} // 忽略 SelfProtectionType 或无效值
            }
        }
        rc
    }
fn audit_file_oper_rename(&self, info: &AvFileInfo, level: u32, pos: u32) -> Result<(), String> {
    let path = CStr::from_bytes_until_nul(&info.path)
        .map_err(|_| "无效 path")?
        .to_str()
        .map_err(|_| "无效 UTF-8 path")?;
    let dst_path = CStr::from_bytes_until_nul(&info.dst_path)
        .map_err(|_| "无效 dst_path")?
        .to_str()
        .map_err(|_| "无效 UTF-8 dst_path")?;
    let comm = CStr::from_bytes_until_nul(&info.comm)
        .map_err(|_| "无效 comm")?
        .to_str()
        .map_err(|_| "无效 UTF-8 comm")?;

    let mut log = AuditLogInfo {
        file_path: None,
        rename_dir: None,
        exception_process: Some(comm.to_string()),
        md5: None,//Some("7490fea7c270d57b4a90add0e7bf7852".to_string()), // 假设 md5 稍后由 process_md5_mgr 更新
        n_type: info.log_type,
        n_level: level,
        n_time: 1692760326, // 应替换为实际时间戳
        notice_remark: None,
        peripheral_name: None,
        peripheral_remark: None,
        peripheral_eid: None,
        p_param: None,
    };

    if pos == 0 {
        log.file_path = Some(path.to_string());
        if !dst_path.is_empty() {
            log.rename_dir = Some(dst_path.to_string());
        }
    } else {
        log.file_path = Some(dst_path.to_string());
        if !path.is_empty() {
            log.rename_dir = Some(path.to_string());
        }
    }
    if log.file_path.is_none() {
        log.file_path = Some(path.to_string());
    }

    match get_md5_global(&comm) {
        Ok(md5) => log.md5 = Some(md5),
        Err(e) => {
            log.md5 = None;
            eprintln!("Failed to get MD5: {}", e);
        }
    }
    if let Err(e) = self.file_audit_log_tx.try_send(log) {
        log_error!("日志发送失败或队列满: {}", e);
    } else {
        log_info!("log日志发送成功");
    }


    // TODO: 取消注释以启用 MD5 更新
    // self.process_md5_mgr.update_process_md5(comm, &mut log.md5);
    // self.report(&log)

    Ok(())
}


    fn rename_tamper_protect_match(&self, info: &AvFileInfo) -> Result<(), String> {
        let path = CStr::from_bytes_until_nul(&info.path)
            .map_err(|_| "无效 path")?
            .to_str()
            .map_err(|_| "无效 UTF-8 path")?;
        let is_dir = (info.flags & 0x7) as u32;
        let type_ = ((info.flags >> 3) & 0x7) as u32;
        let log_level = ((info.flags >> 10) & 0x7) as u32;

        let mut file_mode = is_dir;
        let mut flag_special = -1;

        if let Ok(stat) = std::fs::metadata(path) {
            if stat.is_dir() {
                file_mode = 1;
                if type_ == FILE_MODIFY {
                    flag_special = 0;
                }
            } else if stat.is_file() {
                file_mode = 0;
            }
        }

        if flag_special < 0 {
            let warn_log_type = G_WARN_LOG_TYPE[file_mode as usize][G_RUN_FILE_MODE][type_ as usize];
            let mut info_copy = *info;
            info_copy.log_type = warn_log_type as u16;
            self.audit_file_oper_rename(&info_copy, log_level, 0)?;
        }
        Ok(())
    }
    fn report(&self, log: &AuditLogInfo) -> Result<(), String> {
        let json = serde_json::to_string(log)
            .map_err(|e| format!("JSON 序列化失败: {}", e))?;
        //self.report_sender.send(&json)
        Ok(())
    }
}

const FILE_MODIFY: u32 = 1;
static G_WARN_LOG_TYPE: [[[u32; 5]; 2]; 2] = [
    [
        [3001, 3002, 3003, 3004, 3005],
        [3101, 3102, 3103, 3104, 3105],
    ],
    [
        [2001, 2002, 2003, 2004, 2005],
        [2101, 2102, 2103, 2104, 2105],
    ],
];
static G_RUN_FILE_MODE: usize = 0;
