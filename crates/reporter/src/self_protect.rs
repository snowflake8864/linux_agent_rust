use logging::{log_debug, log_error, log_info};
use std::sync::Arc;
use std::mem;
use tokio::fs::File;
use std::path::Path;
use tokio::io::AsyncReadExt;
use process_mgr::get_md5_global;
use tokio::time::Duration;
use common::manager::boot::BootManager;
use crate::{SelfProtectLogInfo, build_self_protect_alert_log_json};
use net_client::core::NetClient;


#[repr(C)]
#[derive(Clone, Copy)]
pub struct AvSelfProtecNetlink {
    pid: i32,
    ppid: i32,
    uid: i32,
    n_type: i32,
    pub comm: [u8; 128],
    //pub comm_p: [u8; 16],
    pub path: [u8; 128],
}

impl AvSelfProtecNetlink {
    pub async fn get_cmdline(pid: i32) -> String {
        let path = format!("/proc/{}/cmdline", pid);
        log_info!("[get_cmdline] Trying to read: {}", path);

        // 检查文件是否存在
        if !Path::new(&path).exists() {
            log_info!("[get_cmdline] File does not exist for pid {}", pid);
            return String::new();
        }

        // 打开文件
        let mut file = match File::open(&path).await {
            Ok(f) => f,
            Err(e) => {
                log_info!("[get_cmdline] Failed to open {}: {}", path, e);
                return String::new();
            }
        };

        // 读取内容
        let mut contents = Vec::new();
        match file.read_to_end(&mut contents).await {
            Ok(size) => log_info!("[get_cmdline] Read {} bytes", size),
            Err(e) => {
                log_info!("[get_cmdline] Failed to read file {}: {}", path, e);
                return String::new();
            }
        }

        if contents.is_empty() {
            log_info!("[get_cmdline] File is empty for pid {}", pid);
            return String::new();
        }

        // '\0' 替换为空格
        for b in contents.iter_mut() {
            if *b == 0 {
                *b = b' ';
            }
        }

        let cmdline = String::from_utf8_lossy(&contents).trim().to_string();
        log_info!("[get_cmdline] Result cmdline for pid {}: '{}'", pid, cmdline);

        cmdline
    }

    fn looks_like_path(s: &str) -> bool {
        !s.is_empty() && s.starts_with('/')
    }

    /// 从二进制数据解析结构体
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < mem::size_of::<AvSelfProtecNetlink>() {
            return None;
        }

        let ptr = data.as_ptr() as *const AvSelfProtecNetlink;
        unsafe { Some(ptr.read_unaligned()) }
    }

    /// 将 C 风格字符串转为 Rust String
    fn cstr_to_string(bytes: &[u8]) -> String {
        let len = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..len]).to_string()
    }

    /// 异步转换为日志结构
    pub async fn to_log_info(&self) -> SelfProtectLogInfo {
        let proc_dir = Self::cstr_to_string(&self.comm);


        let file_dir = {
            let fallback = Self::cstr_to_string(&self.path);
            if fallback.is_empty() { None } else { Some(fallback) }
        };
        let proc_hash = if Self::looks_like_path(&proc_dir) {
            match get_md5_global(proc_dir.as_str()) {
                Ok(hash) => {
                    /*
                    log_info!(
                        "[to_log_info] pid={} md5({}) = {}",
                        self.pid,
                        proc_dir,
                        hash
                    );
                    */
                    Some(hash)
                }
                Err(err) => {
                    log_debug!(
                        "[to_log_info] get_md5_global failed for '{}', pid={}, err={:?}",
                        proc_dir,
                        self.pid,
                        err
                    );
                    None
                }
            }
        } else {
            log_debug!(
                "[to_log_info] proc_dir '{}' does not look like a path, skip md5",
                proc_dir
            );
            None
        };

        SelfProtectLogInfo {
            file_dir,
            proc_dir: if proc_dir.is_empty() { None } else { Some(proc_dir) },
            proc_hash,
            proc_param:None, 
            target_dir:None,
            n_type: self.n_type as u16,
            n_level: 3,
            n_time: 1692760326 as u64,
        }
    }
}

#[derive(Clone)]
pub struct SelfProtectAuditHandler {
    boot_manager: Arc<BootManager>,
}

impl SelfProtectAuditHandler {
    pub fn new(boot_manager: Arc<BootManager>) -> Self {
        SelfProtectAuditHandler { boot_manager }
    }

    /// 异步处理 Netlink 上来的数据
    pub async fn handle_self_protect_oper(
        &self,
        data: &[u8],
        _data_len: u32,
    ) -> Result<(), String> {
        //log_info!("收到 NetlinkNetlog: {:?}", data);
        let mut log_vec: Vec<SelfProtectLogInfo> = Vec::new();

        if let Some(info) = AvSelfProtecNetlink::from_bytes(data) {
            let log_info = info.to_log_info().await; // 异步等待
            log_vec.push(log_info);
        } else {
            log_error!("解析 av_self_protection_info 失败，数据长度不足");
            return Err("解析失败".to_string());
        }

        //log_info!("解析结果: {:?}", log_vec);

        let net_client = match NetClient::new(Some(self.boot_manager.get_base_url()), true) {
            Ok(client) => client,
            Err(err) => {
                log_error!("创建 NetClient 失败: {}", err);
                return Err("创建 NetClient 失败".to_string());
            }
        };

        if !log_vec.is_empty() {
            let url = format!(
                "{}/v1/alertupload",
                net_client.get_base_url().unwrap_or_default()
            );
            let mut json_str = String::new();

            match build_self_protect_alert_log_json(&log_vec, &mut json_str) {
                Ok(()) => {
                    //log_info!("生成 JSON: {}", json_str);
                    match net_client
                        .post_data_async(
                            &url,
                            &json_str,
                            Duration::from_secs(10),
                            self.boot_manager.get_token().await.as_deref(),
                        )
                        .await
                    {
                        Ok(_resp) =>{}, //log_info!("上报成功"),
                        Err(err) => log_error!("发送日志失败: {}", err),
                    }
                }
                Err(e) => {
                    log_error!("构建 JSON 失败: {}", e);
                }
            }
        }

        Ok(())
    }
}

