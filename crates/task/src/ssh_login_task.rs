// crates/task/src/ssh_login_task.rs
// SSH登录日志采集任务 - 低耦合设计

use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use logging::{log_error, log_info};
use reporter::{SyslogSshLog, build_json::build_ssh_login_json};
use net_client::core::NetClient;

/// utmp结构体定义 (与C语言兼容)
#[repr(C)]
#[derive(Debug, Clone)]
struct Utmp {
    ut_type: i16,
    ut_pid: i32,
    ut_line: [u8; 32],
    ut_id: [u8; 4],
    ut_user: [u8; 32],
    ut_host: [u8; 256],
    ut_exit: UtmpExit,
    ut_session: i32,
    ut_tv: UtmpTimeval,
    ut_addr_v6: [i32; 4],
    unused: [u8; 20],
}

#[repr(C)]
#[derive(Debug, Clone)]
struct UtmpExit {
    e_termination: i16,
    e_exit: i16,
}

#[repr(C)]
#[derive(Debug, Clone)]
struct UtmpTimeval {
    tv_sec: i32,
    tv_usec: i32,
}

const UTMP_SIZE: usize = std::mem::size_of::<Utmp>();
const USER_PROCESS: i16 = 7;  // 登录
const DEAD_PROCESS: i16 = 8;  // 登出

/// SSH登录采集器
pub struct SshLoginCollector {
    btmp_offset: Arc<Mutex<u64>>,
    wtmp_offset: Arc<Mutex<u64>>,
    last_records: Arc<Mutex<HashSet<String>>>,  // 用于去重
}

impl SshLoginCollector {
    pub fn new() -> Self {
        // Initialize offsets to end-of-file so we only pick up NEW records
        // written after the agent starts, not all historical records.
        let btmp_offset = Self::get_file_end("/var/log/btmp");
        let wtmp_offset = Self::get_file_end("/var/log/wtmp");
        Self {
            btmp_offset: Arc::new(Mutex::new(btmp_offset)),
            wtmp_offset: Arc::new(Mutex::new(wtmp_offset)),
            last_records: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    fn get_file_end(path: &str) -> u64 {
        std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    }

    /// 执行采集并上报
    pub async fn collect_and_report(&self, net_client: &NetClient, token: Option<&str>) {
        let mut logs = Vec::new();

        // 采集失败登录 (btmp)
        if let Ok(new_logs) = self.read_btmp().await {
            logs.extend(new_logs);
        }

        // 采集成功登录 (wtmp)
        if let Ok(new_logs) = self.read_wtmp().await {
            logs.extend(new_logs);
        }

        if logs.is_empty() {
            return;
        }

        // 去重：只上报新增记录
        let new_logs = self.filter_new_records(logs).await;
        if new_logs.is_empty() {
            return;
        }

        // 构建JSON并上报
        let mut json_str = String::new();
        match build_ssh_login_json(&new_logs, &mut json_str) {
            Ok(()) => {
                let url = format!("{}/v1/putsyslog", net_client.get_base_url().unwrap_or_default());
                match net_client.post_data_async(
                    &url,
                    &json_str,
                    Duration::from_secs(10),
                    token,
                ).await {
                    Ok(response) => {
                        log_info!("SSH登录日志上报成功: {}条, 服务器响应: {}", new_logs.len(), response);
                        // 更新去重记录
                        self.update_last_records(new_logs).await;
                    }
                    Err(e) => {
                        log_error!("SSH登录日志上报失败: {}", e);
                    }
                }
            }
            Err(e) => {
                log_error!("构建SSH登录JSON失败: {}", e);
            }
        }
    }

    /// 读取btmp文件 (失败登录)
    async fn read_btmp(&self) -> Result<Vec<SyslogSshLog>, String> {
        self.read_utmp_file("/var/log/btmp", true).await
    }

    /// 读取wtmp文件 (成功登录)
    async fn read_wtmp(&self) -> Result<Vec<SyslogSshLog>, String> {
        self.read_utmp_file("/var/log/wtmp", false).await
    }

    /// 读取utmp格式文件
    async fn read_utmp_file(&self, path: &str, is_btmp: bool) -> Result<Vec<SyslogSshLog>, String> {
        let path = Path::new(path);
        if !path.exists() {
            return Ok(Vec::new());
        }

        let mut file = File::open(path).map_err(|e| format!("打开{}失败: {}", path.display(), e))?;
        
        // 获取当前offset
        let offset_lock = if is_btmp { &self.btmp_offset } else { &self.wtmp_offset };
        let mut offset = offset_lock.lock().unwrap();
        
        // 获取文件大小
        let file_size = file.metadata().map_err(|e| format!("获取文件大小失败: {}", e))?.len();
        
        // 如果文件被清空或重置，重置offset
        if *offset > file_size {
            *offset = 0;
        }

        // 跳到上次读取位置
        if *offset > 0 {
            file.seek(SeekFrom::Start(*offset)).map_err(|e| format!("Seek失败: {}", e))?;
        }

        let mut logs = Vec::new();
        let mut buffer = [0u8; UTMP_SIZE];

        loop {
            match file.read_exact(&mut buffer) {
                Ok(()) => {
                    let utmp: Utmp = unsafe { std::ptr::read(buffer.as_ptr() as *const _) };
                    
                    // 只处理登录事件
                    if utmp.ut_type == USER_PROCESS {
                        if let Some(log) = self.parse_utmp_entry(&utmp, is_btmp) {
                            logs.push(log);
                        }
                    }
                }
                Err(_) => break,  // 读取完毕或出错
            }
        }

        // 更新offset
        *offset = file.stream_position().unwrap_or(0);
        
        Ok(logs)
    }

    /// 解析utmp条目
    fn parse_utmp_entry(&self, utmp: &Utmp, is_btmp: bool) -> Option<SyslogSshLog> {
        // 提取用户名
        let username = String::from_utf8_lossy(&utmp.ut_user)
            .trim_end_matches('\0')
            .to_string();
        if username.is_empty() {
            return None;
        }

        // 提取IP地址
        let ip = String::from_utf8_lossy(&utmp.ut_host)
            .trim_end_matches('\0')
            .to_string();
        if ip.is_empty() || ip == "0.0.0.0" {
            return None;
        }

        // 提取终端设备
        let tty = String::from_utf8_lossy(&utmp.ut_line)
            .trim_end_matches('\0')
            .to_string();
        
        // 只处理SSH相关登录 (pts/或包含ssh)
        if !tty.starts_with("pts/") && !tty.contains("ssh") {
            return None;
        }

        // 验证IP格式
        if !self.is_valid_ip(&ip) {
            return None;
        }

        Some(SyslogSshLog {
            ip,
            username,
            login_type: "SSH".to_string(),
            status: if is_btmp { 0 } else { 1 },  // 0=失败, 1=成功
            log_type: 5,
            time: utmp.ut_tv.tv_sec as i64,
        })
    }

    /// 验证IP地址格式
    fn is_valid_ip(&self, ip: &str) -> bool {
        ip.parse::<std::net::IpAddr>().is_ok()
    }

    /// 过滤已上报的记录
    async fn filter_new_records(&self, logs: Vec<SyslogSshLog>) -> Vec<SyslogSshLog> {
        let last_records = self.last_records.lock().unwrap();
        
        logs.into_iter()
            .filter(|log| {
                let key = format!("{}:{}:{}:{}", log.ip, log.username, log.time, log.status);
                !last_records.contains(&key)
            })
            .collect()
    }

    /// 更新已上报记录
    async fn update_last_records(&self, logs: Vec<SyslogSshLog>) {
        let mut last_records = self.last_records.lock().unwrap();
        
        // 保留最近1000条记录，防止内存无限增长
        if last_records.len() > 1000 {
            last_records.clear();
        }
        
        for log in logs {
            let key = format!("{}:{}:{}:{}", log.ip, log.username, log.time, log.status);
            last_records.insert(key);
        }
    }
}

impl Default for SshLoginCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 便捷函数：执行一次采集上报
pub async fn collect_ssh_login(
    net_client: &NetClient,
    token: Option<&str>,
) {
    let collector = SshLoginCollector::new();
    collector.collect_and_report(net_client, token).await;
}
