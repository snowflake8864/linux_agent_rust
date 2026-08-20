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

/// glibc 的 `struct utmp` 布局按架构不同（由 `__WORDSIZE_TIME64_COMPAT32` 决定）：
/// - x86_64 / mips64：为与 32 位进程共享 utmp 文件，ut_session/ut_tv 用 32 位 → 384 字节
/// - aarch64 / loongarch64：无 32 位兼容，用原生 64 位 long/timeval → 400 字节
/// 必须与写入 btmp/wtmp 的系统 glibc 一致，否则 read_exact 步长错位、只能解析出第一条。
#[cfg(any(target_arch = "x86_64", target_arch = "mips64"))]
type UtmpWord = i32; // 384 字节布局

#[cfg(not(any(target_arch = "x86_64", target_arch = "mips64")))]
type UtmpWord = i64; // 400 字节布局

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
    ut_session: UtmpWord,
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
    tv_sec: UtmpWord,
    tv_usec: UtmpWord,
}

const UTMP_SIZE: usize = std::mem::size_of::<Utmp>();

// 编译期校验结构体大小与目标架构的 glibc 一致，防止字段类型改错导致 read_exact 步长错位。
#[cfg(any(target_arch = "x86_64", target_arch = "mips64"))]
const _: () = assert!(UTMP_SIZE == 384, "x86_64/mips64 的 glibc struct utmp 应为 384 字节");

#[cfg(not(any(target_arch = "x86_64", target_arch = "mips64")))]
const _: () = assert!(UTMP_SIZE == 400, "aarch64/loongarch64 的 glibc struct utmp 应为 400 字节");

const LOGIN_PROCESS: i16 = 6; // 登录会话（btmp失败登录多用此类型）
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
                        // 广播到 gRPC AlertService
                        for log in &new_logs { reporter::broadcast_ssh_log(log); }
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
                    
                    // 处理登录事件: wtmp用USER_PROCESS(7), btmp失败登录多用LOGIN_PROCESS(6)
                    let is_login = utmp.ut_type == USER_PROCESS
                        || (is_btmp && utmp.ut_type == LOGIN_PROCESS);
                    if is_login {
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

        // 验证IP格式，并过滤回环地址（127.0.0.1/::1等无上报意义）
        let parsed_ip = match ip.parse::<std::net::IpAddr>() {
            Ok(addr) => addr,
            Err(_) => return None,
        };
        if parsed_ip.is_loopback() {
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
