// crates/task/src/ssh_login_task.rs
// 登录日志采集任务 - 多数据源、多登录方式兼容设计
//
// 覆盖 SSH、本地控制台(tty)、图形显示管理器、串口、telnet、FTP 等登录事件，
// login_type 取具体方式，log_type 固定为 5。
//
// 采集优先级：
//   1. /var/log/btmp (失败) + /var/log/wtmp (成功)  —— 二进制 utmp 格式，覆盖所有 PAM 登录
//   2. /var/log/auth.log / secure / messages        —— 文本文件，覆盖无 btmp/wtmp 的发行版
//   3. journalctl                                   —— 以上文件都不存在时的最后兜底
//
// 所有来源共用同一套去重/上报流程，重复记录（如 wtmp 与 auth.log 的同一次登录）
// 通过 ip:user:time:status 的 key 合并。

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Datelike, Local, NaiveDate, TimeZone};
use logging::{log_error, log_info};
use net_client::core::NetClient;
use reporter::{build_json::build_ssh_login_json, SyslogSshLog};

const BTMP_PATH: &str = "/var/log/btmp";
const WTMP_PATH: &str = "/var/log/wtmp";

/// 各发行版的 sshd 文本日志位置：
/// - Debian/Ubuntu: auth.log
/// - RHEL/CentOS/Fedora: secure
/// - 部分发行版: messages
const TEXT_LOG_PATHS: &[&str] = &[
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/messages",
    // FTP 服务常把登录审计写到独立文件，不在 syslog/auth.log 中。
    "/var/log/vsftpd.log",
    "/var/log/proftpd/proftpd.log",
];

/// 单源单次读取上限，防止文件轮转后出现超大积压时占满 CPU。
/// 超出部分留在下一次 tick 继续读，offset 只推进到已消费的位置。
const MAX_ENTRIES_PER_TICK: usize = 5000;

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
// DEAD_PROCESS(8) 为登出事件，不参与上报。

/// 本地登录（控制台/图形/串口）没有远端 IP，统一用回环地址占位。
const LOCAL_IP: &str = "127.0.0.1";

/// 文本日志中视为交互式登录的 PAM 服务名；cron/sudo/su/systemd 等排除在外。
const INTERACTIVE_SERVICES: &[&str] = &[
    "login", "gdm", "sddm", "lightdm", "kdm", "xdm", "xrdp", "telnet",
];

/// 文件读取游标。除字节偏移外还记录设备号/inode，用于识别日志轮转或文件被替换：
/// 二进制日志轮转后 inode 变化、文本日志被 logrotate 重建，都必须从头读，否则会漏采。
#[derive(Debug, Clone, Default)]
struct FileCursor {
    offset: u64,
    dev: u64,
    ino: u64,
    initialized: bool,
}

impl FileCursor {
    /// 用当前文件元数据初始化：从文件末尾开始（只采 agent 启动后的新记录）。
    fn at_end(metadata: &std::fs::Metadata) -> Self {
        Self {
            offset: metadata.len(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            initialized: true,
        }
    }

    /// 返回是否仍指向同一个文件（未被轮转/替换）。
    fn is_same_file(&self, metadata: &std::fs::Metadata) -> bool {
        self.initialized && self.dev == metadata.dev() && self.ino == metadata.ino()
    }

    fn restart(&mut self, metadata: &std::fs::Metadata) {
        self.offset = 0;
        self.dev = metadata.dev();
        self.ino = metadata.ino();
        self.initialized = true;
    }

    fn sync_identity(&mut self, metadata: &std::fs::Metadata) {
        self.dev = metadata.dev();
        self.ino = metadata.ino();
        self.initialized = true;
    }
}

fn init_cursor(path: &str) -> FileCursor {
    match std::fs::metadata(path) {
        Ok(meta) => FileCursor::at_end(&meta),
        Err(_) => FileCursor::default(),
    }
}

/// SSH登录采集器
pub struct SshLoginCollector {
    btmp_cursor: Arc<Mutex<FileCursor>>,
    wtmp_cursor: Arc<Mutex<FileCursor>>,
    /// 文本日志按路径分别保存游标，文件中途出现也能从当时的 EOF 开始读。
    text_cursors: Arc<Mutex<HashMap<String, FileCursor>>>,
    /// journalctl 时间水位（epoch 秒），只有无任何日志文件时才使用。
    journal_watermark: Arc<Mutex<i64>>,
    /// 上报失败时暂存的日志，下一 tick 重试，避免游标已推进导致日志丢失。
    pending_logs: Arc<Mutex<Vec<SyslogSshLog>>>,
    last_records: Arc<Mutex<HashSet<String>>>,  // 用于去重
}

impl SshLoginCollector {
    pub fn new() -> Self {
        // Initialize offsets to end-of-file so we only pick up NEW records
        // written after the agent starts, not all historical records.
        let mut text_cursors = HashMap::new();
        for path in TEXT_LOG_PATHS {
            text_cursors.insert((*path).to_string(), init_cursor(path));
        }
        Self {
            btmp_cursor: Arc::new(Mutex::new(init_cursor(BTMP_PATH))),
            wtmp_cursor: Arc::new(Mutex::new(init_cursor(WTMP_PATH))),
            text_cursors: Arc::new(Mutex::new(text_cursors)),
            journal_watermark: Arc::new(Mutex::new(Local::now().timestamp() - 120)),
            pending_logs: Arc::new(Mutex::new(Vec::new())),
            last_records: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// 执行采集并上报
    pub async fn collect_and_report(&self, net_client: &NetClient, token: Option<&str>) {
        let mut logs = {
            let mut pending = self.pending_logs.lock().unwrap();
            std::mem::take(&mut *pending)
        };

        // 采集失败登录 (btmp)
        if let Ok(new_logs) = self.read_btmp() {
            logs.extend(new_logs);
        }

        // 采集成功登录 (wtmp)
        if let Ok(new_logs) = self.read_wtmp() {
            logs.extend(new_logs);
        }

        // 文本日志兜底（auth.log / secure / messages）
        logs.extend(self.read_text_logs());

        // 只有在完全没有任何可读日志文件时才调用 journalctl，避免多余进程开销。
        let journal_watermark = *self.journal_watermark.lock().unwrap();
        if !self.has_file_source() {
            logs.extend(self.read_journal(journal_watermark));
        }

        if logs.is_empty() {
            return;
        }

        // 去重：只上报新增记录
        let new_logs = self.filter_new_records(logs);
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
                        // 更新去重记录（仅在上报成功后，失败时由 pending_logs 重试）
                        self.update_last_records(new_logs);
                    }
                    Err(e) => {
                        log_error!("SSH登录日志上报失败: {}", e);
                        self.stash_failed_logs(new_logs);
                    }
                }
            }
            Err(e) => {
                log_error!("构建SSH登录JSON失败: {}", e);
                self.stash_failed_logs(new_logs);
            }
        }
    }

    /// 是否存在可读的登录日志文件。用于决定是否启用 journalctl 兜底。
    fn has_file_source(&self) -> bool {
        std::iter::once(BTMP_PATH)
            .chain(std::iter::once(WTMP_PATH))
            .chain(TEXT_LOG_PATHS.iter().copied())
            .any(|path| File::open(path).is_ok())
    }

    /// 读取btmp文件 (失败登录)
    fn read_btmp(&self) -> Result<Vec<SyslogSshLog>, String> {
        self.read_utmp_file(BTMP_PATH, true, &self.btmp_cursor)
    }

    /// 读取wtmp文件 (成功登录)
    fn read_wtmp(&self) -> Result<Vec<SyslogSshLog>, String> {
        self.read_utmp_file(WTMP_PATH, false, &self.wtmp_cursor)
    }

    /// 读取utmp格式文件
    fn read_utmp_file(
        &self,
        path: &str,
        is_btmp: bool,
        cursor_lock: &Mutex<FileCursor>,
    ) -> Result<Vec<SyslogSshLog>, String> {
        let path = Path::new(path);
        // 文件不存在或无权限时静默跳过：这类系统正是我们要兼容的场景。
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(_) => return Ok(Vec::new()),
        };
        let metadata = file.metadata().map_err(|e| format!("获取文件大小失败: {}", e))?;
        let file_size = metadata.len();

        let mut cursor = cursor_lock.lock().unwrap();
        // inode 变化（轮转/替换）或文件被截断 → 从头读。
        if !cursor.is_same_file(&metadata) || cursor.offset > file_size {
            cursor.restart(&metadata);
        }
        if cursor.offset > 0 {
            file.seek(SeekFrom::Start(cursor.offset))
                .map_err(|e| format!("Seek失败: {}", e))?;
        }

        let mut logs = Vec::new();
        let mut buffer = [0u8; UTMP_SIZE];
        let mut offset = cursor.offset;
        let mut records_read = 0;

        while records_read < MAX_ENTRIES_PER_TICK {
            match file.read_exact(&mut buffer) {
                Ok(()) => {
                    records_read += 1;
                    // buffer 是字节数组，无法保证满足 Utmp 的对齐要求，必须用 read_unaligned。
                    let utmp: Utmp = unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const _) };

                    // 处理登录事件: wtmp用USER_PROCESS(7), btmp失败登录多用LOGIN_PROCESS(6)
                    let is_login = utmp.ut_type == USER_PROCESS
                        || (is_btmp && utmp.ut_type == LOGIN_PROCESS);
                    if is_login {
                        if let Some(log) = Self::parse_utmp_entry(&utmp, is_btmp) {
                            logs.push(log);
                        }
                    }
                    offset += UTMP_SIZE as u64;
                }
                // 读取完毕、尾部不足一条完整记录或出错：offset 停在最后一条完整记录边界。
                Err(_) => break,
            }
        }

        cursor.offset = offset;
        cursor.sync_identity(&metadata);
        Ok(logs)
    }

    /// 解析utmp条目（覆盖 SSH、本地控制台、图形、串口等所有交互式登录）
    fn parse_utmp_entry(utmp: &Utmp, is_btmp: bool) -> Option<SyslogSshLog> {
        // 提取用户名
        let username = String::from_utf8_lossy(&utmp.ut_user)
            .trim_end_matches('\0')
            .to_string();
        if username.is_empty() {
            return None;
        }

        let tty = String::from_utf8_lossy(&utmp.ut_line);
        let host = String::from_utf8_lossy(&utmp.ut_host);
        // wtmp 中大量 ut_line="?" 且无 host 的记录来自 cron/服务，不是交互式登录。
        if (tty.trim().is_empty() || tty.trim() == "?") && host.trim().is_empty() {
            return None;
        }

        let login_type = classify_terminal_login(&tty, &host);
        build_login_log(
            &host,
            &username,
            login_type,
            is_btmp,
            utmp.ut_tv.tv_sec as i64,
        )
    }

    /// 采集所有文本日志中的新增行
    fn read_text_logs(&self) -> Vec<SyslogSshLog> {
        let now = Local::now();
        let mut logs = Vec::new();
        let mut cursors = self.text_cursors.lock().unwrap();

        for path in TEXT_LOG_PATHS {
            let cursor = cursors
                .entry((*path).to_string())
                .or_insert_with(|| init_cursor(path));
            for line in read_new_lines(path, cursor) {
                if let Some(log) = parse_sshd_line(&line, now)
                    .or_else(|| parse_pam_session_line(&line, now))
                    .or_else(|| parse_ftp_line(&line, now))
                {
                    logs.push(log);
                }
            }
        }
        logs
    }

    /// systemd journal 兜底。仅当二进制日志和文本日志都不存在时调用。
    fn read_journal(&self, watermark: i64) -> Vec<SyslogSshLog> {
        // journalctl 通常很快，这里同步调用并限制返回条数；--no-pager 防止等待分页器。
        let output = match std::process::Command::new("journalctl")
            .args([
                "-u", "ssh",
                "-u", "sshd",
                "-o", "short-iso",
                "--no-pager",
                "--since",
                &format!("@{}", watermark),
                "-n",
                "2000",
            ])
            .output()
        {
            Ok(output) => output,
            Err(_) => return Vec::new(), // 未安装 journalctl 或无权限：静默跳过
        };
        if !output.status.success() {
            return Vec::new();
        }

        let now = Local::now();
        let mut logs = Vec::new();
        let mut new_watermark = watermark;
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            // 即便不是登录事件也推进水位，避免每轮重复扫描相同窗口。
            if let Some(t) = parse_line_time(line, now) {
                if t.timestamp() > new_watermark {
                    new_watermark = t.timestamp();
                }
            }
            if let Some(log) = parse_sshd_line(line, now)
                .or_else(|| parse_pam_session_line(line, now))
                .or_else(|| parse_ftp_line(line, now))
            {
                if log.time > watermark {
                    logs.push(log);
                }
            }
        }
        // 保留 1 秒重叠，重复项由去重集合过滤。
        let mut guard = self.journal_watermark.lock().unwrap();
        if new_watermark > *guard {
            *guard = new_watermark - 1;
        }
        logs
    }

    /// 过滤已上报的记录（同时消除本批次内部的重复）
    fn filter_new_records(&self, logs: Vec<SyslogSshLog>) -> Vec<SyslogSshLog> {
        let last_records = self.last_records.lock().unwrap();
        let mut seen = HashSet::new();

        logs.into_iter()
            .filter(|log| {
                let key = log_key(log);
                seen.insert(key.clone()) && !last_records.contains(&key)
            })
            .collect()
    }

    /// 更新已上报记录
    fn update_last_records(&self, logs: Vec<SyslogSshLog>) {
        let mut last_records = self.last_records.lock().unwrap();

        // 保留最近1000条记录，防止内存无限增长
        if last_records.len() > 1000 {
            last_records.clear();
        }

        for log in logs {
            last_records.insert(log_key(&log));
        }
    }

    /// 上报失败时暂存，下一 tick 重试；设置上限防止网络长时间不可用时内存膨胀。
    fn stash_failed_logs(&self, logs: Vec<SyslogSshLog>) {
        let mut pending = self.pending_logs.lock().unwrap();
        for log in logs {
            if pending.len() >= 5000 {
                pending.remove(0);
            }
            pending.push(log);
        }
    }
}

impl Default for SshLoginCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// 从文本日志读取新增的完整行。不足一行的残料不消费，留到下次读取。
/// 返回的字符串不含行尾的 \n / \r。
fn read_new_lines(path: &str, cursor: &mut FileCursor) -> Vec<String> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return Vec::new(), // 文件不存在/无权限/正在轮转
    };
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return Vec::new(),
    };

    if !cursor.is_same_file(&metadata) || cursor.offset > metadata.len() {
        cursor.restart(&metadata);
    }
    if cursor.offset > 0 && file.seek(SeekFrom::Start(cursor.offset)).is_err() {
        return Vec::new();
    }

    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    let mut lines = Vec::new();
    let mut consumed = cursor.offset;

    while lines.len() < MAX_ENTRIES_PER_TICK {
        buffer.clear();
        match reader.read_until(b'\n', &mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                if buffer.last() != Some(&b'\n') {
                    // 写到一半的行：不推进 offset，下一轮从同一位置重读。
                    break;
                }
                consumed += n as u64;
                while buffer.last() == Some(&b'\n') || buffer.last() == Some(&b'\r') {
                    buffer.pop();
                }
                lines.push(String::from_utf8_lossy(&buffer).into_owned());
            }
            Err(_) => break,
        }
    }

    cursor.offset = consumed;
    cursor.sync_identity(&metadata);
    lines
}

/// 从行首解析时间戳，兼容：
/// - RFC3339（rsyslog 默认模板，带微秒；journalctl short-iso 无微秒）
/// - 传统 syslog `Nov 26 09:10:44`（无年份，用当前时间推断，处理跨年）
/// - vsftpd 独立日志 `Mon Nov 26 09:10:44 2026`
fn parse_line_time(line: &str, now: DateTime<Local>) -> Option<DateTime<Local>> {
    let words: Vec<&str> = line.split_whitespace().collect();
    if words.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(words[0]) {
        return Some(dt.with_timezone(&Local));
    }
    if words.len() >= 3 {
        if let Some(month) = month_number(words[0]) {
            return build_datetime(now.year(), month, words[1], words[2], now);
        }
    }
    // vsftpd 独立日志：Mon Nov 26 09:10:44 2026 [pid 1] [user] OK Login
    if words.len() >= 5 && is_weekday(words[0]) {
        if let Some(month) = month_number(words[1]) {
            let year: i32 = words[4].parse().ok()?;
            return build_datetime(year, month, words[2], words[3], now);
        }
    }
    None
}

fn month_number(name: &str) -> Option<u32> {
    match name.to_ascii_lowercase().as_str() {
        "jan" => Some(1),
        "feb" => Some(2),
        "mar" => Some(3),
        "apr" => Some(4),
        "may" => Some(5),
        "jun" => Some(6),
        "jul" => Some(7),
        "aug" => Some(8),
        "sep" => Some(9),
        "oct" => Some(10),
        "nov" => Some(11),
        "dec" => Some(12),
        _ => None,
    }
}

fn is_weekday(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun"
    )
}

fn build_datetime(
    mut year: i32,
    month: u32,
    day: &str,
    hms: &str,
    now: DateTime<Local>,
) -> Option<DateTime<Local>> {
    let day: u32 = day.parse().ok()?;
    let parts: Vec<&str> = hms.split(':').collect();
    if parts.len() != 3 {
        return None;
    }
    let hour: u32 = parts[0].parse().ok()?;
    let minute: u32 = parts[1].parse().ok()?;
    let second: u32 = parts[2].parse().ok()?;

    let naive = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, minute, second)?;
    let mut dt = Local.from_local_datetime(&naive).single()?;
    // 解析出的时间明显晚于当前时间 → 属于上一年（例如 1 月读到 12 月日志）。
    if dt > now + chrono::Duration::days(1) {
        year -= 1;
        let naive = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, minute, second)?;
        dt = Local.from_local_datetime(&naive).single()?;
    }
    Some(dt)
}

/// 解析一条 sshd 文本日志。非 sshd 进程、无关事件一律返回 None。
fn parse_sshd_line(line: &str, now: DateTime<Local>) -> Option<SyslogSshLog> {
    // 门控：进程名可能是 sshd 或 sshd-session，事件关键词限定为四类。
    if !line.contains("sshd") {
        return None;
    }
    if !(line.contains("Accepted ")
        || line.contains("Failed ")
        || line.contains("Invalid user ")
        || line.contains("authentication failure"))
    {
        return None;
    }

    let time = parse_line_time(line, now)?.timestamp();
    let words: Vec<&str> = line.split_whitespace().collect();

    let (status, user, host) = if let Some(pos) = find_word(&words, 0, "Accepted") {
        let for_pos = find_word(&words, pos, "for")?;
        let from_pos = find_word(&words, pos, "from")?;
        (1, *words.get(for_pos + 1)?, *words.get(from_pos + 1)?)
    } else if let Some(pos) = find_word(&words, 0, "Failed") {
        let for_pos = find_word(&words, pos, "for")?;
        let from_pos = find_word(&words, pos, "from")?;
        let mut user = *words.get(for_pos + 1)?;
        // Failed password for invalid user bob from 1.2.3.4 ...
        if user == "invalid" && words.get(for_pos + 2) == Some(&"user") {
            user = *words.get(for_pos + 3)?;
        }
        (0, user, *words.get(from_pos + 1)?)
    } else if let Some(pos) = find_word(&words, 0, "Invalid") {
        // Invalid user bob from 1.2.3.4 port 22
        let from_pos = find_word(&words, pos, "from")?;
        (0, *words.get(pos + 2)?, *words.get(from_pos + 1)?)
    } else {
        // PAM: authentication failure; ... rhost=1.2.3.4 ... user=bob
        let host = words.iter().find_map(|w| w.strip_prefix("rhost="))?;
        let user = words.iter().find_map(|w| w.strip_prefix("user="))?;
        (0, user, host)
    };

    build_login_log(host, user, "SSH", status == 0, time)
}

fn find_word(words: &[&str], start: usize, target: &str) -> Option<usize> {
    words[start..]
        .iter()
        .position(|word| *word == target)
        .map(|index| start + index)
}

/// 解析非 sshd 的交互式 PAM 会话（本地控制台、显示管理器、串口、telnet 等）。
/// 只认明确的服务名白名单，排除 cron/sudo/su/systemd 等非登录会话；
/// sshd 的会话由 `parse_sshd_line` 处理，这里跳过以免同一登录重复上报。
fn parse_pam_session_line(line: &str, now: DateTime<Local>) -> Option<SyslogSshLog> {
    let is_open = line.contains("session opened for user");
    let is_failed = line.contains("FAILED LOGIN") || line.contains("authentication failure");
    if !is_open && !is_failed {
        return None;
    }

    let words: Vec<&str> = line.split_whitespace().collect();
    let tag = process_tag(&words)?;
    let tag_lower = tag.to_ascii_lowercase();
    if tag_lower.contains("ssh") || tag_lower.contains("systemd") {
        return None;
    }
    if !INTERACTIVE_SERVICES.iter().any(|service| tag_lower.contains(service)) {
        return None;
    }

    let user = if is_open {
        let user_pos = find_word(&words, 0, "user")?;
        words.get(user_pos + 1)?.split('(').next()?
    } else {
        // pam_unix 用 user=xxx；login 的 FAILED LOGIN 用 FOR xxx。
        words
            .iter()
            .find_map(|word| word.strip_prefix("user="))
            .or_else(|| {
                find_word(&words, 0, "FOR")
                    .and_then(|pos| words.get(pos + 1))
                    .map(|word| word.trim_end_matches(','))
            })?
    };
    if user.is_empty() {
        return None;
    }

    let host = words
        .iter()
        .find_map(|word| word.strip_prefix("rhost="))
        .unwrap_or("");
    let login_type = classify_service_login(&tag_lower, line);
    build_login_log(
        host,
        user,
        login_type,
        is_failed,
        parse_line_time(line, now)?.timestamp(),
    )
}

/// 解析 FTP 服务（vsftpd/proftpd）的登录审计日志。
/// vsftpd: `[user] OK Login` / `[user] login failed`；
/// proftpd: `user xxx: Login successful.` / `xxx: Login failed.`
fn parse_ftp_line(line: &str, now: DateTime<Local>) -> Option<SyslogSshLog> {
    let lower = line.to_ascii_lowercase();
    let is_ftp = lower.contains("vsftpd")
        || lower.contains("proftpd")
        || (lower.contains("[pid")
            && (lower.contains("ok login")
                || lower.contains("fail login")
                || lower.contains("login failed")));
    if !is_ftp {
        return None;
    }
    let success = lower.contains("ok login")
        || lower.contains("login successful")
        || lower.contains("session opened for user");
    let failed = lower.contains("fail login")
        || lower.contains("login failed")
        || lower.contains("login incorrect")
        || lower.contains("authentication failure");
    if success == failed {
        return None;
    }

    let words: Vec<&str> = line.split_whitespace().collect();
    // 用户名来源：[bob]、user bob、user=bob、rhost 旁的 ruser=，或 "bob login failed" 的前一词。
    let user = words
        .iter()
        .find_map(|word| {
            word.strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .filter(|value| !value.is_empty() && !value.chars().all(|c| c.is_ascii_digit()))
        })
        .or_else(|| {
            let pos = find_word(&words, 0, "user")?;
            words.get(pos + 1).map(|word| word.trim_end_matches(':'))
        })
        .or_else(|| words.iter().find_map(|word| word.strip_prefix("user=")))
        .or_else(|| words.iter().find_map(|word| word.strip_prefix("ruser=")))
        .or_else(|| {
            let pos = find_word(&words, 0, "login")?;
            let candidate = words.get(pos.checked_sub(1)?)?;
            if candidate.chars().all(|c| c.is_ascii_digit()) {
                None
            } else {
                Some(candidate.trim_end_matches(':'))
            }
        })?;
    if user.is_empty() {
        return None;
    }

    // 只关心外部登录：取 rhost= 或行中第一个可解析 IP。
    // 兼容 PAM 的 `rhost=::ffff:1.2.3.4` 和 proftpd 的 `1.2.3.4[1.2.3.4]`。
    // 没有外部 IP（本机登录）直接跳过。
    let ip = words
        .iter()
        .filter_map(|word| {
            let candidate = word.strip_prefix("rhost=").unwrap_or(word);
            // vsftpd 的格式是 Client "::ffff:1.2.3.4"，先去引号再去 ::ffff: 前缀。
            let candidate = candidate.trim_matches(|c: char| {
                !c.is_ascii_alphanumeric() && c != '.' && c != ':'
            });
            let candidate = candidate.strip_prefix("::ffff:").unwrap_or(candidate);
            let candidate = candidate.split('[').next().unwrap_or(candidate);
            let addr = candidate.parse::<IpAddr>().ok()?;
            // IPv4-mapped IPv6 归一成 IPv4，避免 IP 字段变成 ::ffff:1.2.3.4。
            let addr = match addr {
                IpAddr::V6(v6) => v6.to_ipv4().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
                other => other,
            };
            if addr.is_unspecified() {
                None
            } else {
                Some(addr.to_string())
            }
        })
        .next()?;

    build_login_log(
        &ip,
        user,
        "FTP",
        failed,
        parse_line_time(line, now)?.timestamp(),
    )
}

/// 从 syslog 行中提取进程/服务名，如 `sshd-session[123]:` → `sshd-session`。
fn process_tag<'a>(words: &[&'a str]) -> Option<&'a str> {
    for word in words.iter().skip(2).take(3) {
        if let Some(end) = word.find("]:") {
            let tag = &word[..end];
            return Some(tag.split('[').next().unwrap_or(tag));
        }
    }
    None
}

/// 根据 utmp 的终端名和远端主机判断登录方式。
fn classify_terminal_login(tty: &str, host: &str) -> &'static str {
    let tty = tty.trim().to_ascii_lowercase();
    let host = host.trim().to_ascii_lowercase();
    if host.starts_with("ssh")
        || tty.contains("ssh")
        || (tty.starts_with("pts/") && host.parse::<IpAddr>().is_ok())
    {
        "SSH"
    } else if host.starts_with(':') || tty.starts_with(':') {
        "GUI"
    } else if tty.starts_with("ttys") || tty.starts_with("ttyama") || tty.contains("serial") {
        "SERIAL"
    } else if host.contains("telnet") || tty.contains("telnet") {
        "TELNET"
    } else if tty.starts_with("tty") {
        "CONSOLE"
    } else {
        "OTHER"
    }
}

/// 根据 PAM 服务名判断登录方式。
fn classify_service_login(tag: &str, line: &str) -> &'static str {
    if tag.contains("gdm")
        || tag.contains("sddm")
        || tag.contains("lightdm")
        || tag.contains("kdm")
        || tag.contains("xdm")
    {
        "GUI"
    } else if tag.contains("telnet") {
        "TELNET"
    } else if line.to_ascii_lowercase().contains("ttys")
        || line.to_ascii_lowercase().contains("ttyama")
    {
        "SERIAL"
    } else if tag.contains("login") {
        "CONSOLE"
    } else {
        "OTHER"
    }
}

/// 构造上报记录，统一校验 IP 与用户名字段。
/// 本地登录没有远端 IP（host 为空或 `:` 开头的 display），用 LOCAL_IP 占位。
fn build_login_log(
    host: &str,
    username: &str,
    login_type: &str,
    failed: bool,
    time: i64,
) -> Option<SyslogSshLog> {
    if username.is_empty() {
        return None;
    }
    let host = host.trim();
    let ip = if host.is_empty() || host.starts_with(':') || host == "-" {
        LOCAL_IP.to_string()
    } else {
        let addr: IpAddr = host.parse().ok()?;
        // 本地会话（控制台/图形/串口）允许回环；SSH/FTP/TELNET 等远程登录
        // 只关心外部来源，回环连接不上报。
        let is_local = matches!(login_type, "CONSOLE" | "GUI" | "SERIAL");
        if addr.is_unspecified() || (addr.is_loopback() && !is_local) {
            return None;
        }
        addr.to_string()
    };
    Some(SyslogSshLog {
        ip,
        username: username.to_string(),
        login_type: login_type.to_string(),
        status: if failed { 0 } else { 1 },
        log_type: 5,
        time,
    })
}

fn log_key(log: &SyslogSshLog) -> String {
    format!("{}:{}:{}:{}", log.ip, log.username, log.time, log.status)
}

/// 便捷函数：执行一次采集上报
pub async fn collect_ssh_login(
    net_client: &NetClient,
    token: Option<&str>,
) {
    let collector = SshLoginCollector::new();
    collector.collect_and_report(net_client, token).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixed_now() -> DateTime<Local> {
        Local.with_ymd_and_hms(2026, 11, 26, 10, 0, 0).single().unwrap()
    }

    #[test]
    fn parses_rfc3339_accepted_login() {
        let line = "2026-11-23T14:36:50.457403+08:00 host sshd-session[72618]: Accepted publickey for zebra from 1.2.3.4 port 59016 ssh2: RSA SHA256:abc";
        let log = parse_sshd_line(line, fixed_now()).unwrap();
        assert_eq!(log.username, "zebra");
        assert_eq!(log.ip, "1.2.3.4");
        assert_eq!(log.status, 1);
        assert_eq!(log.login_type, "SSH");
        assert_eq!(log.log_type, 5);
        assert_eq!(
            log.time,
            DateTime::parse_from_rfc3339("2026-11-23T14:36:50.457403+08:00")
                .unwrap()
                .timestamp()
        );
    }

    #[test]
    fn parses_failed_login_with_invalid_user() {
        let line = "2026-11-23T15:06:07.016169+08:00 host sshd[74470]: Failed password for invalid user bob from 5.6.7.8 port 49552 ssh2";
        let log = parse_sshd_line(line, fixed_now()).unwrap();
        assert_eq!(log.username, "bob");
        assert_eq!(log.ip, "5.6.7.8");
        assert_eq!(log.status, 0);
    }

    #[test]
    fn parses_syslog_short_timestamp_with_current_year() {
        let line = "Nov 26 09:10:44 host sshd-session[122]: Failed password for root from 9.8.7.6 port 22 ssh2";
        let log = parse_sshd_line(line, fixed_now()).unwrap();
        assert_eq!(log.username, "root");
        assert_eq!(
            log.time,
            Local.with_ymd_and_hms(2026, 11, 26, 9, 10, 44).single().unwrap().timestamp()
        );
    }

    #[test]
    fn syslog_timestamp_rolls_back_year() {
        let now = Local.with_ymd_and_hms(2026, 1, 2, 10, 0, 0).single().unwrap();
        let line = "Dec 31 23:59:59 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2";
        let log = parse_sshd_line(line, now).unwrap();
        assert_eq!(
            log.time,
            Local.with_ymd_and_hms(2025, 12, 31, 23, 59, 59).single().unwrap().timestamp()
        );
    }

    #[test]
    fn parses_journal_short_iso_without_microseconds() {
        let line = "2026-11-26T09:10:44+08:00 host sshd-session[122041]: Accepted password for zebra from 1.2.3.4 port 33660 ssh2";
        let log = parse_sshd_line(line, fixed_now()).unwrap();
        assert_eq!(log.status, 1);
        assert_eq!(log.username, "zebra");
    }

    #[test]
    fn parses_pam_authentication_failure() {
        let line = "2026-11-26T09:10:44+08:00 host sshd[1]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4 user=bob";
        let log = parse_sshd_line(line, fixed_now()).unwrap();
        assert_eq!(log.status, 0);
        assert_eq!(log.username, "bob");
        assert_eq!(log.ip, "1.2.3.4");
    }

    #[test]
    fn ignores_non_login_and_invalid_ip_lines() {
        let cases = [
            "2026-11-26T09:10:44+08:00 host CRON[1]: (root) CMD (echo hi)",
            "2026-11-26T09:10:44+08:00 host sshd[1]: Received disconnect from 1.2.3.4 port 22:11",
            "2026-11-26T09:10:44+08:00 host sshd[1]: Failed password for root from 127.0.0.1 port 22 ssh2",
            "2026-11-26T09:10:44+08:00 host sshd[1]: Failed password for root from not-an-ip port 22 ssh2",
        ];
        for line in cases {
            assert!(parse_sshd_line(line, fixed_now()).is_none(), "不应解析: {}", line);
        }
    }

    #[test]
    fn text_cursor_keeps_partial_line_and_detects_rotation() {
        let path = std::env::temp_dir().join(format!(
            "ssh_login_task_test_{}_cursor.log",
            std::process::id()
        ));
        let path_str = path.to_str().unwrap();
        let _ = std::fs::remove_file(path_str);

        let mut file = File::create(&path).unwrap();
        file.write_all(b"2026-11-26T10:00:00+08:00 h sshd[1]: Accepted password for u from 1.2.3.4 port 22 ssh2\npartial")
            .unwrap();
        drop(file);

        let mut cursor = FileCursor::default();
        let lines = read_new_lines(path_str, &mut cursor);
        assert_eq!(lines.len(), 1);
        let offset_after_complete_line = cursor.offset;

        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b" line2\n").unwrap();
        drop(file);
        let lines = read_new_lines(path_str, &mut cursor);
        assert_eq!(lines, vec!["partial line2"]);
        assert!(cursor.offset > offset_after_complete_line);

        // 轮转：文件被删除重建，游标必须归零重读。
        std::fs::remove_file(&path).unwrap();
        let mut file = File::create(&path).unwrap();
        file.write_all(b"new line\n").unwrap();
        drop(file);
        let lines = read_new_lines(path_str, &mut cursor);
        assert_eq!(lines, vec!["new line"]);
        let _ = std::fs::remove_file(path_str);
    }

    #[test]
    fn classifies_login_methods_from_terminal() {
        assert_eq!(classify_terminal_login("pts/0", "1.2.3.4"), "SSH");
        assert_eq!(classify_terminal_login("pts/0", ":0"), "GUI");
        assert_eq!(classify_terminal_login("tty1", ""), "CONSOLE");
        assert_eq!(classify_terminal_login("ttyS0", ""), "SERIAL");
        assert_eq!(classify_terminal_login("?", "telnet-host"), "TELNET");
        assert_eq!(classify_terminal_login("?", ""), "OTHER");
    }

    #[test]
    fn parses_gui_and_console_pam_sessions() {
        let gui = "2026-11-26T09:10:44+08:00 host gdm-password]: pam_unix(gdm-password:session): session opened for user zebra by (uid=0)";
        let log = parse_pam_session_line(gui, fixed_now()).unwrap();
        assert_eq!(log.username, "zebra");
        assert_eq!(log.login_type, "GUI");
        assert_eq!(log.ip, LOCAL_IP);
        assert_eq!(log.status, 1);

        let console = "2026-11-26T09:11:00+08:00 host login[123]: pam_unix(login:session): session opened for user root(uid=0) by (uid=0)";
        let log = parse_pam_session_line(console, fixed_now()).unwrap();
        assert_eq!(log.login_type, "CONSOLE");
        assert_eq!(log.username, "root");

        let serial = "2026-11-26T09:12:00+08:00 host login[124]: pam_unix(login:auth): FAILED LOGIN 1 FROM ttyS0 FOR alice, Authentication failure";
        let log = parse_pam_session_line(serial, fixed_now()).unwrap();
        assert_eq!(log.login_type, "SERIAL");
        assert_eq!(log.status, 0);
    }

    #[test]
    fn pam_session_parser_skips_sshd_and_non_interactive_services() {
        let sshd = "2026-11-26T09:10:44+08:00 host sshd[1]: pam_unix(sshd:session): session opened for user zebra(uid=1000) by zebra(uid=0)";
        assert!(parse_pam_session_line(sshd, fixed_now()).is_none());

        let cron = "2026-11-26T09:10:44+08:00 host CRON[1]: pam_unix(cron:session): session opened for user root by (uid=0)";
        assert!(parse_pam_session_line(cron, fixed_now()).is_none());

        let sudo = "2026-11-26T09:10:44+08:00 host sudo[1]: pam_unix(sudo:session): session opened for user root by zebra(uid=1000)";
        assert!(parse_pam_session_line(sudo, fixed_now()).is_none());
    }

    #[test]
    fn parses_vsftpd_login_logs() {
        let success = "2026-11-26T09:20:00+08:00 host vsftpd[123]: 1.2.3.4 [bob] OK Login";
        let log = parse_ftp_line(success, fixed_now()).unwrap();
        assert_eq!(log.username, "bob");
        assert_eq!(log.ip, "1.2.3.4");
        assert_eq!(log.login_type, "FTP");
        assert_eq!(log.status, 1);

        let failed = "2026-11-26T09:21:00+08:00 host vsftpd[123]: 1.2.3.4 [bob] login failed";
        let log = parse_ftp_line(failed, fixed_now()).unwrap();
        assert_eq!(log.status, 0);

        // vsftpd 走 PAM 审计：ruser=/rhost=，且 rhost 可能是 ::ffff: 前缀。
        let pam = "2026-11-26T10:31:58.213444+08:00 host vsftpd: pam_unix(vsftpd:auth): authentication failure; logname= uid=0 euid=0 tty=ftp ruser=ftp_test_bad rhost=::ffff:1.2.3.4";
        let log = parse_ftp_line(pam, fixed_now()).unwrap();
        assert_eq!(log.username, "ftp_test_bad");
        assert_eq!(log.ip, "1.2.3.4");
        assert_eq!(log.status, 0);

        // 本机/回环来源不上报。
        let local = "2026-11-26T10:31:58+08:00 host vsftpd: pam_unix(vsftpd:auth): authentication failure; ruser=bob rhost=::ffff:127.0.0.1";
        assert!(parse_ftp_line(local, fixed_now()).is_none());

        // 无外部 IP 的独立日志同样跳过。
        let standalone = "Mon Nov 26 09:20:00 2026 [pid 2] [alice] OK Login";
        assert!(parse_ftp_line(standalone, fixed_now()).is_none());
    }

    #[test]
    fn parses_real_vsftpd_log_format() {
        let success = "Thu Nov 26 10:40:36 2026 [pid 127468] [zebra] OK LOGIN: Client \"::ffff:192.168.4.8\"";
        let log = parse_ftp_line(success, fixed_now()).unwrap();
        assert_eq!(log.username, "zebra");
        assert_eq!(log.ip, "192.168.4.8");
        assert_eq!(log.login_type, "FTP");
        assert_eq!(log.status, 1);

        let failed = "Thu Nov 26 10:31:58 2026 [pid 126861] [ftp_test_bad] FAIL LOGIN: Client \"::ffff:1.2.3.4\"";
        let log = parse_ftp_line(failed, fixed_now()).unwrap();
        assert_eq!(log.username, "ftp_test_bad");
        assert_eq!(log.ip, "1.2.3.4");
        assert_eq!(log.status, 0);
    }

    #[test]
    fn parses_proftpd_login_logs() {
        let line = "2026-11-26T09:22:00+08:00 host proftpd[321]: 1.2.3.4 (1.2.3.4[1.2.3.4]): user carol: Login successful.";
        let log = parse_ftp_line(line, fixed_now()).unwrap();
        assert_eq!(log.username, "carol");
        assert_eq!(log.ip, "1.2.3.4");
        assert_eq!(log.login_type, "FTP");
        assert_eq!(log.status, 1);
    }
}
