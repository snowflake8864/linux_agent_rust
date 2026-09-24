use log::{LevelFilter, Record, Metadata, SetLoggerError};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use chrono::Local;
use serde::Deserialize;
use tokio::fs as async_fs;

#[derive(Deserialize, Clone, PartialEq)]
#[serde(untagged)]
enum LogLevel {
    String(String),
    Number(u8),
}

#[derive(Deserialize, Clone, PartialEq)]
pub struct LogConfig {
    pub log_level: LogLevel,
    pub log_size: u64,
    pub log_path: String,
    pub log_backup_path: String,
}

impl LogConfig {
    fn level_filter(&self) -> LevelFilter {
        match &self.log_level {
            LogLevel::String(ref s) => match s.to_lowercase().as_str() {
                "error" => LevelFilter::Error,
                "warn" => LevelFilter::Warn,
                "info" => LevelFilter::Info,
                "debug" => LevelFilter::Debug,
                "trace" => LevelFilter::Trace,
                _ => LevelFilter::Info,
            },
            LogLevel::Number(n) => match n {
                0 => LevelFilter::Off,
                1 => LevelFilter::Error,
                2 => LevelFilter::Info,
                3 => LevelFilter::Debug,
                4 => LevelFilter::Trace,
                _ => LevelFilter::Info,
            },
        }
    }
}

impl LogLevel {
    fn default_level() -> u8 {
        2
    }
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Number(Self::default_level())
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        LogConfig {
            log_level: LogLevel::default(),
            log_size: 10485760,
            log_path: "/opt/osec/log/osec_backend.log".to_string(),
            log_backup_path: "/opt/osec/log/backup".to_string(),
        }
    }
}

// 共享的当前日志配置：init/reload 都会更新它，log() 每次实时读取，
// 使日志级别、日志路径、轮转大小等可以在运行期热更新。
static SHARED_LOG_CONFIG: OnceLock<Mutex<LogConfig>> = OnceLock::new();

fn log_config() -> &'static Mutex<LogConfig> {
    // 用 get_or_init 惰性初始化默认配置：即使 init 尚未完成（比如 apply_config
    // 在 set_boxed_logger 之前就先写配置），也不会 panic。
    SHARED_LOG_CONFIG.get_or_init(|| Mutex::new(LogConfig::default()))
}

pub struct CustomLogger;

impl CustomLogger {
    fn ensure_dirs(config: &LogConfig) {
        if let Some(parent) = Path::new(&config.log_path).parent() {
            fs::create_dir_all(parent).expect("无法创建日志目录");
        }
        fs::create_dir_all(&config.log_backup_path).expect("无法创建备份目录");
    }

    async fn load_config(config_path: &str) -> Option<LogConfig> {
        let config_content = async_fs::read_to_string(config_path).await.ok()?;
        serde_json::from_str(&config_content).ok()
    }

    pub async fn init(config_path: &str) -> Result<(), SetLoggerError> {
        let config = Self::load_config(config_path)
            .await
            .expect("无法读取或解析配置文件");
        Self::apply_config(config);
        let logger = CustomLogger;
        log::set_boxed_logger(Box::new(logger))?;
        Ok(())
    }

    /// 热加载配置文件（应用日志级别/日志路径/轮转大小等）。
    /// 文件缺失、解析失败返回 Err；Ok(true)=已应用新配置，Ok(false)=与当前一致无需更新。
    pub async fn reload(config_path: &str) -> Result<bool, String> {
        let config =
            Self::load_config(config_path).await.ok_or_else(|| format!("无法读取或解析配置文件: {}", config_path))?;
        let changed = *log_config().lock().unwrap() != config;
        if changed {
            Self::apply_config(config);
        }
        Ok(changed)
    }

    fn apply_config(config: LogConfig) {
        Self::ensure_dirs(&config);
        let level_filter = config.level_filter();
        print!("======日志级别: {}", level_filter);
        *log_config().lock().unwrap() = config;
        log::set_max_level(level_filter);
    }

    fn current_log_path() -> String {
        log_config().lock().unwrap().log_path.clone()
    }

    fn rotate_log_file() {
        let (log_path, log_size, log_backup_path) = {
            let guard = log_config().lock().unwrap();
            (
                guard.log_path.clone(),
                guard.log_size,
                guard.log_backup_path.clone(),
            )
        };
        if let Ok(metadata) = fs::metadata(&log_path) {
            if metadata.len() >= log_size {
                let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
                let backup_file = format!("{}/backend_{}.log", log_backup_path, timestamp);
                if let Err(e) = fs::rename(&log_path, &backup_file) {
                    eprintln!("日志轮转失败: {}", e);
                }
            }
        }
    }
}
/*
impl log::Log for CustomLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
            let file = record.file().unwrap_or("unknown");
            let line = record.line().unwrap_or(0);
            let func = record.module_path().unwrap_or("unknown");

            let message = format!(
                "[{}]  ({}:{}:{}) [{}] {}",
                timestamp,
                file,
                line,
                func,
                record.level(),
                record.args()
            );

            self.rotate_log_file();

            if let Ok(mut file) = File::options()
                .create(true)
                .append(true)
                .open(&self.config.log_path)
            {
                writeln!(file, "{}", message).expect("无法写入日志文件");
            }

            // 控制台打印
            println!("{}", message);
        }
    }

    fn flush(&self) {}
}
*/
impl log::Log for CustomLogger {
   fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {

            let raw_msg = format!("{}", record.args());

            if raw_msg.starts_with("[PLAIN] ") {
                let plain_content = &raw_msg["[PLAIN] ".len()..];

                Self::rotate_log_file();

                if let Ok(mut file) = File::options().create(true).append(true).open(Self::current_log_path()) {
                    writeln!(file, "{}", plain_content).ok();
                }

                println!("{}", plain_content);
                return;
            }

            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
            let level = record.level();

            let raw_msg = format!("{}", record.args());

            // 检查是否是模块日志：[MOD:name] content
            if let Some(stripped) = raw_msg.strip_prefix("[MOD:") {
                if let Some(end_idx) = stripped.find("] ") {
                    let module = &stripped[..end_idx];
                    let content = &stripped[end_idx + 2..];
                    let full_message = format!("[{}] [/{}/{}] {}", timestamp, module, level, content);

                    Self::rotate_log_file();
                    if let Ok(mut file) = File::options().create(true).append(true).open(Self::current_log_path()) {
                        writeln!(file, "{}", full_message).ok();
                    }
                    println!("{}", full_message);
                    return;
                }
            }

            // 否则，走原始带位置信息的日志（用于调试）
            let file = record.file().unwrap_or("unknown");
            let line = record.line().unwrap_or(0);
            let func = record.module_path().unwrap_or("unknown");
            let full_message = format!(
                "[{}] ({}:{}:{}) [{}] {}",
                timestamp, file, line, func, level, raw_msg
            );

            Self::rotate_log_file();
            if let Ok(mut file) = File::options().create(true).append(true).open(Self::current_log_path()) {
                writeln!(file, "{}", full_message).ok();
            }
            println!("{}", full_message);
        }
    }

    fn flush(&self) {}
}
// 日志宏定义
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {{
        use log::Level::Info;
        log::log!(Info, $($arg)*);
    }};
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {{
        use log::Level::Debug;
        log::log!(Debug, $($arg)*);
    }};
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {{
        use log::Level::Error;
        log::log!(Error, $($arg)*);
    }};
}
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {{
        use log::Level::Warn;
        log::log!(Warn, $($arg)*);
    }};
}
#[macro_export]
macro_rules! log_mod {
    ($module:expr, $($arg:tt)*) => {{
        use log::Level::Info;
        log::log!(Info, "[MOD:{}] {}", $module, format_args!($($arg)*));
    }};
}
#[macro_export]
macro_rules! log_raw {
    ($($arg:tt)*) => {{
        use log::Level::Info;
        log::log!(Info, "[RAW] {}", format_args!($($arg)*));
    }};
}
#[macro_export]
macro_rules! log_plain {
    ($($arg:tt)*) => {{
        use log::Level::Info;
        log::log!(Info, "[PLAIN] {}", format_args!($($arg)*));
    }};
}
