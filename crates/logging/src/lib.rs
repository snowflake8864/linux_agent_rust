use log::{LevelFilter, Record, Metadata, SetLoggerError};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use chrono::Local;
use serde::Deserialize;
use tokio::fs as async_fs;

#[derive(Deserialize)]
#[serde(untagged)]
enum LogLevel {
    String(String),
    Number(u8),
}

#[derive(Deserialize)]
pub struct LogConfig {
    pub log_level: LogLevel,
    pub log_size: u64,
    pub log_path: String,
    pub log_backup_path: String,
}

pub struct CustomLogger {
    config: LogConfig,
}

impl CustomLogger {
    pub fn new(config: LogConfig) -> Self {
        if let Some(parent) = Path::new(&config.log_path).parent() {
            fs::create_dir_all(parent).expect("无法创建日志目录");
        }
        fs::create_dir_all(&config.log_backup_path).expect("无法创建备份目录");
        CustomLogger { config }
    }

    pub async fn init(config_path: &str) -> Result<(), SetLoggerError> {
        let config_content = async_fs::read_to_string(config_path)
            .await
            .expect("无法读取配置文件");
        let config: LogConfig = serde_json::from_str(&config_content).expect("无法解析配置文件");

        let level_filter = match &config.log_level {
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
        };
        print!("======日志级别: {}", level_filter);
        let logger = CustomLogger::new(config);
        log::set_boxed_logger(Box::new(logger))?;
        log::set_max_level(level_filter);
        Ok(())
    }

    fn rotate_log_file(&self) {
        let log_path = &self.config.log_path;
        if let Ok(metadata) = fs::metadata(log_path) {
            if metadata.len() >= self.config.log_size {
                let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
                let backup_file = format!("{}/backend_{}.log", self.config.log_backup_path, timestamp);
                if let Err(e) = fs::rename(log_path, &backup_file) {
                    eprintln!("日志轮转失败: {}", e);
                }
            }
        }
    }
}

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

