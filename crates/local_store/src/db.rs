use rusqlite::{Connection, Result};
use std::path::Path;

/// 所有数据库文件统一存放目录
pub const DB_DIR: &str = "/opt/osec/db";

/// 确保 DB 目录存在（首次运行自动创建）
pub fn ensure_db_dir() {
    if !Path::new(DB_DIR).exists() {
        if let Err(e) = std::fs::create_dir_all(DB_DIR) {
            logging::log_error!("[local_store] 创建 DB 目录失败: {}", e);
        } else {
            logging::log_info!("[local_store] 创建 DB 目录: {}", DB_DIR);
        }
    }
}

/// 打开指定路径的 SQLite 连接，启用 WAL 模式（并发写更安全）
pub fn open_conn(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
    Ok(conn)
}
