//! 统一 SQLite 连接管理，供所有业务 crate 复用。
//!
//! 职责：
//!   - 确保 DB 目录存在
//!   - 以统一配置（WAL + NORMAL synchronous）打开连接

use rusqlite::{Connection, Result};
use std::path::Path;

/// 所有 SQLite 数据库文件统一存放目录
pub const DB_DIR: &str = "/opt/osec/db";

/// 确保 DB 目录存在（首次运行自动创建）
pub fn ensure_db_dir() {
    if !Path::new(DB_DIR).exists() {
        if let Err(e) = std::fs::create_dir_all(DB_DIR) {
            log::error!("[sqlite_db] 创建 DB 目录失败: {}", e);
        } else {
            log::info!("[sqlite_db] 创建 DB 目录: {}", DB_DIR);
        }
    }
}

/// 打开指定路径的 SQLite 连接，启用 WAL 模式（并发写更安全）
pub fn open_conn(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
    Ok(conn)
}
