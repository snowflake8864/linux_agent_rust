//! process_policy.db — process_policy 表
//!
//! 进程黑白名单 hash 持久化，支持：
//!   - 全量保存（save_all）
//!   - 全量加载（load_all）
//!
//! hash 为主键，is_white=1 表示白名单，0 表示黑名单。

use rusqlite::{params, Result};
use crate::db::open_conn;

const DB_PATH: &str = "/opt/osec/db/process_policy.db";

/// 建表（幂等，已存在时跳过）
pub fn init_table() -> Result<()> {
    let conn = open_conn(DB_PATH)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS process_policy (
            hash     TEXT    PRIMARY KEY,
            is_white INTEGER NOT NULL
        );"
    )?;
    Ok(())
}

/// 加载全部记录，返回 (hash, is_white) 列表
pub fn load_all() -> Result<Vec<(String, bool)>> {
    let conn = open_conn(DB_PATH)?;
    let mut stmt = conn.prepare("SELECT hash, is_white FROM process_policy")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)? != 0))
    })?;
    rows.collect()
}

/// 全量替换：在事务内清空旧数据，再批量插入白名单和黑名单
pub fn save_all(white: &[String], black: &[String]) -> Result<()> {
    let conn = open_conn(DB_PATH)?;
    conn.execute("DELETE FROM process_policy", [])?;

    let mut stmt = conn.prepare("INSERT INTO process_policy (hash, is_white) VALUES (?1, ?2)")?;
    for h in white {
        stmt.execute(params![h, 1])?;
    }
    for h in black {
        stmt.execute(params![h, 0])?;
    }
    Ok(())
}
