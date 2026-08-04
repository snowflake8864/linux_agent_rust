//! known_executables.db — known_executables 表
//!
//! 记录非标准目录中的可执行文件（由内核 UIO 事件发现），
//! 作为 ExecutableList 标准目录扫描的补充数据源。
//!
//! hash 为主键（MD5 去重），一个 hash 只保留一条。
//!
//! policy_status: 0=未知, 1=白名单, 2=黑名单

use rusqlite::{params, Result};

const DB_PATH: &str = "/opt/osec/db/known_executables.db";

/// 建表（幂等，已存在时跳过）
pub fn init_table() -> Result<()> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS known_executables (
            hash          TEXT PRIMARY KEY,
            path          TEXT NOT NULL DEFAULT '',
            policy_status INTEGER NOT NULL DEFAULT 0,
            first_seen    TEXT NOT NULL DEFAULT '',
            last_seen     TEXT NOT NULL DEFAULT ''
        );",
    )?;
    Ok(())
}

/// 全量加载，返回 (hash, path, policy_status)
pub fn load_all() -> Result<Vec<(String, String, i32)>> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let mut stmt = conn.prepare("SELECT hash, path, policy_status FROM known_executables")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i32>(2)?,
        ))
    })?;
    rows.collect()
}

/// 插入或更新（MD5 去重：hash 已存在则更新 path、policy_status、last_seen）
pub fn upsert(hash: &str, path: &str, policy_status: i32) -> Result<()> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let now = chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    conn.execute(
        "INSERT INTO known_executables (hash, path, policy_status, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?4)
         ON CONFLICT(hash) DO UPDATE SET
             path = excluded.path,
             policy_status = excluded.policy_status,
             last_seen = excluded.last_seen",
        params![hash, path, policy_status, now],
    )?;
    Ok(())
}

/// 批量更新指定 hashes 的 policy_status（ProcessPolicy 变更时调用）
pub fn update_policy_status(hashes: &[String], is_white: bool) -> Result<usize> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let target = if is_white { 1i32 } else { 2i32 };
    let mut count = 0usize;
    for h in hashes {
        count += conn.execute(
            "UPDATE known_executables SET policy_status = ?1 WHERE hash = ?2",
            params![target, h],
        )?;
    }
    Ok(count)
}
