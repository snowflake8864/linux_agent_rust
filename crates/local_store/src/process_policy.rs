//! process_policy.db — process_policy 表
//!
//! 进程黑白名单 hash 持久化，支持：
//!   - process_policy       在线基线（服务器下发）
//!   - process_policy_local 离线本地（gRPC 下发）
//!
//! hash 为主键，is_white=1 表示白名单，0 表示黑名单。

use rusqlite::{params, Result};

const DB_PATH: &str = "/opt/osec/db/process_policy.db";

/// 建在线表（幂等，已存在时跳过）
pub fn init_table() -> Result<()> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS process_policy (
            hash     TEXT    PRIMARY KEY,
            is_white INTEGER NOT NULL
        );",
    )?;
    Ok(())
}

/// 加载在线表全部记录，返回 (hash, is_white) 列表
pub fn load_all() -> Result<Vec<(String, bool)>> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let mut stmt = conn.prepare("SELECT hash, is_white FROM process_policy")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)? != 0))
    })?;
    rows.collect()
}

/// 全量替换在线表：在事务内清空旧数据，再批量插入白名单和黑名单
pub fn save_all(white: &[String], black: &[String]) -> Result<()> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    conn.execute("DELETE FROM process_policy", [])?;

    let mut stmt =
        conn.prepare("INSERT INTO process_policy (hash, is_white) VALUES (?1, ?2)")?;
    for h in white {
        stmt.execute(params![h, 1])?;
    }
    for h in black {
        stmt.execute(params![h, 0])?;
    }
    Ok(())
}

// ── 离线本地表 process_policy_local ──────────────────────────────

/// 建离线本地表（与在线表结构相同）
pub fn init_local_table() -> Result<()> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS process_policy_local (
            hash     TEXT    PRIMARY KEY,
            is_white INTEGER NOT NULL
        );",
    )?;
    Ok(())
}

/// 加载离线本地表全部记录
pub fn load_all_local() -> Result<Vec<(String, bool)>> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let mut stmt = conn.prepare("SELECT hash, is_white FROM process_policy_local")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)? != 0))
    })?;
    rows.collect()
}

/// 全量替换离线本地表
pub fn save_all_local(white: &[String], black: &[String]) -> Result<()> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    conn.execute("DELETE FROM process_policy_local", [])?;

    let mut stmt =
        conn.prepare("INSERT INTO process_policy_local (hash, is_white) VALUES (?1, ?2)")?;
    for h in white {
        stmt.execute(params![h, 1])?;
    }
    for h in black {
        stmt.execute(params![h, 0])?;
    }
    Ok(())
}
