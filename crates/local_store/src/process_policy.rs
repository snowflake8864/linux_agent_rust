//! process_policy.db — process_policy 表
//!
//! 进程黑白名单 hash 持久化，支持：
//!   - process_policy       在线基线（服务器下发）
//!   - process_policy_local 离线本地（gRPC 下发）
//!
//! hash 为主键，is_white=1 表示白名单，0 表示黑名单。
//! 每次保存都会在同一个事务内递增 policy_meta.version，读侧据此做变更检测。

use logging::log_info;
use rusqlite::{params, Result};

const DB_PATH: &str = "/opt/osec/db/process_policy.db";

fn create_table(table: &str) -> Result<()> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {table} (
            hash     TEXT    PRIMARY KEY,
            is_white INTEGER NOT NULL
        );"
    ))?;
    Ok(())
}

fn load(table: &str) -> Result<Vec<(String, bool)>> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let mut stmt = conn.prepare(&format!("SELECT hash, is_white FROM {table}"))?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)? != 0))
    })?;
    rows.collect()
}

fn save(table: &str, white: &[String], black: &[String]) -> Result<u64> {
    let mut conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    let tx = conn.transaction()?;
    tx.execute(&format!("DELETE FROM {table}"), [])?;

    {
        let mut stmt =
            tx.prepare(&format!("INSERT INTO {table} (hash, is_white) VALUES (?1, ?2)"))?;
        for h in white {
            stmt.execute(params![h, 1])?;
        }
        for h in black {
            stmt.execute(params![h, 0])?;
        }
    }

    let version = crate::policy_meta::bump_version(&tx, table)?;
    tx.commit()?;
    Ok(version)
}

/// 建在线表（幂等，已存在时跳过）
pub fn init_table() -> Result<()> {
    create_table("process_policy")
}

/// 加载在线表全部记录，返回 (hash, is_white) 列表
pub fn load_all() -> Result<Vec<(String, bool)>> {
    log_info!("start load process_policy tbl..");
    load("process_policy")
}

/// 全量替换在线表，返回新版本号
pub fn save_all(white: &[String], black: &[String]) -> Result<u64> {
    save("process_policy", white, black)
}

// ── 离线本地表 process_policy_local ──────────────────────────────

/// 建离线本地表（与在线表结构相同）
pub fn init_local_table() -> Result<()> {
    create_table("process_policy_local")
}

/// 加载离线本地表全部记录
pub fn load_all_local() -> Result<Vec<(String, bool)>> {
    load("process_policy_local")
}

/// 全量替换离线本地表，返回新版本号
pub fn save_all_local(white: &[String], black: &[String]) -> Result<u64> {
    save("process_policy_local", white, black)
}

/// 当前域版本号 = max(在线基线表, 离线本地表)
pub fn version() -> Result<u64> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    let online = crate::policy_meta::current_version(&conn, "process_policy")?;
    let local = crate::policy_meta::current_version(&conn, "process_policy_local")?;
    Ok(online.max(local))
}

/// 离线本地表是否被写入过（即使是空名单，也表示“本地策略已接管”）。
/// 兼容旧版本：若本地表已有数据但没有 policy_meta 记录，也视为已写入。
pub fn local_present() -> Result<bool> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    if crate::policy_meta::current_version(&conn, "process_policy_local")? > 0 {
        return Ok(true);
    }
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM process_policy_local",
        [],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// 清空离线本地表并移除其版本标记（上线时服务器策略接管）。
pub fn clear_local() -> Result<()> {
    let mut conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM process_policy_local", [])?;
    tx.execute(
        "DELETE FROM policy_meta WHERE table_name = 'process_policy_local'",
        [],
    )?;
    tx.commit()?;
    Ok(())
}
