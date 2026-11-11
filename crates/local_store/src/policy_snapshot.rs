//! policy_snapshot.db — 通用策略快照表
//!
//! 用于虚拟端口、IP 阻断、黑 IP、外联检测等策略的 JSON 全量快照持久化。
//! 每个 domain 一行 JSON，并在同一事务内递增 policy_meta.version。

use rusqlite::{params, Result};

const DB_PATH: &str = "/opt/osec/db/policy_snapshot.db";

pub fn init_table() -> Result<()> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS policy_snapshot (
            domain TEXT PRIMARY KEY,
            json   TEXT NOT NULL
        );",
    )?;
    Ok(())
}

pub fn save(domain: &str, json: &str) -> Result<u64> {
    let mut conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT OR REPLACE INTO policy_snapshot (domain, json) VALUES (?1, ?2)",
        params![domain, json],
    )?;
    let version = crate::policy_meta::bump_version(&tx, domain)?;
    tx.commit()?;
    Ok(version)
}

pub fn load(domain: &str) -> Result<Option<String>> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    let mut stmt = conn.prepare("SELECT json FROM policy_snapshot WHERE domain = ?1")?;
    let mut rows = stmt.query(params![domain])?;
    match rows.next()? {
        Some(row) => Ok(Some(row.get(0)?)),
        None => Ok(None),
    }
}

pub fn version(domain: &str) -> Result<u64> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    crate::policy_meta::current_version(&conn, domain)
}

pub fn clear(domain: &str) -> Result<()> {
    let mut conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM policy_snapshot WHERE domain = ?1", params![domain])?;
    tx.execute(
        "DELETE FROM policy_meta WHERE table_name = ?1",
        params![domain],
    )?;
    tx.commit()?;
    Ok(())
}
