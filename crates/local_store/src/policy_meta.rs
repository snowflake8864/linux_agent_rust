//! 策略版本元数据：每个策略 DB 文件内按表维护单调递增 version。
//!
//! 写入策略数据与 version 必须处于同一事务，读侧通过 version 判断是否需要
//! 重新从 DB 加载，避免无变化时重复下发内核。

use rusqlite::{params, Connection, Result};

const META_TABLE: &str = "policy_meta";

pub fn ensure_meta(conn: &Connection) -> Result<()> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {META_TABLE} (
            table_name TEXT PRIMARY KEY,
            version    INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );"
    ))?;
    Ok(())
}

/// 在调用方事务内递增指定表的版本并返回新版本号。
pub fn bump_version(conn: &Connection, table: &str) -> Result<u64> {
    conn.execute(
        &format!(
            "INSERT INTO {META_TABLE} (table_name, version, updated_at)
             VALUES (?1, 1, strftime('%s','now'))
             ON CONFLICT(table_name) DO UPDATE SET
                version = version + 1,
                updated_at = strftime('%s','now')"
        ),
        params![table],
    )?;
    conn.query_row(
        &format!("SELECT version FROM {META_TABLE} WHERE table_name = ?1"),
        params![table],
        |row| row.get(0),
    )
}

/// 读取指定表的当前版本号，未写入过时返回 0。
pub fn current_version(conn: &Connection, table: &str) -> Result<u64> {
    let mut stmt = conn.prepare(&format!(
        "SELECT version FROM {META_TABLE} WHERE table_name = ?1"
    ))?;
    let mut rows = stmt.query(params![table])?;
    match rows.next()? {
        Some(row) => Ok(row.get(0)?),
        None => Ok(0),
    }
}
