//! dir_policy.db — 防篡改目录策略持久化
//!
//! 以单行 JSON 快照保存完整策略列表（Vec<POLICY_PROTECT_DIR> 的序列化结果），支持：
//!   - dir_policy       在线基线（服务器 task_down_dir_policy 下发）
//!   - dir_policy_local 离线本地（gRPC update_dir_policy 下发）
//!
//! 由 task::policy_persistence 负责 typed <-> JSON 转换，此处只存字符串。
//! 每次保存都会在同一个事务内递增 policy_meta.version，读侧据此做变更检测。

use rusqlite::{params, Result};

const DB_PATH: &str = "/opt/osec/db/dir_policy.db";

fn create_table(table: &str) -> Result<()> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {table} (
            id   INTEGER PRIMARY KEY CHECK (id = 1),
            json TEXT NOT NULL
        );"
    ))?;
    Ok(())
}

fn save(table: &str, json: &str) -> Result<u64> {
    let mut conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    let tx = conn.transaction()?;
    tx.execute(
        &format!("INSERT OR REPLACE INTO {table} (id, json) VALUES (1, ?1)"),
        params![json],
    )?;
    let version = crate::policy_meta::bump_version(&tx, table)?;
    tx.commit()?;
    Ok(version)
}

fn load(table: &str) -> Result<Option<String>> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let mut stmt = conn.prepare(&format!("SELECT json FROM {table} WHERE id = 1"))?;
    let mut rows = stmt.query([])?;
    match rows.next()? {
        Some(row) => Ok(Some(row.get(0)?)),
        None => Ok(None),
    }
}

/// 建在线基线表（幂等）
pub fn init_table() -> Result<()> {
    create_table("dir_policy")
}

/// 建离线本地表（幂等）
pub fn init_local_table() -> Result<()> {
    create_table("dir_policy_local")
}

/// 全量替换在线基线表，返回新版本号
pub fn save_all(json: &str) -> Result<u64> {
    save("dir_policy", json)
}

/// 全量替换离线本地表，返回新版本号
pub fn save_all_local(json: &str) -> Result<u64> {
    save("dir_policy_local", json)
}

/// 加载在线基线表（无记录返回 None）
pub fn load_all() -> Result<Option<String>> {
    load("dir_policy")
}

/// 加载离线本地表（无记录返回 None）
pub fn load_all_local() -> Result<Option<String>> {
    load("dir_policy_local")
}

/// 当前域版本号 = max(在线基线表, 离线本地表)
pub fn version() -> Result<u64> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    let online = crate::policy_meta::current_version(&conn, "dir_policy")?;
    let local = crate::policy_meta::current_version(&conn, "dir_policy_local")?;
    Ok(online.max(local))
}

/// 清空离线本地表（上线时服务器策略接管）。有实际删除时返回新版本号。
pub fn clear_local() -> Result<u64> {
    let mut conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    let tx = conn.transaction()?;
    let deleted = tx.execute("DELETE FROM dir_policy_local", [])?;
    let version = if deleted > 0 {
        crate::policy_meta::bump_version(&tx, "dir_policy_local")?
    } else {
        crate::policy_meta::current_version(&tx, "dir_policy_local")?
    };
    tx.commit()?;
    Ok(version)
}
