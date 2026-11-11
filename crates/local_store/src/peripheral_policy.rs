//! peripheral_policy.db — peripheral_policy 表
//!
//! 外设（USB）黑白名单持久化，支持：
//!   - peripheral_policy       在线基线（服务器下发）
//!   - peripheral_policy_local 离线本地（gRPC 下发）
//!
//! peripheral_eid 为主键，is_white=1 表示白名单，0 表示黑名单。
//! 每次保存都会在同一个事务内递增 policy_meta.version，读侧据此做变更检测。

use rusqlite::{params, Result};

const DB_PATH: &str = "/opt/osec/db/peripheral_policy.db";

fn create_table(table: &str) -> Result<()> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {table} (
            peripheral_eid  TEXT PRIMARY KEY,
            peripheral_name TEXT NOT NULL DEFAULT '',
            intro           TEXT NOT NULL DEFAULT '',
            type_           TEXT NOT NULL DEFAULT '',
            is_white        INTEGER NOT NULL
        );"
    ))?;
    Ok(())
}

fn load(table: &str) -> Result<Vec<PeripheralPolicyRow>> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let mut stmt = conn.prepare(&format!(
        "SELECT peripheral_eid, peripheral_name, intro, type_, is_white FROM {table}"
    ))?;
    let rows = stmt.query_map([], |row| {
        Ok(PeripheralPolicyRow {
            peripheral_eid: row.get(0)?,
            peripheral_name: row.get(1)?,
            intro: row.get(2)?,
            type_: row.get(3)?,
            is_white: row.get::<_, i32>(4)? != 0,
        })
    })?;
    rows.collect()
}

fn save(table: &str, white: &[PeripheralPolicyRow], black: &[PeripheralPolicyRow]) -> Result<u64> {
    let mut conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    let tx = conn.transaction()?;
    tx.execute(&format!("DELETE FROM {table}"), [])?;

    {
        let mut stmt = tx.prepare(&format!(
            "INSERT INTO {table} (peripheral_eid, peripheral_name, intro, type_, is_white)
             VALUES (?1, ?2, ?3, ?4, ?5)"
        ))?;
        for row in white {
            stmt.execute(params![
                row.peripheral_eid,
                row.peripheral_name,
                row.intro,
                row.type_,
                1
            ])?;
        }
        for row in black {
            stmt.execute(params![
                row.peripheral_eid,
                row.peripheral_name,
                row.intro,
                row.type_,
                0
            ])?;
        }
    }

    let version = crate::policy_meta::bump_version(&tx, table)?;
    tx.commit()?;
    Ok(version)
}

/// 建在线表（幂等，已存在时跳过）
pub fn init_table() -> Result<()> {
    create_table("peripheral_policy")
}

/// 加载在线表全部记录
pub fn load_all() -> Result<Vec<PeripheralPolicyRow>> {
    load("peripheral_policy")
}

/// 全量替换在线表，返回新版本号
pub fn save_all(white: &[PeripheralPolicyRow], black: &[PeripheralPolicyRow]) -> Result<u64> {
    save("peripheral_policy", white, black)
}

// ── 离线本地表 peripheral_policy_local ──────────────────────────────

/// 建离线本地表（与在线表结构相同）
pub fn init_local_table() -> Result<()> {
    create_table("peripheral_policy_local")
}

/// 加载离线本地表全部记录
pub fn load_all_local() -> Result<Vec<PeripheralPolicyRow>> {
    load("peripheral_policy_local")
}

/// 全量替换离线本地表，返回新版本号
pub fn save_all_local(
    white: &[PeripheralPolicyRow],
    black: &[PeripheralPolicyRow],
) -> Result<u64> {
    save("peripheral_policy_local", white, black)
}

/// 当前域版本号 = max(在线基线表, 离线本地表)
pub fn version() -> Result<u64> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    let online = crate::policy_meta::current_version(&conn, "peripheral_policy")?;
    let local = crate::policy_meta::current_version(&conn, "peripheral_policy_local")?;
    Ok(online.max(local))
}

/// 离线本地表是否被写入过（即使是空名单，也表示“本地策略已接管”）。
/// 兼容旧版本：若本地表已有数据但没有 policy_meta 记录，也视为已写入。
pub fn local_present() -> Result<bool> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    if crate::policy_meta::current_version(&conn, "peripheral_policy_local")? > 0 {
        return Ok(true);
    }
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM peripheral_policy_local",
        [],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

#[derive(Debug, Clone, Default)]
pub struct PeripheralPolicyRow {
    pub peripheral_eid: String,
    pub peripheral_name: String,
    pub intro: String,
    pub type_: String,
    pub is_white: bool,
}

/// 清空离线本地表并移除其版本标记（上线时服务器策略接管）。
pub fn clear_local() -> Result<()> {
    let mut conn = sqlite_db::db::open_conn(DB_PATH)?;
    crate::policy_meta::ensure_meta(&conn)?;
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM peripheral_policy_local", [])?;
    tx.execute(
        "DELETE FROM policy_meta WHERE table_name = 'peripheral_policy_local'",
        [],
    )?;
    tx.commit()?;
    Ok(())
}
