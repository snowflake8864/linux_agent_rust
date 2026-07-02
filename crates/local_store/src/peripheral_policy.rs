//! peripheral_policy.db — peripheral_policy 表
//!
//! 外设（USB）黑白名单持久化，支持：
//!   - 全量保存（save_all）
//!   - 全量加载（load_all）
//!
//! peripheral_eid 为主键，is_white=1 表示白名单，0 表示黑名单。

use rusqlite::{params, Result};
use crate::db::open_conn;

const DB_PATH: &str = "/opt/osec/db/peripheral_policy.db";

/// 建表（幂等，已存在时跳过）
pub fn init_table() -> Result<()> {
    let conn = open_conn(DB_PATH)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS peripheral_policy (
            peripheral_eid  TEXT PRIMARY KEY,
            peripheral_name TEXT NOT NULL DEFAULT '',
            intro           TEXT NOT NULL DEFAULT '',
            type_           TEXT NOT NULL DEFAULT '',
            is_white        INTEGER NOT NULL
        );"
    )?;
    Ok(())
}

/// 加载全部记录
pub fn load_all() -> Result<Vec<PeripheralPolicyRow>> {
    let conn = open_conn(DB_PATH)?;
    let mut stmt = conn.prepare(
        "SELECT peripheral_eid, peripheral_name, intro, type_, is_white FROM peripheral_policy"
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(PeripheralPolicyRow {
            peripheral_eid:  row.get(0)?,
            peripheral_name: row.get(1)?,
            intro:           row.get(2)?,
            type_:           row.get(3)?,
            is_white:        row.get::<_, i32>(4)? != 0,
        })
    })?;
    rows.collect()
}

/// 全量替换：清空旧数据，批量插入白名单和黑名单
pub fn save_all(white: &[PeripheralPolicyRow], black: &[PeripheralPolicyRow]) -> Result<()> {
    let conn = open_conn(DB_PATH)?;
    conn.execute("DELETE FROM peripheral_policy", [])?;

    let mut stmt = conn.prepare(
        "INSERT INTO peripheral_policy (peripheral_eid, peripheral_name, intro, type_, is_white)
         VALUES (?1, ?2, ?3, ?4, ?5)"
    )?;
    for row in white {
        stmt.execute(params![row.peripheral_eid, row.peripheral_name, row.intro, row.type_, 1])?;
    }
    for row in black {
        stmt.execute(params![row.peripheral_eid, row.peripheral_name, row.intro, row.type_, 0])?;
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct PeripheralPolicyRow {
    pub peripheral_eid:  String,
    pub peripheral_name: String,
    pub intro:           String,
    pub type_:           String,
    pub is_white:        bool,
}
