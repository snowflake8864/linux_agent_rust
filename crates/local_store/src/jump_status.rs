//! jump.db — jump_status 表
//!
//! 单行设计（id 固定为 1），程序重启时从此表恢复内存缓存 JUMP_STATUS，
//! 在线模式成功拉取 /v1/newestJumpInfo 后写入此表。

use rusqlite::{params, Result};
use serde::{Deserialize, Serialize};

const DB_PATH: &str = "/opt/osec/db/jump.db";

/// 与 grpc_gateway::jump::JumpStatus 字段对应的本地存储结构
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct JumpStatusRow {
    pub current_ip: String,
    pub source_ip: String,
    pub target_ip: String,
    pub gateway: String,
    pub mode: u32,
    pub current_password: String,
    pub last_ip_jump_time: String,
    pub last_pw_jump_time: String,
    pub last_pw_jump_user: String,
    pub ip_scheme: u32,
    pub ip_cycle_label: String,
    pub ip_timing_label: String,
    pub ip_way_label: String,
    pub pw_scheme: u32,
    pub pw_cycle_label: String,
    pub pw_timing_label: String,
    pub updated_at: String,
}

/// 建表（幂等，表已存在时跳过）
pub fn init_table() -> Result<()> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS jump_status (
            id                INTEGER PRIMARY KEY,
            current_ip        TEXT    NOT NULL DEFAULT '',
            source_ip         TEXT    NOT NULL DEFAULT '',
            target_ip         TEXT    NOT NULL DEFAULT '',
            gateway           TEXT    NOT NULL DEFAULT '',
            mode              INTEGER NOT NULL DEFAULT 0,
            current_password  TEXT    NOT NULL DEFAULT '',
            last_ip_jump_time TEXT    NOT NULL DEFAULT '',
            last_pw_jump_time TEXT    NOT NULL DEFAULT '',
            last_pw_jump_user TEXT    NOT NULL DEFAULT '',
            ip_scheme         INTEGER NOT NULL DEFAULT 0,
            ip_cycle_label    TEXT    NOT NULL DEFAULT '',
            ip_timing_label   TEXT    NOT NULL DEFAULT '',
            ip_way_label      TEXT    NOT NULL DEFAULT '',
            pw_scheme         INTEGER NOT NULL DEFAULT 0,
            pw_cycle_label    TEXT    NOT NULL DEFAULT '',
            pw_timing_label   TEXT    NOT NULL DEFAULT '',
            updated_at        TEXT    NOT NULL DEFAULT ''
        );",
    )?;
    Ok(())
}

/// 写入或更新跳变状态（INSERT OR REPLACE，id 固定为 1）
pub fn upsert(row: &JumpStatusRow) -> Result<()> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    conn.execute(
        "INSERT OR REPLACE INTO jump_status (
            id, current_ip, source_ip, target_ip, gateway, mode,
            current_password, last_ip_jump_time, last_pw_jump_time, last_pw_jump_user,
            ip_scheme, ip_cycle_label, ip_timing_label, ip_way_label,
            pw_scheme, pw_cycle_label, pw_timing_label, updated_at
        ) VALUES (
            1, ?1, ?2, ?3, ?4, ?5,
            ?6, ?7, ?8, ?9,
            ?10, ?11, ?12, ?13,
            ?14, ?15, ?16, ?17
        )",
        params![
            row.current_ip,
            row.source_ip,
            row.target_ip,
            row.gateway,
            row.mode,
            row.current_password,
            row.last_ip_jump_time,
            row.last_pw_jump_time,
            row.last_pw_jump_user,
            row.ip_scheme,
            row.ip_cycle_label,
            row.ip_timing_label,
            row.ip_way_label,
            row.pw_scheme,
            row.pw_cycle_label,
            row.pw_timing_label,
            row.updated_at,
        ],
    )?;
    Ok(())
}

/// 从数据库加载跳变状态（行不存在时返回 None）
pub fn load() -> Result<Option<JumpStatusRow>> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let mut stmt = conn.prepare(
        "SELECT current_ip, source_ip, target_ip, gateway, mode,
                current_password, last_ip_jump_time, last_pw_jump_time, last_pw_jump_user,
                ip_scheme, ip_cycle_label, ip_timing_label, ip_way_label,
                pw_scheme, pw_cycle_label, pw_timing_label, updated_at
         FROM jump_status WHERE id = 1",
    )?;

    let mut rows = stmt.query_map([], |r| {
        Ok(JumpStatusRow {
            current_ip: r.get(0)?,
            source_ip: r.get(1)?,
            target_ip: r.get(2)?,
            gateway: r.get(3)?,
            mode: r.get::<_, u32>(4)?,
            current_password: r.get(5)?,
            last_ip_jump_time: r.get(6)?,
            last_pw_jump_time: r.get(7)?,
            last_pw_jump_user: r.get(8)?,
            ip_scheme: r.get::<_, u32>(9)?,
            ip_cycle_label: r.get(10)?,
            ip_timing_label: r.get(11)?,
            ip_way_label: r.get(12)?,
            pw_scheme: r.get::<_, u32>(13)?,
            pw_cycle_label: r.get(14)?,
            pw_timing_label: r.get(15)?,
            updated_at: r.get(16)?,
        })
    })?;

    match rows.next() {
        Some(row) => Ok(Some(row?)),
        None => Ok(None),
    }
}
