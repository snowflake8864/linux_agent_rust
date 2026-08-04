//! quarantine.db — quarantine 表
//!
//! 病毒隔离/还原元数据持久化，替代原有的 .meta JSON 文件方案。
//!
//! 优势：
//!   - (dev, ino) 联合唯一，防止重复隔离
//!   - 支持按病毒名、原始路径、时间范围高效查询
//!   - 还原后标记 restored=1 而非删除，保留历史审计
//!
//! 用法：
//!   隔离时 insert() 一条记录
//!   还原时 mark_restored(id)
//!   查询隔离清单 list_quarantined() / list_by_virus()

use rusqlite::{params, Result};
use serde::{Deserialize, Serialize};

const DB_PATH: &str = "/opt/osec/db/quarantine.db";

/// quarantine 行结构
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct QuarantineRow {
    pub id: i64,
    pub dev: u64,
    pub ino: u64,
    pub original_path: String,
    pub quar_name: String,    // 隔离文件名: {dev}_{ino}_{original_name}
    pub virus_name: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub file_size: u64,
    pub quarantined_at: String, // RFC3339
    pub restored: bool,         // false=已隔离, true=已还原
    pub restored_at: String,    // 还原时间，未还原为空
}

/// 建表（幂等）
pub fn init_table() -> Result<()> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS quarantine (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            dev             INTEGER NOT NULL,
            ino             INTEGER NOT NULL,
            original_path   TEXT    NOT NULL DEFAULT '',
            quar_name       TEXT    NOT NULL DEFAULT '',
            virus_name      TEXT    NOT NULL DEFAULT '',
            uid             INTEGER NOT NULL DEFAULT 0,
            gid             INTEGER NOT NULL DEFAULT 0,
            mode            INTEGER NOT NULL DEFAULT 0,
            file_size       INTEGER NOT NULL DEFAULT 0,
            quarantined_at  TEXT    NOT NULL DEFAULT '',
            restored        INTEGER NOT NULL DEFAULT 0,
            restored_at     TEXT    NOT NULL DEFAULT '',
            UNIQUE(dev, ino)
        );"
    )?;
    Ok(())
}

/// 插入或更新隔离记录。
/// 如果 (dev, ino) 已存在（重新隔离同一文件），则重置为未还原状态。
/// 返回: true=新插入, false=更新了旧记录
pub fn insert(row: &QuarantineRow) -> Result<bool> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let affected = conn.execute(
        "INSERT INTO quarantine (
            dev, ino, original_path, quar_name, virus_name,
            uid, gid, mode, file_size, quarantined_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(dev, ino) DO UPDATE SET
            original_path = excluded.original_path,
            quar_name = excluded.quar_name,
            virus_name = excluded.virus_name,
            uid = excluded.uid,
            gid = excluded.gid,
            mode = excluded.mode,
            file_size = excluded.file_size,
            quarantined_at = excluded.quarantined_at,
            restored = 0,
            restored_at = ''",
        params![
            row.dev, row.ino, row.original_path, row.quar_name, row.virus_name,
            row.uid, row.gid, row.mode, row.file_size, row.quarantined_at,
        ],
    )?;
    Ok(affected > 0)
}

/// 按 (dev, ino) 查找一条隔离记录
pub fn find_by_dev_ino(dev: u64, ino: u64) -> Result<Option<QuarantineRow>> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let mut stmt = conn.prepare(
        "SELECT id, dev, ino, original_path, quar_name, virus_name,
                uid, gid, mode, file_size, quarantined_at, restored, restored_at
         FROM quarantine WHERE dev = ?1 AND ino = ?2"
    )?;
    let mut rows = stmt.query_map(params![dev, ino], map_row)?;
    match rows.next() {
        Some(row) => Ok(Some(row?)),
        None => Ok(None),
    }
}

/// 按原始路径查找隔离记录
pub fn find_by_original_path(original_path: &str) -> Result<Vec<QuarantineRow>> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let mut stmt = conn.prepare(
        "SELECT id, dev, ino, original_path, quar_name, virus_name,
                uid, gid, mode, file_size, quarantined_at, restored, restored_at
         FROM quarantine WHERE original_path = ?1"
    )?;
    let rows = stmt.query_map(params![original_path], map_row)?;
    rows.collect()
}

/// 按病毒名查找所有隔离记录
pub fn list_by_virus(virus_name: &str) -> Result<Vec<QuarantineRow>> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let mut stmt = conn.prepare(
        "SELECT id, dev, ino, original_path, quar_name, virus_name,
                uid, gid, mode, file_size, quarantined_at, restored, restored_at
         FROM quarantine WHERE virus_name = ?1 AND restored = 0"
    )?;
    let rows = stmt.query_map(params![virus_name], map_row)?;
    rows.collect()
}

/// 列出所有未还原的隔离文件
pub fn list_quarantined() -> Result<Vec<QuarantineRow>> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let mut stmt = conn.prepare(
        "SELECT id, dev, ino, original_path, quar_name, virus_name,
                uid, gid, mode, file_size, quarantined_at, restored, restored_at
         FROM quarantine WHERE restored = 0 ORDER BY quarantined_at DESC"
    )?;
    let rows = stmt.query_map([], map_row)?;
    rows.collect()
}

/// 列出所有隔离记录（含已还原）
pub fn list_all() -> Result<Vec<QuarantineRow>> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let mut stmt = conn.prepare(
        "SELECT id, dev, ino, original_path, quar_name, virus_name,
                uid, gid, mode, file_size, quarantined_at, restored, restored_at
         FROM quarantine ORDER BY quarantined_at DESC"
    )?;
    let rows = stmt.query_map([], map_row)?;
    rows.collect()
}

/// 标记一条隔离记录为已还原
pub fn mark_restored(id: i64) -> Result<bool> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let now = chrono::Utc::now().to_rfc3339();
    let affected = conn.execute(
        "UPDATE quarantine SET restored = 1, restored_at = ?1 WHERE id = ?2",
        params![now, id],
    )?;
    Ok(affected > 0)
}

/// 按 (dev, ino) 标记为已还原
pub fn mark_restored_by_dev_ino(dev: u64, ino: u64) -> Result<bool> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let now = chrono::Utc::now().to_rfc3339();
    let affected = conn.execute(
        "UPDATE quarantine SET restored = 1, restored_at = ?1 WHERE dev = ?2 AND ino = ?3",
        params![now, dev, ino],
    )?;
    Ok(affected > 0)
}

/// 删除一条隔离记录（硬删除，用于永久清除）
pub fn delete(id: i64) -> Result<bool> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let affected = conn.execute("DELETE FROM quarantine WHERE id = ?1", params![id])?;
    Ok(affected > 0)
}

/// 按 (dev, ino) 删除隔离记录
pub fn delete_by_dev_ino(dev: u64, ino: u64) -> Result<bool> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let affected = conn.execute(
        "DELETE FROM quarantine WHERE dev = ?1 AND ino = ?2",
        params![dev as i64, ino as i64],
    )?;
    Ok(affected > 0)
}

/// 统计隔离中的文件数
pub fn count_quarantined() -> Result<i32> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    conn.query_row("SELECT COUNT(*) FROM quarantine WHERE restored = 0", [], |r| r.get(0))
}

fn map_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<QuarantineRow> {
    Ok(QuarantineRow {
        id: r.get(0)?,
        dev: r.get::<_, i64>(1)? as u64,
        ino: r.get::<_, i64>(2)? as u64,
        original_path: r.get(3)?,
        quar_name: r.get(4)?,
        virus_name: r.get(5)?,
        uid: r.get::<_, i32>(6)? as u32,
        gid: r.get::<_, i32>(7)? as u32,
        mode: r.get::<_, i32>(8)? as u32,
        file_size: r.get::<_, i64>(9)? as u64,
        quarantined_at: r.get(10)?,
        restored: r.get::<_, i32>(11)? != 0,
        restored_at: r.get(12)?,
    })
}
