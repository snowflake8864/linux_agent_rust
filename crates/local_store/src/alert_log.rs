//! alert.db — alert_log 表
//!
//! 告警日志持久化，支持：
//!   - 插入新告警（insert）
//!   - 更新处置状态（update_handle_status）
//!   - 分页查询（query_page）

use rusqlite::{params, Result};
use serde::{Deserialize, Serialize};
use crate::db::open_conn;

const DB_PATH: &str = "/opt/osec/db/alert.db";

/// 处置状态枚举值（与 handle_status 字段对应）
pub const HANDLE_STATUS_PENDING:  i32 = 0;
pub const HANDLE_STATUS_HANDLED:  i32 = 1;
pub const HANDLE_STATUS_IGNORED:  i32 = 2;

/// alert_log 行结构
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AlertLogRow {
    pub id:                  i64,     // 自增主键，insert 时传 0
    pub alert_type:          i32,     // 告警类型编号
    pub level:               i32,     // 告警级别：1=低 2=中 3=高
    pub process:             String,  // 触发告警的进程名
    pub path:                String,  // 进程或文件完整路径
    pub pid:                 i32,     // 进程 ID
    pub detail:              String,  // 告警详情描述
    pub handle_status:       i32,     // 0=未处理 1=已处理 2=忽略
    pub handle_status_label: String,  // 处置状态文字，如"未处理"（客户端直接展示）
    pub handle_user:         String,  // 执行处置的用户名，未处置时为空
    pub handled_at:          String,  // 处置时间，未处置时为空
    pub created_at:          String,  // 告警产生时间
}

/// 建表（幂等）
pub fn init_table() -> Result<()> {
    let conn = open_conn(DB_PATH)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS alert_log (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type          INTEGER NOT NULL DEFAULT 0,
            level               INTEGER NOT NULL DEFAULT 0,
            process             TEXT    NOT NULL DEFAULT '',
            path                TEXT    NOT NULL DEFAULT '',
            pid                 INTEGER NOT NULL DEFAULT 0,
            detail              TEXT    NOT NULL DEFAULT '',
            handle_status       INTEGER NOT NULL DEFAULT 0,
            handle_status_label TEXT    NOT NULL DEFAULT '未处理',
            handle_user         TEXT    NOT NULL DEFAULT '',
            handled_at          TEXT    NOT NULL DEFAULT '',
            created_at          TEXT    NOT NULL DEFAULT ''
        );"
    )?;
    Ok(())
}

/// 插入一条新告警（返回自增 id）
pub fn insert(row: &AlertLogRow) -> Result<i64> {
    let conn = open_conn(DB_PATH)?;
    conn.execute(
        "INSERT INTO alert_log (
            alert_type, level, process, path, pid, detail,
            handle_status, handle_status_label, handle_user, handled_at, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            row.alert_type, row.level, row.process, row.path, row.pid, row.detail,
            row.handle_status, row.handle_status_label, row.handle_user,
            row.handled_at, row.created_at,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// 更新指定告警的处置状态
/// - handle_status：新的处置状态（HANDLE_STATUS_* 常量）
/// - handle_status_label：对应的文字描述，如"已处理"
/// - handle_user：执行处置的用户名
pub fn update_handle_status(
    id: i64,
    handle_status: i32,
    handle_status_label: &str,
    handle_user: &str,
) -> Result<usize> {
    let conn = open_conn(DB_PATH)?;
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let affected = conn.execute(
        "UPDATE alert_log
            SET handle_status = ?1,
                handle_status_label = ?2,
                handle_user = ?3,
                handled_at = ?4
          WHERE id = ?5",
        params![handle_status, handle_status_label, handle_user, now, id],
    )?;
    Ok(affected)
}

/// 分页查询告警日志
/// - handle_status：None 表示全部，Some(0/1/2) 按处置状态筛选
/// - page：从 1 开始
/// - page_size：每页条数
pub fn query_page(
    handle_status: Option<i32>,
    page: u32,
    page_size: u32,
) -> Result<Vec<AlertLogRow>> {
    let conn = open_conn(DB_PATH)?;
    let offset = (page.saturating_sub(1)) * page_size;

    let rows = if let Some(status) = handle_status {
        let mut stmt = conn.prepare(
            "SELECT id, alert_type, level, process, path, pid, detail,
                    handle_status, handle_status_label, handle_user, handled_at, created_at
               FROM alert_log
              WHERE handle_status = ?1
              ORDER BY created_at DESC
              LIMIT ?2 OFFSET ?3"
        )?;
        let collected: Result<Vec<_>> = stmt.query_map(params![status, page_size, offset], map_row)?.collect();
        collected?
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, alert_type, level, process, path, pid, detail,
                    handle_status, handle_status_label, handle_user, handled_at, created_at
               FROM alert_log
              ORDER BY created_at DESC
              LIMIT ?1 OFFSET ?2"
        )?;
        let collected: Result<Vec<_>> = stmt.query_map(params![page_size, offset], map_row)?.collect();
        collected?
    };

    Ok(rows)
}

fn map_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AlertLogRow> {
    Ok(AlertLogRow {
        id:                  r.get(0)?,
        alert_type:          r.get(1)?,
        level:               r.get(2)?,
        process:             r.get(3)?,
        path:                r.get(4)?,
        pid:                 r.get(5)?,
        detail:              r.get(6)?,
        handle_status:       r.get(7)?,
        handle_status_label: r.get(8)?,
        handle_user:         r.get(9)?,
        handled_at:          r.get(10)?,
        created_at:          r.get(11)?,
    })
}

/// 统计符合条件的总条数（配合分页查询使用）
pub fn count(handle_status: Option<i32>) -> Result<i32> {
    let conn = open_conn(DB_PATH)?;
    let total: i32 = if let Some(status) = handle_status {
        conn.query_row(
            "SELECT COUNT(*) FROM alert_log WHERE handle_status = ?1",
            rusqlite::params![status],
            |r| r.get(0),
        )?
    } else {
        conn.query_row(
            "SELECT COUNT(*) FROM alert_log",
            [],
            |r| r.get(0),
        )?
    };
    Ok(total)
}
