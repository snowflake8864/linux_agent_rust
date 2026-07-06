//! alert.db — alert_log 表
//!
//! 告警日志持久化，支持：
//!   - 插入新告警（insert）
//!   - 更新处置状态（update_handle_status）
//!   - 分页查询（query_page），支持多维度过滤

use rusqlite::{params, Result, ToSql};
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
    pub path:                String,  // 进程/文件路径, 或外设名
    pub pid:                 i32,     // 进程 ID
    pub detail:              String,  // 告警详情描述
    pub identifier:          String,  // 通用标识：进程=md5, 外设=peripheral_eid
    pub n_type:              u32,     // 原始事件类型码（9003-9008 等）
    pub handle_status:       i32,     // 0=未处理 1=已处理 2=忽略
    pub handle_status_label: String,  // 处置状态文字，如"未处理"（客户端直接展示）
    pub handle_user:         String,  // 执行处置的用户名，未处置时为空
    pub handled_at:          i64,     // 处置时间（Unix 时间戳秒），0=未处置
    pub created_at:          i64,     // 告警产生时间（Unix 时间戳秒）
}

/// 建表 + 兼容迁移（幂等）
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
            identifier          TEXT    NOT NULL DEFAULT '',
            n_type              INTEGER NOT NULL DEFAULT 0,
            handle_status       INTEGER NOT NULL DEFAULT 0,
            handle_status_label TEXT    NOT NULL DEFAULT '未处理',
            handle_user         TEXT    NOT NULL DEFAULT '',
            handled_at          TEXT    NOT NULL DEFAULT '',
            created_at          TEXT    NOT NULL DEFAULT ''
        );"
    )?;
    // 兼容旧库：新增列不存在则添加（忽略已有列报错）
    let _ = conn.execute_batch("ALTER TABLE alert_log ADD COLUMN identifier TEXT NOT NULL DEFAULT '';");
    let _ = conn.execute_batch("ALTER TABLE alert_log ADD COLUMN n_type INTEGER NOT NULL DEFAULT 0;");
    // 时间字段从 TEXT 迁移为 INTEGER (Unix 时间戳秒)
    let _ = conn.execute_batch("ALTER TABLE alert_log ADD COLUMN handled_at_ts INTEGER NOT NULL DEFAULT 0;");
    let _ = conn.execute_batch("ALTER TABLE alert_log ADD COLUMN created_at_ts INTEGER NOT NULL DEFAULT 0;");
    Ok(())
}

/// 插入一条新告警（返回自增 id）
/// max_rows: 0 = 不限制，>0 = 插入后自动清理超出该数量的旧记录
pub fn insert(row: &AlertLogRow, max_rows: u32) -> Result<i64> {
    let conn = open_conn(DB_PATH)?;
    conn.execute(
        "INSERT INTO alert_log (
            alert_type, level, process, path, pid, detail, identifier, n_type,
            handle_status, handle_status_label, handle_user,
            handled_at, handled_at_ts,
            created_at, created_at_ts
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            row.alert_type, row.level, row.process, row.path, row.pid, row.detail, row.identifier, row.n_type,
            row.handle_status, row.handle_status_label, row.handle_user,
            row.handled_at.to_string(), row.handled_at,
            row.created_at.to_string(), row.created_at,
        ],
    )?;
    let id = conn.last_insert_rowid();
    // 插入后检查是否需要清理旧数据
    cleanup_old_records(&conn, max_rows)?;
    Ok(id)
}

/// 清理超出限制的旧告警记录（保留最新的 max_rows 条，按 id 升序删除最早的）
/// max_rows: 0 = 不限制，不做任何操作
fn cleanup_old_records(conn: &rusqlite::Connection, max_rows: u32) -> Result<usize> {
    if max_rows == 0 {
        return Ok(0);
    }
    let total: i32 = conn.query_row("SELECT COUNT(*) FROM alert_log", [], |r| r.get(0))?;
    let total = total as u32;
    if total > max_rows {
        let to_delete = total - max_rows;
        let deleted = conn.execute(
            "DELETE FROM alert_log WHERE id IN (SELECT id FROM alert_log ORDER BY id ASC LIMIT ?1)",
            params![to_delete],
        )?;
        if deleted > 0 {
            log::info!("[alert_log] 清理旧告警: 删除 {} 条，保留 {} 条（上限 {}）", deleted, total - deleted as u32, max_rows);
        }
        Ok(deleted)
    } else {
        Ok(0)
    }
}

/// 更新指定告警的处置状态
pub fn update_handle_status(
    id: i64,
    handle_status: i32,
    handle_status_label: &str,
    handle_user: &str,
) -> Result<usize> {
    let conn = open_conn(DB_PATH)?;
    let now_ts = chrono::Local::now().timestamp();
    let now_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let affected = conn.execute(
        "UPDATE alert_log
            SET handle_status = ?1,
                handle_status_label = ?2,
                handle_user = ?3,
                handled_at = ?4,
                handled_at_ts = ?5
          WHERE id = ?6",
        params![handle_status, handle_status_label, handle_user, now_str, now_ts, id],
    )?;
    Ok(affected)
}

/// 批量更新指定告警的处置状态
/// 返回 (成功数, 失败数, 失败 ID 列表)
pub fn batch_update_handle_status(
    ids: &[i64],
    handle_status: i32,
    handle_status_label: &str,
    handle_user: &str,
) -> Result<(i32, i32, Vec<i64>)> {
    let conn = open_conn(DB_PATH)?;
    let now_ts = chrono::Local::now().timestamp();
    let now_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let mut success = 0i32;
    let mut fail = 0i32;
    let mut failed_ids = Vec::new();

    for &id in ids {
        match conn.execute(
            "UPDATE alert_log
                SET handle_status = ?1,
                    handle_status_label = ?2,
                    handle_user = ?3,
                    handled_at = ?4,
                    handled_at_ts = ?5
              WHERE id = ?6",
            params![handle_status, handle_status_label, handle_user, now_str, now_ts, id],
        ) {
            Ok(affected) if affected > 0 => success += 1,
            _ => {
                fail += 1;
                failed_ids.push(id);
            }
        }
    }

    Ok((success, fail, failed_ids))
}

/// 查询过滤条件
#[derive(Default)]
pub struct AlertQueryFilter<'a> {
    pub handle_status:       Option<i32>,
    pub alert_type:          Option<i32>,
    pub identifier:          Option<&'a str>,
    pub handle_status_label: Option<&'a str>,
    pub start_time:          Option<i64>,
    pub end_time:            Option<i64>,
}

/// 分页查询告警日志
/// 支持多维度组合过滤（identifier, handle_status_label, 时间范围 等）
pub fn query_page(
    filter: &AlertQueryFilter,
    page: u32,
    page_size: u32,
) -> Result<Vec<AlertLogRow>> {
    let conn = open_conn(DB_PATH)?;
    let offset = (page.saturating_sub(1)) * page_size;

    let columns = "id, alert_type, level, process, path, pid, detail, identifier, n_type,
                   handle_status, handle_status_label, handle_user,
                   handled_at_ts, created_at_ts";

    let mut where_clauses: Vec<&str> = Vec::new();
    let mut params: Vec<Box<dyn ToSql>> = Vec::new();

    if let Some(s) = filter.handle_status {
        where_clauses.push("handle_status = ?");
        params.push(Box::new(s));
    }
    if let Some(t) = filter.alert_type {
        where_clauses.push("alert_type = ?");
        params.push(Box::new(t));
    }
    if let Some(id) = filter.identifier {
        if !id.is_empty() {
            where_clauses.push("identifier = ?");
            params.push(Box::new(id.to_string()));
        }
    }
    if let Some(label) = filter.handle_status_label {
        if !label.is_empty() {
            where_clauses.push("handle_status_label = ?");
            params.push(Box::new(label.to_string()));
        }
    }
    if let Some(st) = filter.start_time {
        if st > 0 {
            where_clauses.push("created_at_ts >= ?");
            params.push(Box::new(st));
        }
    }
    if let Some(et) = filter.end_time {
        if et > 0 {
            where_clauses.push("created_at_ts <= ?");
            params.push(Box::new(et));
        }
    }

    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", where_clauses.join(" AND "))
    };

    let sql = format!(
        "SELECT {} FROM alert_log{} ORDER BY created_at_ts DESC LIMIT ? OFFSET ?",
        columns, where_sql
    );

    let mut stmt = conn.prepare(&sql)?;

    let collected: Result<Vec<_>> = stmt.query_map(
        rusqlite::params_from_iter(
            params.iter().map(|p| p.as_ref())
                .chain(std::iter::once(&page_size as &dyn ToSql))
                .chain(std::iter::once(&offset as &dyn ToSql))
        ),
        map_row,
    )?.collect();
    collected
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
        identifier:          r.get(7)?,
        n_type:              r.get(8)?,
        handle_status:       r.get(9)?,
        handle_status_label: r.get(10)?,
        handle_user:         r.get(11)?,
        handled_at:          r.get::<_, i64>(12)?,
        created_at:          r.get::<_, i64>(13)?,
    })
}

/// 统计符合条件的总条数（配合分页查询使用）
pub fn count(filter: &AlertQueryFilter) -> Result<i32> {
    let conn = open_conn(DB_PATH)?;

    let mut where_clauses: Vec<&str> = Vec::new();
    let mut params: Vec<Box<dyn ToSql>> = Vec::new();

    if let Some(s) = filter.handle_status {
        where_clauses.push("handle_status = ?");
        params.push(Box::new(s));
    }
    if let Some(t) = filter.alert_type {
        where_clauses.push("alert_type = ?");
        params.push(Box::new(t));
    }
    if let Some(id) = filter.identifier {
        if !id.is_empty() {
            where_clauses.push("identifier = ?");
            params.push(Box::new(id.to_string()));
        }
    }
    if let Some(label) = filter.handle_status_label {
        if !label.is_empty() {
            where_clauses.push("handle_status_label = ?");
            params.push(Box::new(label.to_string()));
        }
    }
    if let Some(st) = filter.start_time {
        if st > 0 {
            where_clauses.push("created_at_ts >= ?");
            params.push(Box::new(st));
        }
    }
    if let Some(et) = filter.end_time {
        if et > 0 {
            where_clauses.push("created_at_ts <= ?");
            params.push(Box::new(et));
        }
    }

    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", where_clauses.join(" AND "))
    };

    let sql = format!("SELECT COUNT(*) FROM alert_log{}", where_sql);

    let total: i32 = conn.query_row(
        &sql,
        rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())),
        |r| r.get(0),
    )?;

    Ok(total)
}
