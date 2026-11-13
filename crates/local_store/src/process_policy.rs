//! process_policy.db — process_policy 表
//!
//! 进程黑白名单 hash 持久化，支持：
//!   - process_policy       在线基线（服务器下发）
//!   - process_policy_local 离线本地（gRPC 下发）
//!
//! hash 为主键，is_white=1 表示白名单，0 表示黑名单。
//! 保存时与表内现有内容做 diff，只增删变化行；内容无变化时不递增 policy_meta.version，
//! 读侧据此跳过重复加载。

use std::collections::HashMap;

use logging::log_info;
use rusqlite::{params, Result, TransactionBehavior};

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
    // 读-比较-写必须在同一事务内完成，避免与服务器任务/gRPC 的并发写入互相覆盖。
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;

    let mut desired: HashMap<String, bool> = HashMap::with_capacity(white.len() + black.len());
    for h in white {
        desired.insert(h.clone(), true);
    }
    for h in black {
        desired.insert(h.clone(), false);
    }

    let mut existing: HashMap<String, bool> = HashMap::new();
    {
        let mut stmt = tx.prepare(&format!("SELECT hash, is_white FROM {table}"))?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)? != 0))
        })?;
        for row in rows {
            let (hash, is_white) = row?;
            existing.insert(hash, is_white);
        }
    }

    // 内容完全一致：不写库、不递增版本，返回当前版本供调用方判断是否变更。
    if existing == desired {
        let version = crate::policy_meta::current_version(&tx, table)?;
        tx.commit()?;
        log_info!("[process_policy] {table} 内容未变化，跳过写入");
        return Ok(version);
    }

    // 删除：老记录中被移除或黑白身份发生变化的行。
    let mut deleted = 0usize;
    {
        let mut stmt = tx.prepare(&format!("DELETE FROM {table} WHERE hash = ?1"))?;
        for (hash, old_white) in &existing {
            if desired.get(hash) != Some(old_white) {
                stmt.execute(params![hash])?;
                deleted += 1;
            }
        }
    }

    // 插入：新增或黑白身份发生变化的行。
    let mut inserted = 0usize;
    {
        let mut stmt =
            tx.prepare(&format!("INSERT INTO {table} (hash, is_white) VALUES (?1, ?2)"))?;
        for (hash, new_white) in &desired {
            if existing.get(hash) != Some(new_white) {
                stmt.execute(params![hash, if *new_white { 1 } else { 0 }])?;
                inserted += 1;
            }
        }
    }

    let version = crate::policy_meta::bump_version(&tx, table)?;
    tx.commit()?;
    log_info!("[process_policy] {table} 增量写入: +{inserted} -{deleted}");
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
