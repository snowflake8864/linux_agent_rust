//! md5_inode_cache.db — md5_inode_cache 表
//!
//! 持久化「非扫描目录」可执行文件的 hash → path 映射。
//!
//! 这些映射在运行期由不明进程命中白/黑名单时即时解析（ebpf_backend::try_resolve_pending_rule）
//! 得到。重启后 md5_map 只从 /bin /usr/bin /usr/sbin /usr/local/bin /usr/lib/systemd 等
//! 标准目录扫描重建，若不持久化，/opt 等路径的白名单进程会再次被拦截一次、再走一遍即时补写。
//!
//! hash 为主键；path 是解析时的绝对路径。启动加载时重新 stat(path) 得到当前 (dev,inode)，
//! 并重新校验文件 MD5 仍等于 hash，避免文件被升级替换后误放行。

use rusqlite::{params, Result};

const DB_PATH: &str = "/opt/osec/db/md5_inode_cache.db";

/// 建表（幂等，已存在时跳过）
pub fn init_table() -> Result<()> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS md5_inode_cache (
            hash      TEXT PRIMARY KEY,
            path      TEXT NOT NULL DEFAULT '',
            last_seen TEXT NOT NULL DEFAULT ''
        );",
    )?;
    Ok(())
}

/// 全量加载，返回 (hash, path) 列表
pub fn load_all() -> Result<Vec<(String, String)>> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let mut stmt = conn.prepare("SELECT hash, path FROM md5_inode_cache")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
        ))
    })?;
    rows.collect()
}

/// 插入或更新（hash 去重）
pub fn upsert(hash: &str, path: &str) -> Result<()> {
    let conn = sqlite_db::db::open_conn(DB_PATH)?;
    let now = chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    conn.execute(
        "INSERT INTO md5_inode_cache (hash, path, last_seen)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(hash) DO UPDATE SET
             path = excluded.path,
             last_seen = excluded.last_seen",
        params![hash, path, now],
    )?;
    Ok(())
}

/// 若 [SQLITE_DB] 与 [DB_POLICY] MD5_INODE_CACHE 均已开启则持久化，否则 no-op。
/// 独立开关：该映射是 eBPF 后端的 md5→inode 解析缓存，与 PROCESS_POLICY 无关。
pub fn persist_if_enabled(hash: &str, path: &str) {
    if !crate::sqlite_db_enabled() {
        return;
    }
    let db_ok = config::net_info::NETINFO_CONFIG
        .lock()
        .map(|c| c.db_policy.md5_inode_cache)
        .unwrap_or(false);
    if !db_ok {
        return;
    }
    if let Err(e) = upsert(hash, path) {
        logging::log_error!("[md5_inode_cache] 持久化 hash→path 失败: {}", e);
    }
}

/// 若开关开启则加载全部记录，否则返回空列表（内部处理加载失败并记日志）。
pub fn load_if_enabled() -> Vec<(String, String)> {
    if !crate::sqlite_db_enabled() {
        return Vec::new();
    }
    let db_ok = config::net_info::NETINFO_CONFIG
        .lock()
        .map(|c| c.db_policy.md5_inode_cache)
        .unwrap_or(false);
    if !db_ok {
        return Vec::new();
    }
    load_all().unwrap_or_else(|e| {
        logging::log_error!("[md5_inode_cache] 加载 hash→path 失败: {}", e);
        Vec::new()
    })
}
