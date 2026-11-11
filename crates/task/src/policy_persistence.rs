//! 服务器/gRPC 下发策略（防篡改目录 / 勒索后缀 / 信任目录）的 SQLite 持久化。
//!
//! 单一来源模型（方案 B）：
//!   - 服务器下发（在线）→ 只写在线基线表 `*`
//!   - 本地 gRPC（离线）  → 只写离线本地表 `*_local`
//!   - 程序运行/启动       → 统一从 DB 读取（本地表优先于在线表）后再下发内核
//!
//! 存储为单行 JSON 快照；typed <-> JSON 转换集中在此，local_store 只存字符串。
//! 每次保存返回 policy_meta.version，调用方据此去重，避免重复加载。

use logging::log_error;
use pattern::pattern_rules_mgr::{POLICY_EXIPOR_PROTECT, POLICY_PROTECT_DIR};
use pattern::GlobalTrustDir;

fn db_enabled() -> bool {
    local_store::sqlite_db_enabled()
}

// ── 保存 ──────────────────────────────────────────────

pub fn save_dir_policy(rules: &[POLICY_PROTECT_DIR], local: bool) -> Result<u64, String> {
    if !db_enabled() {
        return Ok(0);
    }
    let json = serde_json::to_string(rules).map_err(|e| e.to_string())?;
    let r = if local {
        local_store::dir_policy::save_all_local(&json)
    } else {
        local_store::dir_policy::save_all(&json)
    };
    r.map_err(|e| {
        log_error!("[policy_persist] 保存 dir_policy(local={}) 失败: {}", local, e);
        e.to_string()
    })
}

pub fn save_extort_policy(rules: &[POLICY_EXIPOR_PROTECT], local: bool) -> Result<u64, String> {
    if !db_enabled() {
        return Ok(0);
    }
    let json = serde_json::to_string(rules).map_err(|e| e.to_string())?;
    let r = if local {
        local_store::extort_policy::save_all_local(&json)
    } else {
        local_store::extort_policy::save_all(&json)
    };
    r.map_err(|e| {
        log_error!("[policy_persist] 保存 extort_policy(local={}) 失败: {}", local, e);
        e.to_string()
    })
}

pub fn save_trust_dir(dirs: &[GlobalTrustDir], local: bool) -> Result<u64, String> {
    if !db_enabled() {
        return Ok(0);
    }
    let json = serde_json::to_string(dirs).map_err(|e| e.to_string())?;
    let r = if local {
        local_store::trust_dir::save_all_local(&json)
    } else {
        local_store::trust_dir::save_all(&json)
    };
    r.map_err(|e| {
        log_error!("[policy_persist] 保存 trust_dir(local={}) 失败: {}", local, e);
        e.to_string()
    })
}

// ── 合并加载（本地表优先） ─────────────────────────────

/// 在线基线表优先；仅在基线表完全没有记录时回退旧版本的本地表（兼容升级）。
fn load_merged_json<E: std::fmt::Display>(
    online: Result<Option<String>, E>,
    local: Result<Option<String>, E>,
    domain: &str,
) -> Option<String> {
    match online {
        Ok(Some(json)) => return Some(json),
        Ok(None) => {}
        Err(e) => log_error!("[policy_persist] 读取 {domain} 失败: {}", e),
    }
    match local {
        Ok(v) => v,
        Err(e) => {
            log_error!("[policy_persist] 读取 {domain}_local 失败: {}", e);
            None
        }
    }
}

pub fn load_dir_policy_merged() -> Option<Vec<POLICY_PROTECT_DIR>> {
    if !db_enabled() {
        return None;
    }
    let json = load_merged_json(
        local_store::dir_policy::load_all(),
        local_store::dir_policy::load_all_local(),
        "dir_policy",
    )?;
    match serde_json::from_str::<Vec<POLICY_PROTECT_DIR>>(&json) {
        Ok(v) => Some(v),
        Err(e) => {
            log_error!("[policy_persist] 反序列化 dir_policy 失败: {}", e);
            None
        }
    }
}

pub fn load_extort_policy_merged() -> Option<Vec<POLICY_EXIPOR_PROTECT>> {
    if !db_enabled() {
        return None;
    }
    let json = load_merged_json(
        local_store::extort_policy::load_all(),
        local_store::extort_policy::load_all_local(),
        "extort_policy",
    )?;
    match serde_json::from_str::<Vec<POLICY_EXIPOR_PROTECT>>(&json) {
        Ok(v) => Some(v),
        Err(e) => {
            log_error!("[policy_persist] 反序列化 extort_policy 失败: {}", e);
            None
        }
    }
}

pub fn load_trust_dir_merged() -> Option<Vec<GlobalTrustDir>> {
    if !db_enabled() {
        return None;
    }
    let json = load_merged_json(
        local_store::trust_dir::load_all(),
        local_store::trust_dir::load_all_local(),
        "trust_dir",
    )?;
    match serde_json::from_str::<Vec<GlobalTrustDir>>(&json) {
        Ok(v) => Some(v),
        Err(e) => {
            log_error!("[policy_persist] 反序列化 trust_dir 失败: {}", e);
            None
        }
    }
}

// ── 清理 ──────────────────────────────────────────────

/// 上线时清空三类离线本地表（服务器策略接管）。
/// 返回值用于调用方判断是否需要重新加载（清空后本地表不再覆盖基线）。
pub fn clear_local_policies() {
    if !db_enabled() {
        return;
    }
    if let Err(e) = local_store::dir_policy::clear_local() {
        log_error!("[policy_persist] 清空 dir_policy_local 失败: {}", e);
    }
    if let Err(e) = local_store::extort_policy::clear_local() {
        log_error!("[policy_persist] 清空 extort_policy_local 失败: {}", e);
    }
    if let Err(e) = local_store::trust_dir::clear_local() {
        log_error!("[policy_persist] 清空 trust_dir_local 失败: {}", e);
    }
}
