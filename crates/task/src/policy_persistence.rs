//! 服务器下发策略（防篡改目录 / 勒索后缀 / 信任目录）的 SQLite 持久化。
//!
//! 生命周期（与 process_policy 双表模式一致）：
//!   - 服务器下发（在线）→ 写在线基线表 `*`
//!   - 本地 gRPC（离线）→ 写离线本地表 `*_local`
//!   - 离线重启        → 从对应表恢复到 pattern_mgr 并下发内核
//!   - 重新上线        → 清空 `*_local`（服务器策略接管）
//!
//! 存储为单行 JSON 快照；typed <-> JSON 转换集中在此，local_store 只存字符串。

use logging::{log_error, log_info};
use pattern::pattern_rules_mgr::{POLICY_EXIPOR_PROTECT, POLICY_PROTECT_DIR};
use pattern::GlobalTrustDir;

fn db_enabled() -> bool {
    local_store::sqlite_db_enabled()
}

// ── 保存 ──────────────────────────────────────────────

pub fn save_dir_policy(rules: &[POLICY_PROTECT_DIR], local: bool) {
    if !db_enabled() {
        return;
    }
    match serde_json::to_string(rules) {
        Ok(json) => {
            let r = if local {
                local_store::dir_policy::save_all_local(&json)
            } else {
                local_store::dir_policy::save_all(&json)
            };
            if let Err(e) = r {
                log_error!("[policy_persist] 保存 dir_policy(local={}) 失败: {}", local, e);
            }
        }
        Err(e) => log_error!("[policy_persist] 序列化 dir_policy 失败: {}", e),
    }
}

pub fn save_extort_policy(rules: &[POLICY_EXIPOR_PROTECT], local: bool) {
    if !db_enabled() {
        return;
    }
    match serde_json::to_string(rules) {
        Ok(json) => {
            let r = if local {
                local_store::extort_policy::save_all_local(&json)
            } else {
                local_store::extort_policy::save_all(&json)
            };
            if let Err(e) = r {
                log_error!("[policy_persist] 保存 extort_policy(local={}) 失败: {}", local, e);
            }
        }
        Err(e) => log_error!("[policy_persist] 序列化 extort_policy 失败: {}", e),
    }
}

pub fn save_trust_dir(dirs: &[GlobalTrustDir], local: bool) {
    if !db_enabled() {
        return;
    }
    match serde_json::to_string(dirs) {
        Ok(json) => {
            let r = if local {
                local_store::trust_dir::save_all_local(&json)
            } else {
                local_store::trust_dir::save_all(&json)
            };
            if let Err(e) = r {
                log_error!("[policy_persist] 保存 trust_dir(local={}) 失败: {}", local, e);
            }
        }
        Err(e) => log_error!("[policy_persist] 序列化 trust_dir 失败: {}", e),
    }
}

// ── 恢复 ──────────────────────────────────────────────

/// 从 DB 恢复三类策略到 pattern_mgr（并下发内核）。
/// local=true 读 `*_local`，false 读在线基线表 `*`。表为空时保持内存现状。
pub fn restore_policies_from_db(local: bool) {
    if !db_enabled() {
        return;
    }
    let mgr = match crate::task_fetcher::GLOBAL_PATTERN_MGR.get() {
        Some(m) => m.clone(),
        None => {
            log_error!("[policy_persist] GLOBAL_PATTERN_MGR 未初始化，跳过策略恢复");
            return;
        }
    };
    let mut pm = match mgr.lock() {
        Ok(g) => g,
        Err(e) => {
            log_error!("[policy_persist] 锁 pattern_mgr 失败: {}", e);
            return;
        }
    };

    // 防篡改目录
    let dir_json = if local {
        local_store::dir_policy::load_all_local()
    } else {
        local_store::dir_policy::load_all()
    };
    match dir_json {
        Ok(Some(json)) => match serde_json::from_str::<Vec<POLICY_PROTECT_DIR>>(&json) {
            Ok(rules) => {
                let n = rules.len();
                pm.set_protect_dir(rules);
                log_info!("[policy_persist] 恢复防篡改目录 {} 条 (local={})", n, local);
            }
            Err(e) => log_error!("[policy_persist] 反序列化 dir_policy 失败: {}", e),
        },
        Ok(None) => {}
        Err(e) => log_error!("[policy_persist] 读取 dir_policy 失败: {}", e),
    }

    // 勒索后缀
    let extort_json = if local {
        local_store::extort_policy::load_all_local()
    } else {
        local_store::extort_policy::load_all()
    };
    match extort_json {
        Ok(Some(json)) => match serde_json::from_str::<Vec<POLICY_EXIPOR_PROTECT>>(&json) {
            Ok(rules) => {
                let n = rules.len();
                pm.set_exiport_dir(rules);
                log_info!("[policy_persist] 恢复勒索后缀 {} 条 (local={})", n, local);
            }
            Err(e) => log_error!("[policy_persist] 反序列化 extort_policy 失败: {}", e),
        },
        Ok(None) => {}
        Err(e) => log_error!("[policy_persist] 读取 extort_policy 失败: {}", e),
    }

    // 信任目录
    let trust_json = if local {
        local_store::trust_dir::load_all_local()
    } else {
        local_store::trust_dir::load_all()
    };
    match trust_json {
        Ok(Some(json)) => match serde_json::from_str::<Vec<GlobalTrustDir>>(&json) {
            Ok(dirs) => {
                let n = dirs.len();
                pm.set_global_trust_dir(dirs);
                log_info!("[policy_persist] 恢复信任目录 {} 条 (local={})", n, local);
            }
            Err(e) => log_error!("[policy_persist] 反序列化 trust_dir 失败: {}", e),
        },
        Ok(None) => {}
        Err(e) => log_error!("[policy_persist] 读取 trust_dir 失败: {}", e),
    }
}

// ── 清理 ──────────────────────────────────────────────

/// 上线时清空三类离线本地表（服务器策略接管）。
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
