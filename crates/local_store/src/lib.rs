pub mod alert_log;
pub mod jump_status;
pub mod known_executables;
pub mod peripheral_policy;
pub mod process_policy;
pub mod quarantine;

/// 便捷查询：SQLite 基础设施是否已开启
pub fn sqlite_db_enabled() -> bool {
    config::net_info::NETINFO_CONFIG
        .lock()
        .map(|c| c.sqlite_db.enabled)
        .unwrap_or(false)
}

/// 程序启动时调用一次，创建所有 DB 文件目录和各表。
/// 只初始化开关已开启的模块。幂等：表已存在时跳过，不会清空数据。
pub fn init_all() {
    if !sqlite_db_enabled() {
        log::info!("[local_store] SQLite 基础设施未启用 ([SQLITE_DB] ENABLED=0)，跳过所有 DB 初始化");
        return;
    }

    sqlite_db::db::ensure_db_dir();

    let db = &config::net_info::NETINFO_CONFIG.lock().unwrap().db_policy;

    if db.alert_log {
        if let Err(e) = alert_log::init_table() {
            logging::log_error!("[local_store] alert_log 建表失败: {}", e);
        }
    }
    if db.process_policy {
        if let Err(e) = process_policy::init_table() {
            logging::log_error!("[local_store] process_policy 建表失败: {}", e);
        }
        if let Err(e) = process_policy::init_local_table() {
            logging::log_error!("[local_store] process_policy_local 建表失败: {}", e);
        }
    }
    if db.known_executables {
        if let Err(e) = known_executables::init_table() {
            logging::log_error!("[local_store] known_executables 建表失败: {}", e);
        }
    }
    if db.jump_status {
        if let Err(e) = jump_status::init_table() {
            logging::log_error!("[local_store] jump_status 建表失败: {}", e);
        }
    }
    if db.peripheral_policy {
        if let Err(e) = peripheral_policy::init_table() {
            logging::log_error!("[local_store] peripheral_policy 建表失败: {}", e);
        }
        if let Err(e) = peripheral_policy::init_local_table() {
            logging::log_error!("[local_store] peripheral_policy_local 建表失败: {}", e);
        }
    }
    if db.quarantine {
        if let Err(e) = quarantine::init_table() {
            logging::log_error!("[local_store] quarantine 建表失败: {}", e);
        }
    }
}
