pub mod db;
pub mod jump_status;
pub mod alert_log;
pub mod process_policy;
pub mod known_executables;

/// 程序启动时调用一次，创建所有 DB 文件目录和各表。
/// 幂等：表已存在时跳过，不会清空数据。
pub fn init_all() {
    db::ensure_db_dir();

    if let Err(e) = jump_status::init_table() {
        logging::log_error!("[local_store] jump_status 建表失败: {}", e);
    }
    if let Err(e) = alert_log::init_table() {
        logging::log_error!("[local_store] alert_log 建表失败: {}", e);
    }
    if let Err(e) = process_policy::init_table() {
        logging::log_error!("[local_store] process_policy 建表失败: {}", e);
    }
    if let Err(e) = known_executables::init_table() {
        logging::log_error!("[local_store] known_executables 建表失败: {}", e);
    }
}
