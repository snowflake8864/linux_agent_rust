
use std::collections::HashSet;
use once_cell::sync::Lazy;
use std::sync::Mutex;
use logging::{log_info,log_error};

const PROCESS_RULE_FILE: &str = "/proc/osec/process_rt";
const MD5_RULE_FILE: &str = "/proc/osec/md5_rt";

#[derive(Default)]
pub struct ProcessPolicyManager {
    white_set: HashSet<String>,
    black_set: HashSet<String>,
    prev_white_set: HashSet<String>,
    prev_black_set: HashSet<String>,
    run_process_mode: bool,
}

impl ProcessPolicyManager {
    pub fn new(run_process_mode: bool) -> Self {
        Self {
            run_process_mode,
            ..Default::default()
        }
    }

    fn add_md5_rules(data: &str) {
        //log_info!("[process_policy] >>> add_md5_rules raw='{}'", data.trim_end());
        match common::backend::with_backend(|b| b.add_md5_rules(data)) {
            Ok(()) => {/*log_info!("[process_policy] ✅ add_md5_rules: 已写入内核")*/},
            Err(e) => log_error!("[process_policy] ❌ add_md5_rules 失败: {}", e),
        }
    }

    fn notify_kernel_update() {
        log_info!("[process_policy] >>> notify_kernel_update");
        match common::backend::with_backend(|b| b.notify_process_update()) {
            Ok(()) => log_info!("[process_policy] ✅ notify_kernel_update: 已通知内核"),
            Err(e) => log_error!("[process_policy] ❌ notify_kernel_update 失败: {}", e),
        }
    }

    fn kill_process(process_path: &str) {
       log_info!("[process_policy] 命中黑名单进程，准备终止: {}", process_path);
    }


    /// save_to_db: Some(true)=离线本地表, Some(false)=在线基线表, None=不写DB
    pub fn set_policy_process(&mut self, process_list: &[String], is_white: bool, save_to_db: Option<bool>) {
        let mut is_changed = false;

        if is_white {
            log_info!("[process_policy] 应用白名单: {} 条hash", process_list.len());
            self.white_set.clear();
            self.white_set.extend(process_list.iter().cloned());

            // 👇 清理原来的黑名单中的路径
            for path in &self.white_set {
                if self.prev_black_set.contains(path) {
                    let rule = format!("del 1 {}\n", path);
                    Self::add_md5_rules(&rule);
                    self.prev_black_set.remove(path); // 同时更新 prev_black_set
                    is_changed = true;
                }
            }

            for path in &self.white_set {
                if !self.prev_white_set.contains(path) {
                    let rule = format!("{}=0\n", path);
                    Self::add_md5_rules(&rule);
                    is_changed = true;
                }
            }

            for path in &self.prev_white_set {
                if !self.white_set.contains(path) {
                    let rule = format!("del 0 {}\n", path);
                    Self::add_md5_rules(&rule);
                    is_changed = true;
                }
            }

            if is_changed {
                self.prev_white_set = self.white_set.clone();
                Self::notify_kernel_update();
                log_info!("[process_policy] 白名单已下发内核 ({} 条)", self.white_set.len());
            }
        } else {
            log_info!("[process_policy] 应用黑名单: {} 条hash", process_list.len());
            self.black_set.clear();
            self.black_set.extend(process_list.iter().cloned());

            //  杀掉进程
            for path in process_list {
                if self.run_process_mode {
                    Self::kill_process(path);
                }
            }

            //  清理原来的白名单中的路径
            for path in &self.black_set {
                if self.prev_white_set.contains(path) {
                    let rule = format!("del 0 {}\n", path);
                    Self::add_md5_rules(&rule);
                    self.prev_white_set.remove(path); // 同时更新 prev_white_set
                    is_changed = true;
                }
            }

            for path in &self.black_set {
                if !self.prev_black_set.contains(path) {
                    let rule = format!("{}=1\n", path);
                    Self::add_md5_rules(&rule);
                    is_changed = true;
                }
            }

            for path in &self.prev_black_set {
                if !self.black_set.contains(path) {
                    let rule = format!("del 1 {}\n", path);
                    Self::add_md5_rules(&rule);
                    is_changed = true;
                }
            }

            if is_changed {
                self.prev_black_set = self.black_set.clone();
                Self::notify_kernel_update();
                log_info!("[process_policy] 黑名单已下发内核 ({} 条)", self.black_set.len());
            }
        }

        // 持久化黑白名单到 SQLite（受 [SQLITE_DB] 和 [DB_POLICY] 开关控制）
        // save_to_db: Some(true)=离线本地表, Some(false)=在线基线表, None=不写
        if let Some(local) = save_to_db {
            self.try_save_policy_to_db(is_white, local);
        }
    }

    /// 尝试将进程名单持久化到 DB（如果开关已开启）
    /// local: true=离线本地表(process_policy_local), false=在线基线表(process_policy)
    fn try_save_policy_to_db(&self, is_white: bool, local: bool) {
        if !local_store::sqlite_db_enabled() {
            return;
        }
        let db_ok = config::net_info::NETINFO_CONFIG
            .lock()
            .map(|c| c.db_policy.process_policy)
            .unwrap_or(false);
        if !db_ok {
            return;
        }
        let white: Vec<String> = self.white_set.iter().cloned().collect();
        let black: Vec<String> = self.black_set.iter().cloned().collect();
        let result = if local {
            local_store::process_policy::save_all_local(&white, &black)
        } else {
            local_store::process_policy::save_all(&white, &black)
        };
        if let Err(e) = result {
            logging::log_error!("[process_policy] 持久化到{}(local={}) 失败: {}",
                if local { "离线本地表" } else { "在线基线表" }, local, e);
        }
        // 同步到 known_executables 表
        let target = if is_white { &white } else { &black };
        if let Err(e) = local_store::known_executables::update_policy_status(target, is_white) {
            logging::log_error!("[known_executables] 同步策略状态失败: {}", e);
        }
    }

    /// 从 SQLite 加载黑白名单到内存（启动时调用，不写 kernel）
    /// local: true=从离线本地表加载, false=从在线基线表加载
    pub fn load_policy_from_db_if_enabled(&mut self, local: bool) {
        if !local_store::sqlite_db_enabled() {
            return;
        }
        let db_ok = config::net_info::NETINFO_CONFIG
            .lock()
            .map(|c| c.db_policy.process_policy)
            .unwrap_or(false);
        if !db_ok {
            return;
        }
        let result = if local {
            local_store::process_policy::load_all_local()
        } else {
            local_store::process_policy::load_all()
        };
        match result {
            Ok(entries) => {
                self.white_set.clear();
                self.black_set.clear();
                for (hash, is_white) in entries {
                    if is_white {
                        self.white_set.insert(hash);
                    } else {
                        self.black_set.insert(hash);
                    }
                }
                log::info!("[process_policy] 从 SQLite({}) 加载: 白名单 {} 条, 黑名单 {} 条",
                    if local { "local" } else { "online" },
                    self.white_set.len(), self.black_set.len());
            }
            Err(e) => {
                logging::log_error!("[process_policy] 从 DB 加载失败: {}", e);
            }
        }
    }

    /// 将内存中已加载（DB 恢复）的黑白名单全量下发到内核。
    /// 离线启动时服务器不会下发进程策略，后端初始化完成后必须主动推给 eBPF/驱动，
    /// 否则 gRPC 能读到内存里的策略，但内核 proc_rules 没有对应规则、不会触发拦截。
    pub fn apply_loaded_policy_to_kernel(&mut self) {
        // 只在 DB 开关开启时才下发（[SQLITE_DB] ENABLED + [DB_POLICY] PROCESS_POLICY）
        if !local_store::sqlite_db_enabled() {
            return;
        }
        let db_ok = config::net_info::NETINFO_CONFIG
            .lock()
            .map(|c| c.db_policy.process_policy)
            .unwrap_or(false);
        if !db_ok {
            return;
        }
        let white: Vec<String> = self.white_set.iter().cloned().collect();
        let black: Vec<String> = self.black_set.iter().cloned().collect();

        if !white.is_empty() {
            let data: String = white.iter().map(|h| format!("{}=0\n", h)).collect();
            Self::add_md5_rules(&data);
        }
        if !black.is_empty() {
            let data: String = black.iter().map(|h| format!("{}=1\n", h)).collect();
            Self::add_md5_rules(&data);
        }

        // 同步 prev 集合，避免后续 set_policy_process 的 diff 把这些 hash 误判为“新增”重复下发
        self.prev_white_set = self.white_set.clone();
        self.prev_black_set = self.black_set.clone();

        if !white.is_empty() || !black.is_empty() {
            Self::notify_kernel_update();
            log_info!("[process_policy] 启动下发 DB 策略到内核: 白名单 {} 条, 黑名单 {} 条",
                white.len(), black.len());
        }
    }

    /// 上线时清空离线本地表，使旧 gRPC 策略作废（服务器策略接管）。
    pub fn clear_local_policy(&self) {
        if !local_store::sqlite_db_enabled() {
            return;
        }
        let db_ok = config::net_info::NETINFO_CONFIG
            .lock()
            .map(|c| c.db_policy.process_policy)
            .unwrap_or(false);
        if !db_ok {
            return;
        }
        match local_store::process_policy::save_all_local(&[], &[]) {
            Ok(()) => log_info!("[process_policy] 已清空离线本地表（上线，服务器策略接管）"),
            Err(e) => log_error!("[process_policy] 清空离线本地表失败: {}", e),
        }
    }

    /// 首次切离线时，从离线本地表加载 gRPC 策略并下发内核。
    /// 本地表为空时保留当前（服务器）策略，避免误清空。
    pub fn load_local_policy_and_apply(&mut self) {
        if !local_store::sqlite_db_enabled() {
            return;
        }
        let db_ok = config::net_info::NETINFO_CONFIG
            .lock()
            .map(|c| c.db_policy.process_policy)
            .unwrap_or(false);
        if !db_ok {
            return;
        }
        let entries = match local_store::process_policy::load_all_local() {
            Ok(e) => e,
            Err(e) => {
                log_error!("[process_policy] 加载离线本地表失败: {}", e);
                return;
            }
        };
        if entries.is_empty() {
            log_info!("[process_policy] 离线本地表为空，保留当前服务器策略");
            return;
        }
        let mut white = Vec::new();
        let mut black = Vec::new();
        for (hash, is_white) in entries {
            if is_white { white.push(hash) } else { black.push(hash) }
        }
        self.set_policy_process(&white, true, None);
        self.set_policy_process(&black, false, None);
        log_info!("[process_policy] 离线加载本地策略并下发内核: 白 {} 条, 黑 {} 条", white.len(), black.len());
    }

    pub fn get_white_list(&self) -> Vec<String> {
        self.white_set.iter().cloned().collect()
    }

    pub fn get_black_list(&self) -> Vec<String> {
        self.black_set.iter().cloned().collect()
    }
}
pub static POLICY_MANAGER: Lazy<Mutex<ProcessPolicyManager>> = Lazy::new(|| {
    Mutex::new(ProcessPolicyManager::new(true))
});
