
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
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
        match OpenOptions::new().read(true).write(true).open(MD5_RULE_FILE) {
            Ok(mut file) => {
                let _ = file.write_all(data.as_bytes());
            }
            Err(e) => {
                //log_error!("open {} failed: {}", MD5_RULE_FILE, e);
            }
        }
    }

    fn notify_kernel_update() {
        match OpenOptions::new().read(true).write(true).open(PROCESS_RULE_FILE) {
            Ok(mut file) => {
                let _data = "update\n";
                let _ = file.write_all(_data.as_bytes());
            }
            Err(e) => {
                log_error!("open {} failed: {}", PROCESS_RULE_FILE, e);
            }
        }

    }

    fn kill_process(process_path: &str) {
       log_info!("Killing blacklisted process: {}", process_path);
    }


    /// action: 0=移除(未知), 1=白名单, 2=黑名单
    /// save_to_db: None=不存DB, Some(false)=存在线表, Some(true)=存本地表
    pub fn set_policy_process(&mut self, process_list: &[String], action: i32, save_to_db: Option<bool>) {
        let mut is_changed = false;

        match action {
            0 => {
                for path in process_list {
                    if self.white_set.remove(path) {
                        let rule = format!("del 0 {}\n", path);
                        Self::add_md5_rules(&rule);
                        self.prev_white_set.remove(path);
                        is_changed = true;
                    }
                    if self.black_set.remove(path) {
                        let rule = format!("del 1 {}\n", path);
                        Self::add_md5_rules(&rule);
                        self.prev_black_set.remove(path);
                        is_changed = true;
                    }
                }
                if is_changed { Self::notify_kernel_update(); }
            }
            1 => {
                for path in process_list {
                    if self.black_set.remove(path) {
                        Self::add_md5_rules(&format!("del 1 {}\n", path));
                        self.prev_black_set.remove(path);
                        is_changed = true;
                    }
                    if !self.white_set.contains(path) {
                        Self::add_md5_rules(&format!("{}=0\n", path));
                        self.white_set.insert(path.clone());
                        self.prev_white_set.insert(path.clone());
                        is_changed = true;
                    }
                }
                if is_changed { Self::notify_kernel_update(); }
            }
            2 => {
                for path in process_list {
                    if self.run_process_mode { Self::kill_process(path); }
                    if self.white_set.remove(path) {
                        Self::add_md5_rules(&format!("del 0 {}\n", path));
                        self.prev_white_set.remove(path);
                        is_changed = true;
                    }
                    if !self.black_set.contains(path) {
                        Self::add_md5_rules(&format!("{}=1\n", path));
                        self.black_set.insert(path.clone());
                        self.prev_black_set.insert(path.clone());
                        is_changed = true;
                    }
                }
                if is_changed { Self::notify_kernel_update(); }
            }
            _ => { log_error!("[process_policy] 无效 action: {}", action); return; }
        }

        let white: Vec<String> = self.white_set.iter().cloned().collect();
        let black: Vec<String> = self.black_set.iter().cloned().collect();
        match save_to_db {
            Some(true) => {
                if let Err(e) = local_store::process_policy::save_all_local(&white, &black) {
                    log_error!("[process_policy] 持久化到本地表失败: {}", e);
                }
            }
            Some(false) => {
                if let Err(e) = local_store::process_policy::save_all(&white, &black) {
                    log_error!("[process_policy] 持久化失败: {}", e);
                }
            }
            None => { /* DB_POLICY 未启用，不写 DB */ }
        }
        // if let Err(e) = local_store::known_executables::update_policy_status(&white, true) {
        //     log_error!("[known_executables] 同步白名单失败: {}", e);
        // }
        // if let Err(e) = local_store::known_executables::update_policy_status(&black, false) {
        //     log_error!("[known_executables] 同步黑名单失败: {}", e);
        // }
    }

    /// 从 SQLite 加载黑白名单到内存（启动时调用，不写 kernel）
    /// local: true=从离线本地表加载, false=从在线基线表加载
    pub fn load_policy_from_db(&mut self, local: bool) {
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
                self.prev_white_set = self.white_set.clone();
                self.prev_black_set = self.black_set.clone();
                log_info!(
                    "[process_policy] 从 DB({}) 加载: {} 白名单, {} 黑名单",
                    if local { "local" } else { "online" },
                    self.white_set.len(),
                    self.black_set.len()
                );
            }
            Err(e) => log_error!("[process_policy] 从 DB 加载失败: {}", e),
        }
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
