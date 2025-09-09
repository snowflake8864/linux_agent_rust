
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


    pub fn set_policy_process(&mut self, process_list: &[String], is_white: bool) {
        let mut is_changed = false;

        if is_white {
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
            }
        } else {
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
            }
        }
    }
}
pub static POLICY_MANAGER: Lazy<Mutex<ProcessPolicyManager>> = Lazy::new(|| {
    Mutex::new(ProcessPolicyManager::new(true))
});
