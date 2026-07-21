
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
        // 通过 SecurityBackend，驱动写 /proc/osec，ebpf 写 BPF map
        let _ = common::backend::with_backend(|b| b.add_md5_rules(data));
    }

    fn notify_kernel_update() {
        let _ = common::backend::with_backend(|b| b.notify_process_update());
    }

    fn kill_process(process_path: &str) {
       log_info!("[process_policy] 命中黑名单进程，准备终止: {}", process_path);
    }


    pub fn set_policy_process(&mut self, process_list: &[String], is_white: bool) {
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
