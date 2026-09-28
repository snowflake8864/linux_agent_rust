
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
    pending_white: Option<HashSet<String>>,
    pending_black: Option<HashSet<String>>,
    pending_save_to_db: Option<bool>,
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
    /// 收到一侧名单先暂存，等白、黑两侧都到齐后统一 diff 下发（三态：白/黑/未知）。
    pub fn set_policy_process(&mut self, process_list: &[String], is_white: bool, save_to_db: Option<bool>) {
        if is_white {
            log_info!("[process_policy] 收到白名单: {} 条hash（待合并）", process_list.len());
            self.pending_white = Some(process_list.iter().cloned().collect());
        } else {
            log_info!("[process_policy] 收到黑名单: {} 条hash（待合并）", process_list.len());
            self.pending_black = Some(process_list.iter().cloned().collect());

            // 命中黑名单进程，终止
            for path in process_list {
                if self.run_process_mode {
                    Self::kill_process(path);
                }
            }
        }

        // 直接覆盖（含 None），避免上一次的 save_to_db 残留影响本轮
        self.pending_save_to_db = save_to_db;

        // 白、黑两侧都到齐，统一比较并下发
        if self.pending_white.is_some() && self.pending_black.is_some() {
            self.apply_pending_policy();
        }
    }

    /// 统一三态 diff：对比「当前生效名单(white_set/black_set)」与「待合并名单(pending)」，
    /// 一次性算出 白↔黑 互转、白/黑→未知、未知→白/黑 的增量，然后下发内核/bpf。
    fn apply_pending_policy(&mut self) {
        let new_white = self.pending_white.take().unwrap();
        let new_black = self.pending_black.take().unwrap();
        let save_to_db = self.pending_save_to_db.take();

        let mut batch: Vec<String> = Vec::new();
        let mut n_add_white = 0usize;           // 未知→白
        let mut n_add_black = 0usize;           // 未知→黑
        let mut n_del_white = 0usize;           // 白→未知（从内核/bpf 删除）
        let mut n_del_black = 0usize;           // 黑→未知（从内核/bpf 删除）
        let mut n_move_white_to_black = 0usize; // 白→黑
        let mut n_move_black_to_white = 0usize; // 黑→白

        // 黑→白：老黑 ∩ 新白
        for h in &new_white {
            if self.black_set.contains(h) {
                batch.push(format!("del 1 {}\n", h));
                batch.push(format!("{}=0\n", h));
                n_move_black_to_white += 1;
            }
        }

        // 白→黑：老白 ∩ 新黑
        for h in &new_black {
            if self.white_set.contains(h) {
                batch.push(format!("del 0 {}\n", h));
                batch.push(format!("{}=1\n", h));
                n_move_white_to_black += 1;
            }
        }

        // 未知→白：新白 - 老白 - 老黑
        for h in &new_white {
            if !self.white_set.contains(h) && !self.black_set.contains(h) {
                batch.push(format!("{}=0\n", h));
                n_add_white += 1;
            }
        }

        // 未知→黑：新黑 - 老黑 - 老白
        for h in &new_black {
            if !self.black_set.contains(h) && !self.white_set.contains(h) {
                batch.push(format!("{}=1\n", h));
                n_add_black += 1;
            }
        }

        // 白→未知：老白 - 新白 - 新黑
        for h in &self.white_set {
            if !new_white.contains(h) && !new_black.contains(h) {
                batch.push(format!("del 0 {}\n", h));
                n_del_white += 1;
            }
        }

        // 黑→未知：老黑 - 新黑 - 新白
        for h in &self.black_set {
            if !new_black.contains(h) && !new_white.contains(h) {
                batch.push(format!("del 1 {}\n", h));
                n_del_black += 1;
            }
        }

        // 更新当前生效名单
        self.white_set = new_white;
        self.black_set = new_black;

        if !batch.is_empty() {
            Self::add_md5_rules(&batch.concat());
        }
        Self::notify_kernel_update();

        log_info!("[process_policy] 已下发: 未知→白{} 未知→黑{} 白→未知{} 黑→未知{} 白→黑{} 黑→白{}",
            n_add_white, n_add_black, n_del_white, n_del_black, n_move_white_to_black, n_move_black_to_white);

        if let Some(local) = save_to_db {
            self.persist_policy(local);
        }
    }

    /// 将内存黑白名单全量持久化到 DB（如果开关已开启）
    /// local: true=离线本地表(process_policy_local), false=在线基线表(process_policy)
    fn persist_policy(&self, local: bool) {
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
        // 同步到 known_executables 表（白名单 → policy_status=1，黑名单 → policy_status=2）
        if let Err(e) = local_store::known_executables::update_policy_status(&white, true) {
            logging::log_error!("[known_executables] 同步白名单策略状态失败: {}", e);
        }
        if let Err(e) = local_store::known_executables::update_policy_status(&black, false) {
            logging::log_error!("[known_executables] 同步黑名单策略状态失败: {}", e);
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

    /// 启动即离线：合并加载在线基线表(process_policy，上次服务器策略) + 离线本地表(process_policy_local，gRPC 策略)。
    /// 先加载在线基线，再叠加本地表（同 hash 本地覆盖在线），保证：
    ///   - 上次在线时服务器下发的策略不丢失（本次离线延用）；
    ///   - 本地 gRPC 策略仍然生效。
    pub fn load_policy_from_db_merged(&mut self) {
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

        self.white_set.clear();
        self.black_set.clear();

        // 1. 在线基线表（上次服务器策略）
        let mut online_white = 0usize;
        let mut online_black = 0usize;
        match local_store::process_policy::load_all() {
            Ok(entries) => {
                for (hash, is_white) in entries {
                    if is_white {
                        self.white_set.insert(hash);
                        online_white += 1;
                    } else {
                        self.black_set.insert(hash);
                        online_black += 1;
                    }
                }
            }
            Err(e) => logging::log_error!("[process_policy] 加载在线基线表失败: {}", e),
        }

        // 2. 离线本地表（gRPC 策略），同 hash 覆盖在线
        match local_store::process_policy::load_all_local() {
            Ok(entries) => {
                for (hash, is_white) in entries {
                    self.white_set.remove(&hash);
                    self.black_set.remove(&hash);
                    if is_white {
                        self.white_set.insert(hash);
                    } else {
                        self.black_set.insert(hash);
                    }
                }
            }
            Err(e) => logging::log_error!("[process_policy] 加载离线本地表失败: {}", e),
        }

        log::info!(
            "[process_policy] 合并加载完成: 在线基线(白{} 黑{}) + 本地覆盖 => 最终 白{} 黑{}",
            online_white, online_black, self.white_set.len(), self.black_set.len()
        );
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

        // 启动时全量下发，white_set/black_set 本身即「已下发快照」，后续 set_policy_process 直接据此 diff。
        // 无论策略是否为空都通知内核：空策略表示「加载完成」，eBPF 侧据此开启进程检测，
        // 否则无黑白名单时检测会一直关闭。
        Self::notify_kernel_update();
        if !white.is_empty() || !black.is_empty() {
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
