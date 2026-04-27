use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use logging::{log_info,log_error};
use std::fs::OpenOptions;
use std::io::{Write, Error, ErrorKind};
use serde::Deserialize;
use serde_json::Value;
use crate::GlobalTrustDir;


// 枚举类型
#[derive(Debug, Clone, Copy)]
enum PatternAction {
    PassReturn,
    BlockReturn,
    ContinueRun,
    SelfProtection,
    TrustDirAction,
}

#[derive(Debug, Clone, Copy)]
enum PatternType {
    SelfProtectionType,
    LesouProtectionType,
    TamperProtectionType,
}



#[derive(Clone, Debug, Deserialize)]
pub struct POLICY_EXIPOR_PROTECT {
    pub file_type: String,
    pub typ: u8,
    pub map_comm: HashMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct POLICY_PROTECT_DIR {
    pub id: u32,
    pub dir: String,
    pub protect_rw: u8,
    #[serde(rename = "type")]
    pub typ: u8,
    pub is_extend: u8,
    pub include_file: String,
    #[serde(rename = "protect_file")]
    pub file_ext: String,
    pub is_white: String,
    pub white_hash: String,
}

// 主管理器结构体
#[derive(Debug, Default, Clone)]
pub struct PatternRulesMgr {
    const_file_patterns: String,
    const_file_rules: String,
    global_trust_dir_patterns: String,
    global_trust_dir_rules: String,
    exiport_dir_patterns: String,
    exiport_dir_rules: String,
    protect_dir_patterns: String,
    protect_dir_rules: String,
    protect_dir_white_patterns: String,
    protect_dir_white_rules: String,
    protect_dir_include_exe_patterns: String,
    protect_dir_include_exe_rules: String,
    protect_dir_exclude_exe_patterns: String,
    protect_dir_exclude_exe_rules: String,
    exiport_true_process: String,
    protect_true_process: String,

    pre_global_trust_dir_patterns: String,
    pre_exiport_dir_patterns: String,
    pre_const_file_patterns: String,
    pre_protect_dir_patterns: String,
    pre_protect_dir_white_patterns: String,
    pre_protect_dir_include_exe_patterns: String,
    pre_protect_dir_exclude_exe_patterns: String,
    pre_exiport_true_process: String,
    pre_protect_true_process: String,
    default_global_trust_dirs: Vec<GlobalTrustDir>,
    load_pattern_rules_flag: bool,
    inited: bool,
}

impl PatternRulesMgr {
    pub fn new() -> Self {

        let default_global_trust_dirs = vec![
            GlobalTrustDir { dir: "/opt/osec/log".to_string(), typ: 0, is_extend: 0 },
        ];
        PatternRulesMgr {
            const_file_patterns: String::new(),
            const_file_rules: String::new(),
            global_trust_dir_patterns: String::new(),
            global_trust_dir_rules: String::new(),
            exiport_dir_patterns: String::new(),
            exiport_dir_rules: String::new(),
            protect_dir_patterns: String::new(),
            protect_dir_rules: String::new(),
            protect_dir_white_patterns: String::new(),
            protect_dir_white_rules: String::new(),
            protect_dir_include_exe_patterns: String::new(),
            protect_dir_include_exe_rules: String::new(),
            protect_dir_exclude_exe_patterns: String::new(),
            protect_dir_exclude_exe_rules: String::new(),
            exiport_true_process: String::new(),
            protect_true_process: String::new(),

            pre_global_trust_dir_patterns: String::new(),
            pre_exiport_dir_patterns: String::new(),
            pre_const_file_patterns: String::new(),
            pre_protect_dir_patterns: String::new(),
            pre_protect_dir_white_patterns: String::new(),
            pre_protect_dir_include_exe_patterns: String::new(),
            pre_protect_dir_exclude_exe_patterns: String::new(),
            pre_exiport_true_process: String::new(),
            pre_protect_true_process: String::new(),
            default_global_trust_dirs,

            load_pattern_rules_flag: false,
            inited: false,
        }
    }
    pub fn parse_exipor_policy_from_json(data: &Value) -> Result<Vec<POLICY_EXIPOR_PROTECT>, String> {
        let array = data.as_array().ok_or("data is not an array")?;
        let mut result = Vec::new();

        for item in array {
            let typ = item.get("type").and_then(Value::as_u64).unwrap_or(0) as u8;
            let file_type = item
                .get("file_suffix")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let mut map_comm = HashMap::new();
            if let Some(process_info_array) = item.get("process").and_then(Value::as_array) {
                for process in process_info_array {
                    if let (Some(name), Some(hash)) = (
                        process.get("name").and_then(Value::as_str),
                        process.get("hash").and_then(Value::as_str),
                    ) {
                        map_comm.insert(hash.to_string(), name.to_string());
                        log_info!("=======================================hash:{},name:{}", hash, name);
                    }
                }
            }

            result.push(POLICY_EXIPOR_PROTECT {
                file_type,
                typ,
                map_comm,
            });
        }

        Ok(result)
    }
    pub fn parse_policy_from_json(data: &Value) -> Result<Vec<POLICY_PROTECT_DIR>, String> {
        let array = data.as_array().ok_or("data is not an array")?;
        let mut result = Vec::new();

        for item in array {
            let id = item["id"].as_u64().unwrap_or(0) as u32;
            let dir = item["dir"].as_str().unwrap_or("").to_string();
            let protect_rw = item["protect_rw"].as_u64().unwrap_or(0) as u8;
            let typ = item["type"].as_u64().unwrap_or(0) as u8;
            let is_extend = item["is_extend"].as_u64().unwrap_or(0) as u8;
            let include_file = item["include_file"].as_str().unwrap_or("").to_string();
            let file_ext = item["protect_file"].as_str().unwrap_or("").to_string();
            let is_white = item["protect_folder"].as_str().unwrap_or("").to_string();

            let mut white_hash_vec = vec![];

            if let Some(process_array) = item["process"].as_array() {

                for p in process_array {
                    if let Some(hash) = p["hash"].as_str() {
                        white_hash_vec.push(hash.to_string());
                    }
                }
            }

            let white_hash = white_hash_vec.join(",");

            result.push(POLICY_PROTECT_DIR {
                id,
                dir,
                protect_rw,
                typ,
                is_extend,
                include_file,
                file_ext,
                is_white,
                white_hash,
            });
        }

        Ok(result)
    }

    // 初始化
    pub fn init(&mut self) {
        if self.inited {
            log_info!("Already initialized.");
            return;
        }

        self.load_pattern_rules_flag = false;
        self.inited = true;

        log_info!("==================================PatternRulesMgr initialized.");
    }

    // 检查文件是否存在
    pub fn check_files_exist() -> bool {
        const FILES_TO_CHECK: &[&str] = &[
            "/proc/osec/docker_rt",
            "/proc/osec/dpi/file_patterns",
            "/proc/osec/dpi/rules",
            "/proc/osec/dpi/true_process_rt",
            "/proc/osec/forward/forward_device",
            "/proc/osec/forward/forward_gateway",
            "/proc/osec/forward/session_cache_max",
            "/proc/osec/forward/session_cache_tbl",
            "/proc/osec/forward/session_cache_timeo",
            "/proc/osec/md5_rt",
            "/proc/osec/osec_conn/block_saddr_rt",
            "/proc/osec/osec_conn/block_saddr_rt_v6",
            "/proc/osec/osec_conn/ipv6_block_cache_max",
            "/proc/osec/osec_conn/ipv6_block_cache_tbl",
            "/proc/osec/process_rt",
            "/proc/osec/self",
        ];

        for path in FILES_TO_CHECK {
            if !Path::new(*path).exists() {
                log_error!("File {} does not exist.", path);
                return false;
            }
        }
        true
    }


    /// 只在文件存在时写入内容，否则返回错误
    fn write_to_proc_file(path: &str, content: &str) -> std::io::Result<()> {
        // 检查文件是否存在
        if !std::path::Path::new(path).exists() {
            let err = Error::new(ErrorKind::NotFound, format!("File {} does not exist", path));
            log_error!("{}", err);
            return Err(err);
        }

        // 打开文件（只写）
        let mut file = OpenOptions::new()
            .write(true)
            .open(path)?;

        file.write_all(content.as_bytes())?;
        log_info!("Successfully wrote to {}", path);
        Ok(())
    }

    // 清除文件模式
    pub fn clear_file_pattern(&self) -> std::io::Result<()> {
        let mut file = File::create("/proc/osec/dpi/file_patterns")?;
        file.write_all(b"c\n")?;
        Ok(())
    }

    // 清除 DPI 规则
    pub fn clear_dpi_rules(&self) -> std::io::Result<()> {
        let mut file = File::create("/proc/osec/dpi/rules")?;
        file.write_all(b"c\n")?;
        Ok(())
    }

    // 清除进程白名单
    pub fn clear_true_process(&self) {
        if let Err(e) = File::create("/proc/osec/dpi/true_process_rt").and_then(|mut f| f.write_all(b"c\n")) {
            log_error!("Failed to clear true process: {}", e);
        }
    }

    // 构建文件模式
    pub fn build_file_pattern(&self) {
        if let Err(e) = File::create("/proc/osec/dpi/file_patterns").and_then(|mut f| f.write_all(b"b\n")) {
            log_error!("Build file pattern failed: {}", e);
        }
    }

    pub fn add_file_pattern(&mut self, enable: bool) {
        if !enable {
            return;
        }
        self.const_file_patterns.clear();
        self.const_file_rules.clear();

        self.const_file_patterns.push_str("name=self_1,key=/var/lib/dpkg/info/osec.\n");
        self.const_file_rules.push_str("target=self,pattern=self_1,type=3\n");

        self.const_file_patterns.push_str("name=self_2,key=/opt/osec,pkt_len=-1,case_offset=1\n");
        self.const_file_rules.push_str("target=self,pattern=self_2,type=3\n");

        self.const_file_patterns.push_str("name=self_3,key=/opt/osec/,case_offset=1\n");
        self.const_file_rules.push_str("target=self,pattern=self_3,type=3\n");
        self.const_file_patterns.push_str("name=self_4,key=/etc/systemd/system/multi-user.target.wants/osec.\n");
        self.const_file_rules.push_str("target=self,pattern=self_4,type=3\n");
        self.const_file_patterns.push_str("name=self_5,key=/etc/systemd/system/multi-user.target.wants/agent_manager.\n");
        self.const_file_rules.push_str("target=self,pattern=self_5,type=3\n");
        self.set_pattern_rules();
    }

    // 设置全局信任目录
    pub fn set_global_trust_dir(&mut self, dirs: Vec<GlobalTrustDir>) {
        self.global_trust_dir_patterns.clear();
        self.global_trust_dir_rules.clear();

        for (i, dir) in dirs.iter().enumerate().take(50) {
            let name = format!("trueDir_{}", i);
            self.global_trust_dir_patterns.push_str(&format!("name={},key={}", name, dir.dir));

            if dir.is_extend == 0 {
                self.global_trust_dir_patterns.push_str(",isnot_extend=1");
            }

            if dir.typ == 1 {
                let depth = dir.dir.len();
                self.global_trust_dir_patterns.push_str(&format!(",depth={}", depth));
            } else {
                self.global_trust_dir_patterns.push_str(",pkt_len=-1");
            }

            self.global_trust_dir_patterns.push_str(",case_offset=1\n");

            self.global_trust_dir_rules.push_str(&format!(
                    "target=TDir_rule,type=0,pattern={}\n",
                    name
            ));
        }

        self.set_pattern_rules();
    }


    // 设置导出目录保护

    pub fn set_exiport_dir(&mut self, exports: Vec<POLICY_EXIPOR_PROTECT>) {
        self.exiport_dir_patterns.clear();
        self.exiport_dir_rules.clear();
        self.exiport_true_process.clear();

        let mut trusted_process_rule_number = 0;

        for (i, export) in exports.iter().enumerate().take(50) {
            let name = format!("exiportInfo_{}", i);

            self.exiport_dir_patterns.push_str(&format!("name={}", name));
            self.exiport_dir_rules.push_str(&format!("target={},pattern={}", name, name));

            if export.typ == 1 {
                // 后缀匹配
                self.exiport_dir_patterns.push_str(",key=.");
                self.exiport_dir_patterns.push_str(&export.file_type);

                let offset = -(export.file_type.len() as isize + 1);
                self.exiport_dir_patterns
                    .push_str(&format!(",offset={}", offset));

                self.exiport_dir_rules.push_str(",action=3"); // include file suffix
            } else {
                // 普通前缀匹配
                self.exiport_dir_patterns.push_str(",case_offset=1");
                self.exiport_dir_patterns.push_str(",key=");
                self.exiport_dir_patterns.push_str(&export.file_type);

                self.exiport_dir_patterns
                    .push_str(&format!(",depth={}", export.file_type.len()));
            }

            if !export.map_comm.is_empty() {
                trusted_process_rule_number += 1;
                let rule_id = trusted_process_rule_number.to_string();
                for (k, _) in &export.map_comm {
                    self.exiport_true_process
                        .push_str(&format!("{},{},99\n", k, rule_id));
                    }
                log_info!("=====================================================true process [{:?}]", self.exiport_true_process);
                self.exiport_dir_rules.push_str(&format!(",TPNC={}", rule_id));
            }

            self.exiport_dir_rules.push_str(",type=1\n");
            self.exiport_dir_patterns.push_str("\n");
        }

        if exports.len() > 50 {
            log::info!("exiport global dir is too big and break, size: {}", exports.len());
        }

        self.set_pattern_rules();
    }
    pub fn clear_exiport_dir(&mut self) {
        self.exiport_dir_patterns.clear();
        self.exiport_dir_rules.clear();
        self.set_pattern_rules();
    } 

    pub fn set_protect_dir(&mut self, dirs: Vec<POLICY_PROTECT_DIR>) {
        let mut trusted_process_rule_number = 0;

        self.protect_dir_patterns.clear();
        self.protect_dir_white_patterns.clear();
        self.protect_dir_rules.clear();
        self.protect_dir_white_rules.clear();
        self.protect_dir_include_exe_patterns.clear();
        self.protect_dir_include_exe_rules.clear();
        self.protect_dir_exclude_exe_patterns.clear();
        self.protect_dir_exclude_exe_rules.clear();
        self.protect_true_process.clear();

        for (i, dir) in dirs.iter().enumerate().take(50) {
            let i_str = i.to_string();
            let mut has_white_hash = false;

            // white_hash (可信进程)
            if !dir.white_hash.is_empty() {
                trusted_process_rule_number += 1;
                let index_str = trusted_process_rule_number.to_string();
                for hash in dir.white_hash.split(',') {
                    self.protect_true_process.push_str(&format!("{},{},88\n", hash, index_str));
                }
                has_white_hash = true;
            }

            // 目录白名单规则
            if !dir.is_white.is_empty() {
                for (j, white_path) in dir.is_white.split('|').enumerate() {
                    let j_str = format!("_{}", j);
                    self.protect_dir_white_patterns.push_str(&format!(
                            "name=protectExcludeDir_{}{},key={}\n",
                            i_str, j_str, white_path
                    ));
                    self.protect_dir_white_rules.push_str(&format!(
                            "target=protectExcludeDir,pattern=protectExcludeDir_{}{},type=2,action=1,rule_idx={},level=1\n",
                            i_str, j_str, i_str
                    ));
                }
            }

            // 目录规则 pattern
            self.protect_dir_patterns.push_str(&format!(
                    "name=ProtectDir_{},type=2,key={}",
                    i_str, dir.dir
            ));

            if dir.typ == 1 {
                if dir.is_extend == 0 {
                    self.protect_dir_patterns.push_str(",isnot_extend=1");
                }
                let depth = dir.dir.len();
                self.protect_dir_patterns.push_str(&format!(",depth={},case_offset=1", depth));
            } else {
                self.protect_dir_patterns.push_str(",case_offset=1,pkt_len=-1");
            }
            self.protect_dir_patterns.push('\n');

            // include_file 后缀
            if !dir.include_file.is_empty() {
                for (j, suffix) in dir.include_file.split('|').enumerate() {
                    let j_str = format!("_{}", j);
                    self.protect_dir_include_exe_patterns.push_str(&format!(
                            "name=protectIncFileExe_{}{},key=.{},offset=-{}\n",
                            i_str, j_str, suffix, suffix.len() + 1
                    ));

                    self.protect_dir_include_exe_rules.push_str(&format!(
                            "target=protectIncFileExe_{},pattern=ProtectDir_{}>protectIncFileExe_{}{},rule_idx={},action=3,protect_rw={}",
                            i_str, i_str, i_str, j_str, i_str, dir.protect_rw
                    ));

                    if has_white_hash {
                        self.protect_dir_include_exe_rules
                            .push_str(&format!(",TPNC={}", trusted_process_rule_number));
                    }

                    self.protect_dir_include_exe_rules.push_str(",type=2\n");
                }
                log_info!(
                    "self.protect_dir_include_exe_patterns: {}",
                    self.protect_dir_include_exe_patterns
                );
                log_info!(
                    "self.protect_dir_include_exe_rules: {}",
                    self.protect_dir_include_exe_rules
                );
            }
            // file_ext 排除规则
            else if !dir.file_ext.is_empty() {
                self.protect_dir_rules.push_str(&format!(
                        "target=ProtectDir_{},pattern=ProtectDir_{},rule_idx={},protect_rw={}",
                        i_str, i_str, i_str, dir.protect_rw
                ));
                if has_white_hash {
                    self.protect_dir_rules
                        .push_str(&format!(",TPNC={}", trusted_process_rule_number));
                }
                self.protect_dir_rules.push_str(",type=2\n");

                for (j, suffix) in dir.file_ext.split('|').enumerate() {
                    let j_str = format!("_{}", j);
                    self.protect_dir_exclude_exe_patterns.push_str(&format!(
                            "name=protectExcFileExe_{}{},key=.{},offset=-{}\n",
                            i_str, j_str, suffix, suffix.len() + 1
                    ));
                    self.protect_dir_exclude_exe_rules.push_str(&format!(
                            "target=protectExcFileExe_{}{},pattern=ProtectDir_{}>protectExcFileExe_{}{},rule_idx={},action=2,type=2\n",
                            i_str, j_str, i_str, i_str, j_str, i_str
                    ));
                }
            } else {
                self.protect_dir_rules.push_str(&format!(
                        "target=ProtectDir_{},pattern=ProtectDir_{},rule_idx={},protect_rw={}",
                        i_str, i_str, i_str, dir.protect_rw
                ));
                if has_white_hash {
                    self.protect_dir_rules
                        .push_str(&format!(",TPNC={}", trusted_process_rule_number));
                }
                self.protect_dir_rules.push_str(",type=2\n");
            }
        }

        log_info!("protect_dir_patterns:{}", self.protect_dir_patterns);
        log_info!("protect_dir_include_exe_patterns:{}", self.protect_dir_include_exe_patterns);
        log_info!("protect_dir_rules:{}", self.protect_dir_rules);
        log_info!("protect_dir_include_exe_rules:{}", self.protect_dir_include_exe_rules);
        log_info!("protect_dir_exclude_exe_rules:{}", self.protect_dir_exclude_exe_rules);
        log_info!("protect_dir_white_rules:{}", self.protect_dir_white_rules);
        log_info!("protect_true_process:{}", self.protect_true_process);

        self.set_pattern_rules();
    }


    pub fn clear_protect_dir(&mut self) {

        self.protect_dir_patterns.clear();
        self.protect_dir_white_patterns.clear();
        self.protect_dir_rules.clear();
        self.protect_dir_white_rules.clear();
        self.protect_dir_include_exe_patterns.clear();
        self.protect_dir_include_exe_rules.clear();
        self.protect_dir_exclude_exe_patterns.clear();
        self.protect_dir_exclude_exe_rules.clear();
        self.protect_true_process.clear();

        self.set_pattern_rules();
    }

    // 加载规则到内核
    pub fn load_pattern_rules(&self) {
        if !self.const_file_patterns.is_empty() {
            let _ = Self::write_to_proc_file("/proc/osec/dpi/file_patterns", &self.const_file_patterns);
            let _ = Self::write_to_proc_file("/proc/osec/dpi/rules", &self.const_file_rules);
        }
        if !self.global_trust_dir_patterns.is_empty() {
            let _ = Self::write_to_proc_file("/proc/osec/dpi/file_patterns", &self.global_trust_dir_patterns);
            let _ = Self::write_to_proc_file("/proc/osec/dpi/rules", &self.global_trust_dir_rules);
        }
        if !self.exiport_dir_patterns.is_empty() {
            let _ = Self::write_to_proc_file("/proc/osec/dpi/file_patterns", &self.exiport_dir_patterns);
            let _ = Self::write_to_proc_file("/proc/osec/dpi/rules", &self.exiport_dir_rules);
        }
        if !self.protect_dir_patterns.is_empty() {
            let _ = Self::write_to_proc_file("/proc/osec/dpi/file_patterns", &self.protect_dir_patterns);
        }
        if !self.protect_dir_rules.is_empty() {
            let _ = Self::write_to_proc_file("/proc/osec/dpi/rules", &self.protect_dir_rules);
        }
        if !self.protect_dir_white_patterns.is_empty() {
            let _ = Self::write_to_proc_file("/proc/osec/dpi/file_patterns", &self.protect_dir_white_patterns);
            let _ = Self::write_to_proc_file("/proc/osec/dpi/rules", &self.protect_dir_white_rules);
        }
        if !self.protect_dir_include_exe_patterns.is_empty() {
            log_info!("===protect_dir_include_exe_patterns:{}", self.protect_dir_include_exe_patterns);
            let _ = Self::write_to_proc_file("/proc/osec/dpi/file_patterns", &self.protect_dir_include_exe_patterns);
            let _ = Self::write_to_proc_file("/proc/osec/dpi/rules", &self.protect_dir_include_exe_rules);
        }
        if !self.protect_dir_exclude_exe_patterns.is_empty() {
            let _ = Self::write_to_proc_file("/proc/osec/dpi/file_patterns", &self.protect_dir_exclude_exe_patterns);
            let _ = Self::write_to_proc_file("/proc/osec/dpi/rules", &self.protect_dir_exclude_exe_rules);
        }
        if !self.protect_true_process.is_empty() {
            log_info!("00=====================================================true process [{:?}]", self.protect_true_process);
            let _ = Self::write_to_proc_file("/proc/osec/dpi/true_process_rt", &self.protect_true_process);
        }
        if !self.exiport_true_process.is_empty() {

            log_info!("=====================================================true process [{:?}]", self.exiport_true_process);
            let _ = Self::write_to_proc_file("/proc/osec/dpi/true_process_rt", &self.exiport_true_process);
        }

        self.build_file_pattern();
    }

    // 判断是否变更
    fn patterns_has_changed(&self) -> bool {
        self.pre_global_trust_dir_patterns != self.global_trust_dir_patterns ||
            self.pre_exiport_dir_patterns != self.exiport_dir_patterns ||
            self.pre_const_file_patterns != self.const_file_patterns ||
            self.pre_protect_dir_patterns != self.protect_dir_patterns ||
            self.pre_protect_dir_white_patterns != self.protect_dir_white_patterns ||
            self.pre_protect_dir_include_exe_patterns != self.protect_dir_include_exe_patterns ||
            self.pre_protect_dir_exclude_exe_patterns != self.protect_dir_exclude_exe_patterns ||
            self.pre_exiport_true_process != self.exiport_true_process ||
            self.pre_protect_true_process != self.protect_true_process
    }

    // 备份当前状态
    fn patterns_backup(&mut self) {
        self.pre_global_trust_dir_patterns = self.global_trust_dir_patterns.clone();
        self.pre_exiport_dir_patterns = self.exiport_dir_patterns.clone();
        self.pre_const_file_patterns = self.const_file_patterns.clone();
        self.pre_protect_dir_patterns = self.protect_dir_patterns.clone();
        self.pre_protect_dir_white_patterns = self.protect_dir_white_patterns.clone();
        self.pre_protect_dir_include_exe_patterns = self.protect_dir_include_exe_patterns.clone();
        self.pre_protect_dir_exclude_exe_patterns = self.protect_dir_exclude_exe_patterns.clone();
        self.pre_exiport_true_process = self.exiport_true_process.clone();
        self.pre_protect_true_process = self.protect_true_process.clone();
    }

    // 设置规则
    pub fn set_pattern_rules(&mut self) {
        if self.patterns_has_changed() {
            let _ = self.clear_file_pattern();
            let _ = self.clear_dpi_rules();
            self.clear_true_process();
            self.load_pattern_rules();
            self.patterns_backup();
        }
    }
}
