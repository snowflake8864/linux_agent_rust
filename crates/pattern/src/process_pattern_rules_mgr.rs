
use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Write};
use std::path::Path;
use log::{info, error};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use crate::GlobalTrustDir;

// 定义常量文件路径
const FILE_PATTERNS_PROC_FILE: &str = "/proc/osec/process_dpi/file_patterns";
const DPI_RULE_PROC_FILE: &str = "/proc/osec/process_dpi/rules";

// 定义进程模式结构体
#[derive(Debug, Clone)]
struct ProcessPattern {
    key: &'static str,    // 进程路径或名称
    typ: u8,              // 类型：0 表示普通进程，1 表示系统进程
    param: &'static str,  // 额外参数，如 match_full_path=1 或 pkt_len=-1
}

// 预定义的进程模式
const PROCESS_PATTERNS: &[ProcessPattern] = &[
    ProcessPattern { key: "bin/sudo", typ: 0, param: "" },
    ProcessPattern { key: "/lib/command-not-found", typ: 0, param: ",pkt_len=-1" },
    ProcessPattern { key: "systemd-cgroups-agent", typ: 0, param: ",pkt_len=-1" },
    ProcessPattern { key: "/opt/vigilixav/sbin/vigilixd", typ: 0, param: ",match_full_path=1" },
    ProcessPattern { key: "/opt/osec/MagicArmor_0", typ: 0, param: ",match_full_path=1" },
    ProcessPattern { key: "/bin/dbus-daemon", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "/sbin/init", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "/sbin/NetworkManager", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "/sbin/lightdm", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "/sbin/alsactl", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "/lib/systemd/systemd-journald", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "/lib/systemd/systemd-udevd", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "/lib/systemd/systemd-timesyncd", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "/lib/systemd/systemd-logind", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "/usr/lib/accountsservice/accounts-daemon", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "/usr/lib/xorg/Xorg", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "/usr/lib/policykit-1/polkitd", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "/lib/systemd/systemd", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "/usr/sbin/rsyslogd", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "/bin/login", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "bin/du", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "bin/dash", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "/bin/run-parts", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "/sbin/dhclient-script", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "bin/sort", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "bin/sudo", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "bin/apt-get", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "bin/dpkg-preconfigure", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "bin/dpkg-split", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "bin/apt-extracttemplates", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "bin/stty", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "bin/lsmod", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "bin/rmmod", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "bin/tc", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "bin/unzip", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "bin/reboot", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "/usr/bin/systemctl", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "/usr/sbin/service", typ: 1, param: ",match_full_path=1" },
    ProcessPattern { key: "/shutdown", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "/halt", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "/poweroff", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "/systemd", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "lsof", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "awk", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "bin/tc", typ: 1, param: ",pkt_len=-1" },
    ProcessPattern { key: "/opt/osec/MagicArmorAgent", typ: 0, param: ",match_full_path=1" },
    ProcessPattern { key: "/usr/bin/bash", typ: 0, param: ",match_full_path=1" },
    ProcessPattern { key: "/opt/EndpointSecurityApp/scripts/SecurityScan_linux.sh", typ: 0, param: ",match_full_path=1" },
    ProcessPattern { key: "/opt/EndpointSecurityApp/EndpointSecurityApp", typ: 0, param: ",match_full_path=1" },
    ProcessPattern { key: "/opt/terminal_agent/terminal_agent_qt5", typ: 0, param: ",match_full_path=1" },
    ProcessPattern { key: "/usr/bin/docker", typ: 0, param: ",match_full_path=1" },
    ProcessPattern { key: "/bin/docker", typ: 0, param: ",match_full_path=1" },
    ProcessPattern { key: "/usr/lib/cni/bridge", typ: 0, param: ",match_full_path=1" },
    ProcessPattern { key: "/usr/lib/cni/portmap", typ: 0, param: ",match_full_path=1" },
    ProcessPattern { key: "/usr/lib/cni/firewall", typ: 0, param: ",match_full_path=1" },
    ProcessPattern { key: "/usr/lib/cni/tuning", typ: 0, param: ",match_full_path=1" },
    ProcessPattern { key: "/usr/bin/podman", typ: 0, param: ",match_full_path=1" },
];

// 主管理器结构体
#[derive(Debug)]
pub struct ProcessPatternRulesMgr {
    const_file_patterns: String,           // 常量进程模式
    const_file_rules: String,             // 常量进程规则
    global_trust_dir_patterns: String,    // 全局信任目录模式
    global_trust_dir_rules: String,       // 全局信任目录规则
    pre_global_trust_dir_patterns: String,// 备份全局信任目录模式
    pre_const_file_patterns: String,      // 备份常量进程模式
    inited: bool,                         // 初始化标志
}

pub static PROCESS_PATTERN_RULES_MGR: Lazy<Mutex<ProcessPatternRulesMgr>> = Lazy::new(|| {
    info!("初始化全局 ProcessPatternRulesMgr 单例");
    Mutex::new(ProcessPatternRulesMgr {
        const_file_patterns: String::new(),
        const_file_rules: String::new(),
        global_trust_dir_patterns: String::new(),
        global_trust_dir_rules: String::new(),
        pre_global_trust_dir_patterns: String::new(),
        pre_const_file_patterns: String::new(),
        inited: false,
    })
});

impl ProcessPatternRulesMgr {
    pub fn init(&mut self) {
        if self.inited {
            info!("ProcessPatternRulesMgr 已经初始化");
            return;
        }

        self.inited = true;
        info!("ProcessPatternRulesMgr 初始化成功");
        self.add_const_process_pattern();
    }

    // 向 /proc 文件写入内容
    fn write_to_proc_file(path: &str, content: &str) -> std::io::Result<()> {
        // 检查文件是否存在
        if !Path::new(path).exists() {
            let err = Error::new(ErrorKind::NotFound, format!("文件 {} 不存在", path));
            error!("{}", err);
            return Err(err);
        }

        // 打开文件并写入
        let mut file = OpenOptions::new()
            .write(true)
            .open(path)?;
        file.write_all(content.as_bytes())?;
        info!("成功写入文件 {}", path);
        Ok(())
    }

    // 清除文件模式
    pub fn clear_file_pattern(&self) -> std::io::Result<()> {
        if let Some(w) = crate::get_dpi_writer() {
            w.clear_process();
            info!("已清除进程模式（DpiWriter）");
            return Ok(());
        }
        let mut file = File::create(FILE_PATTERNS_PROC_FILE)?;
        file.write_all(b"c\n")?;
        info!("已清除文件模式");
        Ok(())
    }

    // 清除 DPI 规则
    pub fn clear_dpi_rules(&self) -> std::io::Result<()> {
        // DpiWriter 模式下 clear_process() 已同时清空 pattern 与 rule，无需重复
        if crate::get_dpi_writer().is_some() {
            return Ok(());
        }
        let mut file = File::create(DPI_RULE_PROC_FILE)?;
        file.write_all(b"c\n")?;
        info!("已清除 DPI 规则");
        Ok(())
    }

    // 构建文件模式
    pub fn build_file_pattern(&self) {
        if let Some(w) = crate::get_dpi_writer() {
            w.build_process();
            info!("已构建进程模式（DpiWriter）");
            return;
        }
        if let Err(e) = File::create(FILE_PATTERNS_PROC_FILE).and_then(|mut f| f.write_all(b"b\n")) {
            error!("构建文件模式失败: {}", e);
        } else {
            info!("已构建文件模式");
        }
    }

    // 添加常量进程模式
    pub fn add_const_process_pattern(&mut self) {
        // 清空现有模式和规则
        self.const_file_patterns.clear();
        self.const_file_rules.clear();

        // 遍历预定义的进程模式
        for (index, process) in PROCESS_PATTERNS.iter().enumerate() {
            let index = index + 1; // 从 1 开始计数
            let pattern_name = if process.typ == 0 { "true_process_" } else { "sys_true_process_" };
            let target = if process.typ == 0 { "true_process" } else { "sys_true_process" };

            // 构建模式字符串
            let pattern = format!(
                "name={}{},key={}{}\n",
                pattern_name, index, process.key, process.param
            );
            self.const_file_patterns.push_str(&pattern);

            // 构建规则字符串
            let rule = format!(
                "target={},pattern={}{},type={}\n",
                target, pattern_name, index, process.typ
            );
            self.const_file_rules.push_str(&rule);
        }

        // 设置规则
        self.set_pattern_rules();
        info!("已添加常量进程模式");
    }

    // 设置全局信任目录
    pub fn set_global_trust_dir(&mut self, global_trust_dirs: Vec<GlobalTrustDir>) {
        // 清空现有模式和规则
        self.global_trust_dir_patterns.clear();
        self.global_trust_dir_rules.clear();

        // 限制最多 50 个信任目录
        for (i, dir) in global_trust_dirs.iter().enumerate().take(50) {
            let name = format!("trueDir_{}", i);
            let mut pattern = format!("name={},key={}", name, dir.dir);

            // 根据类型添加参数
            if dir.typ == 1 {
                if dir.is_extend == 0 {
                    pattern.push_str(",isnot_extend=1");
                }
                let depth = dir.dir.len();
                pattern.push_str(&format!(",depth={}", depth));
            } else {
                pattern.push_str(",pkt_len=-1");
            }
            pattern.push_str(",case_offset=1\n");

            // 添加模式
            self.global_trust_dir_patterns.push_str(&pattern);

            // 添加规则
            let rule = format!("target=TDir_rule,type=0,pattern={}\n", name);
            self.global_trust_dir_rules.push_str(&rule);
        }

        if global_trust_dirs.len() > 50 {
            info!("信任目录数量过多，已截断至 50，总数: {}", global_trust_dirs.len());
        }

        // 设置规则
        self.set_pattern_rules();
        info!("已设置全局信任目录");
    }

    // 加载模式和规则到内核
    fn load_pattern_rules(&self) {
        // backend 模式（driver/eBPF）：都走 DpiWriter。
        // - driver：DriverBackend 照写 /proc/osec/process_dpi（与原先一致）。
        // - eBPF：EbpfBackend 只把信任进程（true_process_/sys_true_process_）解析成
        //   (dev,inode) 写入 proc_rules，跳过信任目录 trueDir_*（由 file DPI 处理）。
        if let Some(w) = crate::get_dpi_writer() {
            if !self.const_file_patterns.is_empty() {
                w.write_process_pair(&self.const_file_patterns, &self.const_file_rules);
            }
            if !self.global_trust_dir_patterns.is_empty() {
                w.write_process_pair(&self.global_trust_dir_patterns, &self.global_trust_dir_rules);
            }
            self.build_file_pattern();
            info!("已通过 DpiWriter 加载进程模式和规则到内核");
            return;
        }

        // 无 DpiWriter 注册时（正常启动流程都会注册），回退直接写 /proc/osec/process_dpi
        if !self.const_file_patterns.is_empty() {
            let _ = Self::write_to_proc_file(FILE_PATTERNS_PROC_FILE, &self.const_file_patterns);
            let _ = Self::write_to_proc_file(DPI_RULE_PROC_FILE, &self.const_file_rules);
        }

        // 写入全局信任目录模式
        if !self.global_trust_dir_patterns.is_empty() {
            let _ = Self::write_to_proc_file(FILE_PATTERNS_PROC_FILE, &self.global_trust_dir_patterns);
            let _ = Self::write_to_proc_file(DPI_RULE_PROC_FILE, &self.global_trust_dir_rules);
        }

        // 构建文件模式
        self.build_file_pattern();
        info!("已加载模式和规则到内核");
    }

    // 判断模式是否变更
    fn patterns_has_changed(&self) -> bool {
        self.pre_global_trust_dir_patterns != self.global_trust_dir_patterns ||
            self.pre_const_file_patterns != self.const_file_patterns || true
    }

    // 备份当前模式
    fn patterns_backup(&mut self) {
        self.pre_global_trust_dir_patterns = self.global_trust_dir_patterns.clone();
        self.pre_const_file_patterns = self.const_file_patterns.clone();
        info!("已备份模式");
    }

    // 设置模式规则
    pub fn set_pattern_rules(&mut self) {
        if self.patterns_has_changed() {
            let _ = self.clear_file_pattern();
            let _ = self.clear_dpi_rules();
            self.load_pattern_rules();
            self.patterns_backup();
        }
        info!("已设置模式规则");
    }
}
