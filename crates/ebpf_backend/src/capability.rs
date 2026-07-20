use std::fs;
use std::path::Path;
use std::process::Command;

/// eBPF 系统能力检测结果
#[derive(Debug)]
pub struct EbpfCapability {
    pub kernel_ok: bool,
    pub kernel_version: String,
    pub btf_ok: bool,
    pub bpf_lsm_ok: bool,
    pub bpf_fs_ok: bool,
}

impl EbpfCapability {
    /// 检测所有 eBPF 必需条件，任一项失败返回 false
    pub fn check() -> Self {
        let kernel_version = get_kernel_version();
        let cap = EbpfCapability {
            kernel_ok: check_kernel_version(&kernel_version),
            kernel_version: kernel_version.clone(),
            btf_ok: Path::new("/sys/kernel/btf/vmlinux").exists(),
            bpf_lsm_ok: check_bpf_lsm(),
            bpf_fs_ok: check_bpf_fs(),
        };
        cap
    }

    /// 所有检测是否通过
    pub fn all_ok(&self) -> bool {
        self.kernel_ok && self.btf_ok && self.bpf_lsm_ok && self.bpf_fs_ok
    }

    /// 返回失败原因的中文描述
    pub fn fail_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if !self.kernel_ok {
            reasons.push(format!(
                "内核版本过低: {} (需要 >= 5.8)",
                self.kernel_version
            ));
        }
        if !self.btf_ok {
            reasons.push("BTF 不支持: /sys/kernel/btf/vmlinux 不存在，请开启 CONFIG_DEBUG_INFO_BTF".into());
        }
        if !self.bpf_lsm_ok {
            reasons.push(
                "BPF LSM 未启用: /sys/kernel/security/lsm 中不含 bpf，请在 GRUB 添加 lsm=...,bpf".into(),
            );
        }
        if !self.bpf_fs_ok {
            reasons.push("bpffs 未挂载: /sys/fs/bpf 不存在，请 mount -t bpf bpffs /sys/fs/bpf".into());
        }
        reasons
    }
}

fn get_kernel_version() -> String {
    let output = Command::new("uname")
        .arg("-r")
        .output()
        .unwrap_or_else(|_| panic!("无法执行 uname -r"));
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn check_kernel_version(version: &str) -> bool {
    // 解析主版本号，例如 "5.15.0-91-generic" → (5, 15)
    let parts: Vec<&str> = version.split(&['.', '-'][..]).collect();
    if parts.len() >= 2 {
        if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
            return major > 5 || (major == 5 && minor >= 8);
        }
    }
    false
}

fn check_bpf_lsm() -> bool {
    if let Ok(content) = fs::read_to_string("/sys/kernel/security/lsm") {
        content.split(',').any(|s| s.trim() == "bpf")
    } else {
        false
    }
}

fn check_bpf_fs() -> bool {
    if let Ok(content) = fs::read_to_string("/proc/mounts") {
        content.lines().any(|l| l.contains("bpf") && l.contains("/sys/fs/bpf"))
    } else {
        false
    }
}
