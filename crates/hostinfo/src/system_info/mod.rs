
use std::fs;
use std::io::{self, Error};
use std::process::Command;

pub struct SystemInfo;

impl SystemInfo {
    /// 获取主机名称
    pub fn get_computer_name() -> Result<String, Error> {
        // 直接读取 /proc/sys/kernel/hostname
        let hostname = fs::read_to_string("/proc/sys/kernel/hostname")?;
        Ok(hostname.trim().to_string())
    }

    /// 获取操作系统版本（兼容老系统如 CentOS 6）
    fn get_os_version() -> Result<String, Error> {
        // 方式1: 读取 /etc/os-release（现代 Linux 发行版）
        if let Ok(os_release) = fs::read_to_string("/etc/os-release") {
            for line in os_release.lines() {
                if line.starts_with("PRETTY_NAME=") {
                    return Ok(line
                        .trim_start_matches("PRETTY_NAME=")
                        .trim_matches('"')
                        .to_string());
                }
                if line.starts_with("NAME=") {
                    return Ok(line
                        .trim_start_matches("NAME=")
                        .trim_matches('"')
                        .to_string());
                }
            }
        }

        // 方式2: 读取 /etc/redhat-release（CentOS/RHEL 6 等）
        if let Ok(content) = fs::read_to_string("/etc/redhat-release") {
            return Ok(content.trim().to_string());
        }

        // 方式3: 读取 /etc/centos-release
        if let Ok(content) = fs::read_to_string("/etc/centos-release") {
            return Ok(content.trim().to_string());
        }

        // 方式4: 读取 /etc/lsb-release（Ubuntu 老版本）
        if let Ok(lsb_release) = fs::read_to_string("/etc/lsb-release") {
            let mut description = None;
            let mut distro = None;
            for line in lsb_release.lines() {
                if line.starts_with("DISTRIB_DESCRIPTION=") {
                    description = Some(
                        line.trim_start_matches("DISTRIB_DESCRIPTION=")
                            .trim_matches('"')
                            .to_string(),
                    );
                }
                if line.starts_with("DISTRIB_ID=") {
                    distro = Some(
                        line.trim_start_matches("DISTRIB_ID=")
                            .trim_matches('"')
                            .to_string(),
                    );
                }
            }
            if let Some(desc) = description {
                return Ok(desc);
            }
            if let Some(distro) = distro {
                return Ok(distro);
            }
        }

        // 方式5: 读取 /etc/debian_version
        if let Ok(content) = fs::read_to_string("/etc/debian_version") {
            return Ok(format!("Debian {}", content.trim()));
        }

        // 方式6: 使用 lsb_release 命令（兜底）
        if let Ok(output) = Command::new("lsb_release").arg("-d").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(desc) = stdout.strip_prefix("Description:\t") {
                return Ok(desc.trim().to_string());
            }
        }

        // 方式7: 使用 uname 命令（最终兜底）
        if let Ok(output) = Command::new("uname").arg("-s").output() {
            let os = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !os.is_empty() {
                return Ok(os);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "OS version not found",
        ))
    }

    /// 获取内核版本
    pub fn get_kernel_version() -> Result<String, Error> {
        let release = fs::read_to_string("/proc/sys/kernel/osrelease")?;
        Ok(release.trim().to_string())
    }

    /// 获取操作系统 + 内核信息
    pub fn get_computer_version() -> Result<String, Error> {
        let os_version = SystemInfo::get_os_version().unwrap_or_else(|_| "Unknown".to_string());
        let kernel_version = SystemInfo::get_kernel_version().unwrap_or_else(|_| "Unknown".to_string());
        Ok(format!("{}_kernel:{}", os_version.replace(' ', ""), kernel_version))
    }

    /// 获取总磁盘大小（以 GB 为单位）
    pub fn get_disk_size() -> Result<String, Error> {
        let block_dir = "/sys/block";
        let mut total_size_gb = 0u64;

        let entries = fs::read_dir(block_dir)?
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name().to_string_lossy().to_string();
                name.starts_with("sd") || name.starts_with("nvme") || name.starts_with("vda")
            })
            .map(|entry| entry.path());

        for path in entries {
            let size_file = path.join("size");
            if let Ok(size_str) = fs::read_to_string(size_file) {
                if let Ok(sectors) = size_str.trim().parse::<u64>() {
                    let size_gb = sectors * 512 / 1024 / 1024 / 1024;
                    total_size_gb += size_gb;
                }
            }
        }

        Ok(format!("{} GB", total_size_gb))
    }

    pub fn get_memory_size() -> Result<String, Error> {
        let meminfo = fs::read_to_string("/proc/meminfo")?;
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(kb_str) = parts.get(1) {
                    if let Ok(kb) = kb_str.parse::<f64>() {
                        let gb = kb / 1024.0 / 1024.0; // kB → MB → GB
                        return Ok(format!("{:.1}G", gb));
                    }
                }
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "Memory size not found"))
    }
    /// 获取 CPU 核心数
    pub fn get_cpu_cores() -> Result<String, Error> {
        let output = Command::new("nproc").output()?;
        let output_str = String::from_utf8_lossy(&output.stdout);
        Ok(output_str.trim().to_string())
    }
}

