
use std::collections::HashMap;
use std::fs;
use std::io::{self, Error};
use std::process::Command;

/// os-release 可能的存放位置
const OS_RELEASE_PATHS: [&str; 2] = ["/etc/os-release", "/usr/lib/os-release"];

/// os-release 缺失时的兜底文件（老版本 CentOS/Kylin、Alpine、Debian 等）
const OS_FALLBACK_PATHS: [&str; 4] = [
    "/etc/redhat-release",
    "/etc/lsb-release",
    "/etc/alpine-release",
    "/etc/debian_version",
];

pub struct SystemInfo;

/// 解析 os-release 内容为 key -> value（去掉引号，忽略空行与注释）
fn parse_os_release(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        let value = if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            &value[1..value.len() - 1]
        } else {
            value
        };
        if !key.is_empty() && !value.is_empty() {
            map.insert(key.to_string(), value.to_string());
        }
    }
    map
}

/// 读取并解析 os-release
fn read_os_release() -> Result<HashMap<String, String>, Error> {
    let mut last_err: Option<Error> = None;
    for path in OS_RELEASE_PATHS {
        match fs::read_to_string(path) {
            Ok(content) => {
                let map = parse_os_release(&content);
                if !map.is_empty() {
                    return Ok(map);
                }
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "os-release not found")))
}

/// 兜底：从 /etc/redhat-release、/etc/lsb-release、/etc/alpine-release、/etc/debian_version
/// 中读取发行版描述
fn read_os_version_fallback() -> Option<String> {
    for path in OS_FALLBACK_PATHS {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        let map = parse_os_release(&content);
        if let Some(desc) = map
            .get("DISTRIB_DESCRIPTION")
            .or_else(|| map.get("PRETTY_NAME"))
        {
            return Some(desc.clone());
        }
        if let Some(line) = content
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
        {
            return Some(line.to_string());
        }
    }
    None
}

/// 根据 os-release 内容拼出版本描述
fn resolve_os_version(release: &HashMap<String, String>) -> Option<String> {
    if let Some(pretty) = release.get("PRETTY_NAME") {
        return Some(pretty.clone());
    }
    let name = release.get("NAME").or_else(|| release.get("ID"));
    let version = release
        .get("VERSION_ID")
        .or_else(|| release.get("VERSION"))
        .or_else(|| release.get("BUILD_ID"));
    match (name, version) {
        (Some(name), Some(v)) => Some(format!("{} {}", name, v)),
        (Some(name), None) => Some(name.clone()),
        _ => None,
    }
}

impl SystemInfo {
    /// 获取主机名称
    pub fn get_computer_name() -> Result<String, Error> {
        // 直接读取 /proc/sys/kernel/hostname
        let hostname = fs::read_to_string("/proc/sys/kernel/hostname")?;
        Ok(hostname.trim().to_string())
    }

    /// 获取操作系统版本（包含具体发行版本号）
    ///
    /// 优先使用 PRETTY_NAME，例如 "Ubuntu 22.04.3 LTS (Jammy Jellyfish)"、
    /// "CentOS Linux 7 (Core)"、"Kylin Linux Advanced Server V10 (Sword)"、
    /// "UnionTech OS 20"、"openEuler 22.03 (LTS-SP3)"；
    /// 部分发行版（如 Alpine）没有 PRETTY_NAME，此时用 NAME + VERSION_ID
    /// （如 "Alpine 3.18"）或 NAME + VERSION 兜底；连 os-release 都没有的
    /// 老系统则回退到 /etc/redhat-release 等传统版本文件。
    pub fn get_os_version() -> Result<String, Error> {
        let release = read_os_release().unwrap_or_default();
        resolve_os_version(&release)
            .or_else(read_os_version_fallback)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "OS version not found"))
    }

    /// 获取内核版本
    pub fn get_kernel_version() -> Result<String, Error> {
        let release = fs::read_to_string("/proc/sys/kernel/osrelease")?;
        Ok(release.trim().to_string())
    }

    /// 获取操作系统 + 内核信息
    pub fn get_computer_version() -> Result<String, Error> {
        let os_version = SystemInfo::get_os_version()?;
        let kernel_version = SystemInfo::get_kernel_version()?;
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

