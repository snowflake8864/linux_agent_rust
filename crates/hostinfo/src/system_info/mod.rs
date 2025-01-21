use std::fs;
use nix::sys::utsname::uname;
use nix::unistd::gethostname;
use std::io::{self, Error};
use std::process::Command;

pub struct SystemInfo;

impl SystemInfo {
    /// 获取主机名称
    pub fn get_computer_name() -> Result<String, Error> {
        let hostname = gethostname()?;
        Ok(hostname.to_string_lossy().to_string())
    }

    /// 获取操作系统版本
    pub fn get_os_version() -> Result<String, Error> {
        let os_release = fs::read_to_string("/etc/os-release")?;
        for line in os_release.lines() {
            if line.starts_with("NAME=") {
                return Ok(line.trim_start_matches("NAME=").trim_matches('"').to_string());
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "OS version not found"))
    }

    /// 获取内核版本
    pub fn get_kernel_version() -> Result<String, Error> {
        let uts = uname()?;
        Ok(uts.release().to_string_lossy().to_string())
    }

    /// 获取计算机版本信息，包含操作系统和内核信息
    pub fn get_computer_version() -> Result<String, Error> {
        let os_version = SystemInfo::get_os_version()?;
        let kernel_version = SystemInfo::get_kernel_version()?;
        Ok(format!("{}_kernel:{}", os_version.replace(" ", ""), kernel_version))
    }

    /// 获取磁盘大小（以GB为单位）
    /*
       pub fn get_disk_size() -> Result<String, Error> {
       let output = Command::new("df")
       .arg("-h")
       .arg("/")
       .output()?;

       let output_str = String::from_utf8_lossy(&output.stdout);
       for line in output_str.lines() {
       if line.starts_with("/dev") {
       let parts: Vec<&str> = line.split_whitespace().collect();
       if parts.len() >= 2 {
       return Ok(parts[1].to_string());
       }
       }
       }
       Err(io::Error::new(io::ErrorKind::NotFound, "Disk size not found"))
       }
       */

    pub fn get_disk_size() -> Result<String, Error> { 
        let block_dir = "/sys/block";
        let mut total_size_gb = 0u64;

        // 读取 /sys/block 目录中的所有磁盘设备
        let entries = fs::read_dir(block_dir)?
            .filter_map(|entry| entry.ok())  // 过滤掉无法读取的条目
            .filter(|entry| {
                // 先获取文件名，然后将其转为字符串并检查是否以磁盘设备的标识开头
                let file_name = entry.file_name();
                let name = file_name.to_string_lossy(); // 使用 to_string_lossy() 延长生命周期
                name.starts_with("sd") || name.starts_with("nvme") || name.starts_with("vda")
            }) // 过滤掉非磁盘设备
        .map(|entry| entry.path())
            .collect::<Vec<_>>();

        for entry in entries {
            // 获取磁盘设备的大小文件路径（比如 /sys/block/sda/size）
            let size_file = entry.join("size");

            // 读取磁盘大小（单位：扇区）
            if let Ok(size_in_sectors_str) = fs::read_to_string(size_file) {
                if let Ok(size_in_sectors) = size_in_sectors_str.trim().parse::<u64>() {
                    // 每个扇区 512 字节
                    let size_in_bytes = size_in_sectors * 512;
                    let size_in_gb = size_in_bytes / 1024 / 1024 / 1024; // 转换为 GB
                    total_size_gb += size_in_gb;
                }
            }
        }

        // 返回所有磁盘总大小
        Ok(format!("{} GB", total_size_gb))
    }

    pub fn get_memory_size() -> Result<String, Error> {
        // 读取 /proc/meminfo 文件
        let meminfo = fs::read_to_string("/proc/meminfo")?;

        // 查找 MemTotal 行
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let total_memory_kb: u64 = parts[1].parse().unwrap_or(0);
                    let total_memory_gb = total_memory_kb / 1024 / 1024; // 转换为 GB
                    return Ok(format!("{}G", total_memory_gb));
                }
            }
        }

        Err(io::Error::new(io::ErrorKind::NotFound, "Memory size not found"))
    } 

    /// 获取CPU核心数
    pub fn get_cpu_cores() -> Result<String, Error> {
        let output = Command::new("nproc")
            .output()?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        Ok(output_str.trim().to_string())
    }

}

