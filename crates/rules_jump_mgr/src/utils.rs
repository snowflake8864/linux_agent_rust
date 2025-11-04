use logging::log_info;
// crates/rules_jump_mgr/src/utils.rs
use tokio::process::Command;
use std::net::Ipv4Addr;
use ipnet::Ipv4Net;
use regex::Regex;
use std::fs;

/// 运行外部命令并返回 stdout（err -> Err(String)）
pub async fn run_cmd_capture(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .await
        .map_err(|e| format!("failed exec {} {:?}: {}", cmd, args, e))?;
    if !output.status.success() {
        return Err(format!(
            "{} {:?} failed: {}",
            cmd,
            args,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// 运行命令，不捕获输出（仅返回是否成功）
pub async fn run_cmd_status(cmd: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .await
        .map_err(|e| format!("failed exec {} {:?}: {}", cmd, args, e))?;
    if !status.success() {
        return Err(format!("{} {:?} exit code: {}", cmd, args, status));
    }
    Ok(())
}

/// netmask "255.255.255.0" -> prefix 24
pub fn netmask_to_prefix(netmask: &str) -> Result<u8, Box<dyn std::error::Error>> {
    let ip: Ipv4Addr = netmask.parse()?;
    let mask_u32: u32 = ip.into();
    Ok(mask_u32.count_ones() as u8)
}

/// prefix -> netmask
pub fn prefix_to_netmask(prefix: u8) -> Result<String, Box<dyn std::error::Error>> {
    if prefix > 32 { return Err("invalid prefix".into()); }
    let mask: u32 = if prefix == 0 { 0 } else { (!0u32).checked_shl(32 - prefix as u32).unwrap_or(0) };
    let a = ((mask >> 24) & 0xFF) as u8;
    let b = ((mask >> 16) & 0xFF) as u8;
    let c = ((mask >> 8) & 0xFF) as u8;
    let d = (mask & 0xFF) as u8;
    Ok(format!("{}.{}.{}.{}", a, b, c, d))
}

/// parse CIDR "10.0.0.1/24" -> ("10.0.0.1", 24)
pub fn parse_cidr(cidr: &str) -> Result<(String, u8), Box<dyn std::error::Error>> {
    let net: Ipv4Net = cidr.parse()?;
    Ok((net.addr().to_string(), net.prefix_len()))
}

/// 检查指定接口上是否存在某 IPv4 地址（解析 ip -4 addr show dev <iface>）
pub async fn ip_exists_on_iface(iface: &str, ip: &str) -> bool {
    match run_cmd_capture("ip", &["-4", "addr", "show", "dev", iface]).await {
        Ok(out) => out.contains(ip),
        Err(_) => false,
    }
}

pub async fn get_local_ip() -> Option<String> {
    let mut ips = Vec::new();

    if let Ok(out) = run_cmd_capture("ip", &["-o", "-4", "addr", "show", "scope", "global"]).await {
        let re = Regex::new(r"inet\s+(\d+\.\d+\.\d+\.\d+)/\d+").unwrap();
        for line in out.lines() {
            if let Some(cap) = re.captures(line) {
                let ip = cap.get(1).unwrap().as_str();
                if ip != "127.0.0.1" && !ip.starts_with("169.254.") {
                    ips.push(ip.to_string());
                }
            }
        }
    }

    if ips.is_empty() {
        if let Ok(out) = run_cmd_capture("ip", &["route", "get", "1.1.1.1"]).await {
            let re = Regex::new(r"src\s+(\d+\.\d+\.\d+\.\d+)").unwrap();
            if let Some(cap) = re.captures(&out) {
                let fallback_ip = cap.get(1).unwrap().as_str();
                if fallback_ip != "127.0.0.1" && !fallback_ip.starts_with("169.254.") {
                    ips.push(fallback_ip.to_string());
                }
            }
        }
    }

    // 去重并返回第一个
    ips.sort_unstable();
    ips.dedup();
    ips.into_iter().next()
}

pub async fn get_local_ips_all() -> Option<String> {
    let out4 = run_cmd_capture("ip", &["-o", "-4", "addr", "show"]).await.ok();
    let out6 = run_cmd_capture("ip", &["-o", "-6", "addr", "show"]).await.ok();

    let mut ips = Vec::new();

    // 虚拟接口前缀
    const BAD_IFACES: [&str; 8] = [
        "lo", "docker", "veth", "br-", "cni", "flannel", "kube", "virbr",
    ];

    // 处理 IPv4
    if let Some(out) = out4 {
        for line in out.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            let iface = parts[1];
            let cidr = parts[3];

            // 过滤虚拟网卡
            if BAD_IFACES.iter().any(|bad| iface.starts_with(bad)) {
                continue;
            }

            if let Some((ip, _)) = cidr.split_once('/') {
                ips.push(ip.to_string());
            }
        }
    }

    // 处理 IPv6
    if let Some(out) = out6 {
        for line in out.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            let iface = parts[1];
            let cidr = parts[3];

            // 过滤虚拟网卡
            if BAD_IFACES.iter().any(|bad| iface.starts_with(bad)) {
                continue;
            }

            if let Some((ip, _)) = cidr.split_once('/') {
                // ✅ 排除 IPv6 无用地址
                if ip == "::1" {
                    continue;
                }
                if ip.starts_with("fe80:") {
                    continue;
                }
                if ip.starts_with("ff") {
                    continue;
                }
                ips.push(ip.to_string());
            }
        }
    }

    if ips.is_empty() {
        None
    } else {
        Some(ips.join(","))
    }
}
pub async fn get_local_ips_exclude(excluded_ip: &str) -> Vec<String> {
    let mut ips = Vec::new();

    // 1. 尝试从 ip addr 获取（排除 lo, 169.254, excluded_ip）
    if let Ok(out) = run_cmd_capture("ip", &["-o", "-4", "addr", "show", "scope", "global"]).await {
        // 更健壮的正则：匹配 "2: eth0    inet 192.168.1.10/24 ..."
        let re = Regex::new(r"inet\s+(\d+\.\d+\.\d+\.\d+)/\d+").unwrap();
        for line in out.lines() {
            if let Some(cap) = re.captures(line) {
                let ip = cap.get(1).unwrap().as_str();
                if ip != "127.0.0.1"
                    && !ip.starts_with("169.254.")
                    && ip != excluded_ip
                {
                    ips.push(ip.to_string());
                }
            }
        }
    }

    // 2. 如果没找到，fallback 到默认路由的 src IP（即使它等于 excluded_ip）
    if ips.is_empty() {
        if let Ok(out) = run_cmd_capture("ip", &["route", "get", "1.1.1.1"]).await {
            let re = Regex::new(r"src\s+(\d+\.\d+\.\d+\.\d+)").unwrap();
            if let Some(cap) = re.captures(&out) {
                let fallback_ip = cap.get(1).unwrap().as_str();
                if fallback_ip != "127.0.0.1" && !fallback_ip.starts_with("169.254.") {
                    ips.push(fallback_ip.to_string());
                }
            }
        }
    }

    // 去重
    ips.sort_unstable();
    ips.dedup();
    ips
}
pub fn has_established_connection(target_ip: &str) -> bool {
    // /proc/net/tcp lines: local_address:port rem_address:port st ...
    if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
        // convert target_ip to hex little-endian (host order) used in /proc/net/tcp
        if let Ok(ip) = target_ip.parse::<Ipv4Addr>() {
            let octets = ip.octets();
            let hex = format!("{:02X}{:02X}{:02X}{:02X}", octets[3], octets[2], octets[1], octets[0]);
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() > 3 {
                    let rem_addr = fields[2];
                    // rem_addr format: "0100007F:0035"
                    if rem_addr.starts_with(&hex) {
                        // state field at index 3: "01" = ESTABLISHED
                        let state = fields[3];
                        if state == "01" { return true; }
                    }
                }
            }
        }
    }
    false
}

