use std::process::Command;

pub fn get_ip() -> Option<String> {
    let output = Command::new("ip")
        .args(["addr", "show"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ips = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();

        // 匹配 IPv4 地址行：以 "inet " 开头
        if trimmed.starts_with("inet ") {
            // 提取 IP/掩码 部分（通常是第一个字段 after "inet"）
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            let ip_with_prefix = parts[1]; // e.g. "192.168.16.117/16"

            // 跳过 loopback
            if ip_with_prefix.starts_with("127.") {
                continue;
            }

            // 去掉前缀部分（/16, /24 等）
            if let Some(ip) = ip_with_prefix.split_once('/') {
                let ip_addr = ip.0;
                if !ip_addr.is_empty() {
                    ips.push(ip_addr.to_string());
                }
            }
        }
    }

    if ips.is_empty() {
        None
    } else {
        Some(ips.join(","))
    }
}

pub fn get_mac() -> Option<String> {
    // 优先从 /sys/class/net/ 读取物理网卡的 MAC 地址
    if let Some(mac) = get_mac_from_sysfs() {
        return Some(mac);
    }

    // 回退到 ifconfig 方式（兼容旧系统）
    get_mac_from_ifconfig()
}

/// 从 /sys/class/net/ 读取物理网卡的 MAC 地址
/// 优先匹配物理网卡（enp*, ens*, eth*, eno*），跳过虚拟网卡和 loopback
fn get_mac_from_sysfs() -> Option<String> {
    let net_dir = std::path::Path::new("/sys/class/net");
    if !net_dir.exists() {
        return None;
    }

    let entries = std::fs::read_dir(net_dir).ok()?;

    // 物理网卡命名前缀（按优先级排序）
    let physical_prefixes = ["enp", "ens", "eth", "eno", "wlp", "wlan"];
    // 虚拟网卡/不需要的接口前缀
    let skip_prefixes = ["lo", "virbr", "docker", "veth", "br-", "lxcbr", "vnet"];

    let mut physical_macs: Vec<String> = Vec::new();
    let mut other_macs: Vec<String> = Vec::new();

    for entry in entries.filter_map(|e| e.ok()) {
        let iface_name = entry.file_name().to_string_lossy().to_string();

        // 跳过 loopback 和虚拟网卡
        if skip_prefixes.iter().any(|p| iface_name.starts_with(p)) {
            continue;
        }

        let addr_path = entry.path().join("address");
        if let Ok(mac) = std::fs::read_to_string(&addr_path) {
            let mac = mac.trim().to_string();
            if mac.is_empty() || mac == "00:00:00:00:00:00" {
                continue;
            }

            if physical_prefixes.iter().any(|p| iface_name.starts_with(p)) {
                physical_macs.push(mac);
            } else {
                other_macs.push(mac);
            }
        }
    }

    // 优先返回物理网卡的 MAC
    if !physical_macs.is_empty() {
        return Some(physical_macs[0].clone());
    }
    // 其次返回其他非虚拟网卡的 MAC
    if !other_macs.is_empty() {
        return Some(other_macs[0].clone());
    }

    None
}

/// 回退方案：解析 ifconfig 输出
fn get_mac_from_ifconfig() -> Option<String> {
    let output = Command::new("ifconfig")
        .output()
        .ok()?
        .stdout;

    let s = String::from_utf8_lossy(&output);

    for line in s.lines() {
        if let Some(pos) = line.find("ether ") {
            return extract_mac(&line[pos + 6..]);
        }
        if let Some(pos) = line.find("HWaddr ") {
            return extract_mac(&line[pos + 7..]);
        }
    }
    None
}

fn extract_mac(s: &str) -> Option<String> {
    s.get(..17).map(|mac| mac.to_string())
}
