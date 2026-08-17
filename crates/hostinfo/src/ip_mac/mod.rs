use std::process::Command;

/// 虚拟网卡前缀，get_ip 与 get_mac 共用。
/// 跳过 docker/veth/br-/CNI 等虚拟接口，避免上报的 IP/MAC 被容器网络污染。
/// 注意 `br-` 带连字符，只匹配 docker 风格 `br-<hash>`，不会误伤物理桥 `br0`。
const SKIP_IFACE_PREFIXES: [&str; 18] = [
    "lo", "virbr", "docker", "veth", "br-", "lxcbr", "vnet",
    "tun", "tap", "vxlan", "flannel", "cni", "kube", "cali", "ovs",
    "nodelocaldns", "dummy", "ipvs",
];

/// 上报的 IP 列表最多保留的条目数
const MAX_IPS: usize = 6;

pub fn get_ip() -> Option<String> {
    // `-o` 每地址一行，`-4` 只取 IPv4。
    let output = Command::new("ip")
        .args(["-o", "-4", "addr", "show"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ips = Vec::new();

    for line in stdout.lines() {
        // `ip -o addr` 每行格式: "<idx>: <iface> inet <ip>/<prefix> ..."
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 || parts[2] != "inet" {
            continue;
        }

        let iface = parts[1];
        // 跳过 loopback 和虚拟网卡（docker/veth/br- 等）
        if SKIP_IFACE_PREFIXES.iter().any(|p| iface.starts_with(p)) {
            continue;
        }

        let ip_with_prefix = parts[3]; // e.g. "192.168.16.117/16"

        // 跳过链路本地地址（169.254.x，如 nodelocaldns / APIPA）
        if ip_with_prefix.starts_with("169.254.") {
            continue;
        }

        // 去掉前缀部分（/16, /24 等）
        if let Some((ip_addr, _)) = ip_with_prefix.split_once('/') {
            if !ip_addr.is_empty() {
                ips.push(ip_addr.to_string());
            }
        }
    }

    // 默认网关地址必须包含在列表里，放在最前面，保证截断到 MAX_IPS 后仍在。
    let mut result: Vec<String> = Vec::new();
    if let Some(gw) = get_default_gateway() {
        result.push(gw);
    }
    for ip in ips {
        if result.len() >= MAX_IPS {
            break;
        }
        if !result.contains(&ip) {
            result.push(ip);
        }
    }

    if result.is_empty() {
        None
    } else {
        Some(result.join(","))
    }
}

/// 获取默认网关地址（`ip route show default` → `default via <gw> ...`）。
/// 用 `ip` 而非 `route -n`，避免依赖可能未安装的 net-tools。
pub fn get_default_gateway() -> Option<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 3 && cols[0] == "default" && cols[1] == "via" {
            // 跳过 IPv6 网关（含 ':'）
            if cols[2].contains(':') {
                continue;
            }
            return Some(cols[2].to_string());
        }
    }
    None
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

    let mut physical_macs: Vec<String> = Vec::new();
    let mut other_macs: Vec<String> = Vec::new();

    for entry in entries.filter_map(|e| e.ok()) {
        let iface_name = entry.file_name().to_string_lossy().to_string();

        // 跳过 loopback 和虚拟网卡
        if SKIP_IFACE_PREFIXES.iter().any(|p| iface_name.starts_with(p)) {
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
