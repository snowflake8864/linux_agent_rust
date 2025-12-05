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
    let output = Command::new("ifconfig")
        .output()
        .ok()?
        .stdout;

    let s = String::from_utf8_lossy(&output);

    for line in s.lines() {
        // 匹配 "ether " 或 "HWaddr "
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
