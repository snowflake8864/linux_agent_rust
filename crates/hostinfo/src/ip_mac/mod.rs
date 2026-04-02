use std::env;
use std::process::Command;

#[allow(dead_code)]
pub fn get_ip() -> Option<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;

    if !output.status.success() {
        return get_first_non_loopback_ip();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Some(line) = stdout.lines().next() {
        for part in line.split_whitespace() {
            if part.starts_with("dev ") {
                let dev = &part[4..];
                return get_ip_by_interface(dev);
            }
        }
    }

    get_first_non_loopback_ip()
}

fn get_ip_by_interface(dev: &str) -> Option<String> {
    let output = Command::new("ip")
        .args(["addr", "show", dev])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("inet ") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                let ip_with_prefix = parts[1];
                if let Some(ip) = ip_with_prefix.split_once('/') {
                    return Some(ip.0.to_string());
                }
            }
        }
    }
    None
}

fn get_first_non_loopback_ip() -> Option<String> {
    let output = Command::new("ip").args(["addr", "show"]).output().ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("inet ") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let ip_with_prefix = parts[1];
            if ip_with_prefix.starts_with("127.") {
                continue;
            }
            if let Some(ip) = ip_with_prefix.split_once('/') {
                return Some(ip.0.to_string());
            }
        }
    }
    None
}

pub fn get_mac() -> Option<String> {
    let output = Command::new("ifconfig").output().ok()?.stdout;

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
