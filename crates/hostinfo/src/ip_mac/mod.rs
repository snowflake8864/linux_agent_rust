use std::process::Command;

pub fn get_ip() -> Option<String> {
    let output = Command::new("ifconfig")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())?;

    let mut ip = String::new();
    for line in output.lines() {
        let trimmed_line = line.trim();
        if trimmed_line.starts_with("inet ") || trimmed_line.starts_with("inet addr:") {
            let ip_address = trimmed_line.split_whitespace().nth(1).unwrap_or("");
            if !ip_address.contains("127.0.0.1") && !ip_address.is_empty() {
                if !ip.is_empty() {
                    ip += ",";
                }
                ip += ip_address;
            }
        }
    }
    if ip.is_empty() {
        None
    } else {
        Some(ip)
    }
}

pub fn get_mac() -> Option<String> {
    let output = Command::new("ifconfig")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())?;

    for line in output.lines() {
        if let Some(mac_start) = line.find("ether ") {
            return Some(line[mac_start + 6..mac_start + 23].to_string());
        }
    }
    None
}

