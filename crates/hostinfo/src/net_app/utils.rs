use std::net::Ipv4Addr;

pub fn hex_to_ip_port(hex: &str) -> (String, String) {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return ("0.0.0.0".into(), "0".into());
    }

    let ip_raw = parts[0];
    let port_hex = parts[1];

    let ip = u32::from_str_radix(ip_raw, 16).unwrap_or(0);
    let ip_addr = Ipv4Addr::from(ip.swap_bytes()).to_string();

    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0).to_string();

    (ip_addr, port)
}

pub fn proc_net_status_to_str(status_hex: &str) -> &'static str {
    match status_hex {
        "0A" => "LISTEN",
        "01" => "ESTABLISHED",
        _ => "--",
    }
}

