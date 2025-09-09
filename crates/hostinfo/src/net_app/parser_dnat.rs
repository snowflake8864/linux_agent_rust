use crate::net_app::model::{NETAPP_STATE, PortBusinessInfo};
use chrono::Utc;
use std::process::Command;

pub fn update_dnat_info() {
    let output = Command::new("sh")
        .arg("-c")
        .arg("iptables -t nat -L -n -v | grep DNAT | grep tcp")
        .output();

    if let Ok(out) = output {
        if !out.status.success() {
            return;
        }

        let now = Utc::now().timestamp();
        let content = String::from_utf8_lossy(&out.stdout);
        let mut map = NETAPP_STATE.write().unwrap();

        for line in content.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() < 11 {
                continue;
            }

            let dnat = tokens[10];
            if let Some(pos) = dnat.rfind(':') {
                let port_str = &dnat[pos+1..];
                if let Ok(port) = port_str.parse::<u16>() {
                    let info = PortBusinessInfo {
                        time: now,
                        protocol: tokens[9].to_string(),
                        local_ip: "0.0.0.0".into(),
                        local_port: port,
                        remote_ip: "".into(),
                        remote_port: "".into(),
                        status: "--".into(),
                        pid: 0,
                        process_path: "iptableDNAT".into(),
                    };
                    map.port_map.insert(port, info.clone());
                    map.port_str_map.insert(port_str.to_string(), info);
                }
            }
        }
    }
}

