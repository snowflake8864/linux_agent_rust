use crate::net_app::model::{NETAPP_STATE, PortBusinessInfo};
use chrono::Utc;
use std::process::Command;

pub fn update_docker_info() {
    if Command::new("sh").arg("-c").arg("command -v docker").output().map(|o| !o.status.success()).unwrap_or(true) {
        return;
    }

    let output = Command::new("sh")
        .arg("-c")
        .arg("docker ps --format '{{.Ports}}' | awk -F '[ ,]+' '{for(i=1; i<=NF; i++) if($i ~ /^[0-9]+\\/tcp$/) print $i}' | awk -F '/' '{print $1}'")
        .output();

    if let Ok(out) = output {
        let now = Utc::now().timestamp();
        let content = String::from_utf8_lossy(&out.stdout);
        let mut map = NETAPP_STATE.write().unwrap();

        for line in content.lines() {
            if let Ok(port) = line.trim().parse::<u16>() {
                let info = PortBusinessInfo {
                    time: now,
                    protocol: "tcp".into(),
                    local_ip: "0.0.0.0".into(),
                    local_port: port,
                    remote_ip: "".into(),
                    remote_port: "".into(),
                    status: "LISTEN".into(),
                    pid: 0,
                    process_path: "dockerBusinessPort".into(),
                };
                map.port_map.insert(port, info.clone());
                map.port_str_map.insert(port.to_string(), info);
            }
        }
    }
}

