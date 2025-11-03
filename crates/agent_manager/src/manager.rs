//crates/agent_manager/src/manager.rs
use tokio::sync::mpsc::Receiver;
use tokio::time::{sleep, Duration, timeout};
use tokio::process::Command;
use chrono::{Utc, Datelike};  
use std::io::{Read, Write};
use std::path::PathBuf;
use std::fs;
use std::process::Stdio;
use logging::{log_info, log_error};


const MAX_WAIT_SECONDS: u64 = 30;
const POLL_INTERVAL_MILLIS: u64 = 500;


#[derive(Debug, Clone)]
pub enum AgentCommand {
    Update,
    Uninstall,
    Unknown(String),
}

pub async fn run_agent_manager(mut cmd_rx: Receiver<AgentCommand>) {
    log_info!("[agent_manager] Ready to receive commands...");

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            AgentCommand::Update => {
                log_info!("[agent_manager] === Received 'update' ===");

                if let Err(e) = write_proc_self().await {
                    log_error!("[agent_manager] write_proc_self error: {}", e);
                }

                if let Err(e) = stop_osec_services().await {
                    log_error!("[agent_manager] stop_osec_services error: {}", e);
                }

                tokio::spawn(async {
                    if let Some(script_path) = find_upgrade_script("/tmp/osec_update") {
                        run_script_and_cleanup(script_path, "/tmp/osec_update").await;
                    } else {
                        log_error!("[agent_manager] No upgrade script found");
                    }
                });
            }

            AgentCommand::Uninstall => {
                log_info!("[agent_manager] === Received 'uninstall' ===");

                if let Err(e) = write_proc_self().await {
                    log_error!("[agent_manager] write_proc_self error: {}", e);
                }

                if let Err(e) = stop_osec_services().await {
                    log_error!("[agent_manager] stop_osec_services error: {}", e);
                }

                tokio::spawn(async {
                    uninstall_all().await;
                    std::process::exit(0);
                });
            }

            AgentCommand::Unknown(s) => {
                log_info!("[agent_manager] Unknown command: {}", s);
            }
        }
    }
}
async fn write_proc_self() -> Result<(), String> {
    let now = Utc::now();
    let year = now.year() as u64;
    let month = now.month() as u64;  // 1..=12
    let day = now.day() as u64;      // 1..=31

    let date_num = year * 10000 + month * 100 + day;

    let incremented = date_num + 1;

    let inc_str = incremented.to_string();
    let inc_len = inc_str.len();

    let formatted;
    if inc_len == 8 {
        let y = &inc_str[0..4];
        let m = &inc_str[4..6];
        let d = &inc_str[6..8];
        let m_num: u64 = m.parse().unwrap();
        let d_num: u64 = d.parse().unwrap();
        formatted = format!("{}{}{}", y, m_num, d_num);
    } else if inc_len == 7 {
        let y = &inc_str[0..4];
        let rest: u64 = inc_str[4..].parse().unwrap();
        let m = rest / 100;
        let d = rest % 100;
        formatted = format!("{}{}{}", y, m, d);
    } else {
        formatted = inc_str;
    }

    let proc_path = "/proc/osec/self";
    log_info!("[agent_manager] Writing {}", proc_path);

    if !std::path::Path::new(proc_path).exists() {
        log_info!("[agent_manager] {} 不存在，跳过写入", proc_path);
        return Ok(());
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(proc_path)
        .map_err(|e| format!("打开失败: {}", e))?;

    let content = format!("veda {} 0\n", formatted);
    file.write_all(content.as_bytes())
        .map_err(|e| format!("写入失败: {}", e))?;

    log_info!("[agent_manager] ✅ 已写入: {}", content.trim());

    let mut read_buf = String::new();
    fs::File::open(proc_path)
        .and_then(|mut f| f.read_to_string(&mut read_buf))
        .map_err(|e| format!("读取失败: {}", e))?;

    log_info!("[agent_manager] 读取结果: {}", read_buf.trim());
    Ok(())
}

async fn is_process_running(name: &str) -> bool {
    let output = Command::new("pgrep").arg("-f").arg(name).output().await;
    match output {
        Ok(out) if out.status.success() => {
            true
        }
        _ => false,
    }
}

async fn stop_osec_services() -> Result<(), String> {
    log_info!("[agent_manager] Attempting to stop and disable osec...");

    let has_systemctl = Command::new("which")
        .arg("systemctl")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    let has_service = Command::new("which")
        .arg("service")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    if has_systemctl {
        log_info!("[agent_manager] Using systemctl to stop and disable osec");
        let _ = Command::new("systemctl").args(["stop", "osec"]).status().await;
        let _ = Command::new("systemctl").args(["disable", "osec"]).status().await;

        let _ = tokio::fs::remove_file("/etc/systemd/system/osec.service").await;
        let _ = Command::new("systemctl").arg("daemon-reload").status().await;
    }
    else if has_service {
        log_info!("[agent_manager] Using service to stop osec");
        let _ = Command::new("service").args(["osec", "stop"]).status().await;

        let _ = tokio::fs::remove_file("/etc/init.d/osecservicecentos").await;
    }
    else {
        log_info!("[agent_manager] Falling back to pkill for osecmonitor and MagicArmor_0");
        let _ = Command::new("pkill").arg("-9").arg("osecmonitor").status().await;
    }

    log_info!("[agent_manager] Sending SIGKILL to any remaining MagicArmor_0");
    let _ = Command::new("pkill").arg("-9").arg("MagicArmor_0").status().await;

    log_info!("[agent_manager] Waiting for MagicArmor_0 to exit...");
    let wait_result = timeout(Duration::from_secs(MAX_WAIT_SECONDS), async {
        while is_process_running("MagicArmor_0").await {
            sleep(Duration::from_millis(POLL_INTERVAL_MILLIS)).await;
        }
    }).await;

    if wait_result.is_err() {
        log_error!(
            "[agent_manager] Timeout: MagicArmor_0 did not exit within {} seconds.",
            MAX_WAIT_SECONDS
        );
    }

    log_info!("[agent_manager] Attempting to unload osec_base kernel module");
    let _ = Command::new("rmmod").arg("osec_base").status().await;

    sleep(Duration::from_millis(300)).await;

    log_info!("[agent_manager] osec services and processes cleaned up.");
    Ok(())
}
async fn run_script_and_cleanup(script_path: PathBuf, cleanup_dir: &str) {

   // tokio::time::sleep(Duration::from_secs(30)).await;
    log_info!("[agent_manager] Executing {:?}", script_path);

    match Command::new("/bin/bash")
        .arg(&script_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status().await
    {
        Ok(status) => {
            log_info!("[agent_manager] Script exited with: {}", status);
            if status.success() {
                let _ = fs::remove_dir_all(cleanup_dir);
                log_info!("[agent_manager] Cleanup complete.");
            }
        }

        Err(e) => {
            log_error!("[agent_manager] Failed to run script: {}", e);
        }
    }
}

/// 查找 osec-upgrade*.sh
fn find_upgrade_script(dir: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(dir).ok()?;

    for entry in entries.flatten() {
        let path = entry.path();
        if let Some(name) = path.file_name()?.to_str() {
            if name.starts_with("osec-upgrade") && name.ends_with(".sh") {
                return Some(path);
            }
        }
    }

    None
}

async fn uninstall_all() {
    log_info!("[agent_manager] 开始执行卸载流程...");

    let has_systemctl = Command::new("which")
        .arg("systemctl")
        .output().await
        .map(|o| o.status.success())
        .unwrap_or(false);

    let has_service = Command::new("which")
        .arg("service")
        .output().await
        .map(|o| o.status.success())
        .unwrap_or(false);

    // --- 删除 osec 服务 ---
    if has_systemctl {
        let _ = Command::new("systemctl").args(["stop", "osec"]).status().await;
        let _ = Command::new("systemctl").args(["disable", "osec"]).status().await;
        let _ = fs::remove_file("/etc/systemd/system/osec.service");
        let _ = Command::new("systemctl").args(["daemon-reload"]).status().await;
    } else if has_service {
        let _ = Command::new("service").args(["osec", "stop"]).status().await;
        let _ = fs::remove_file("/etc/init.d/osec");
    } else {
        let _ = Command::new("pkill").arg("-f").arg("osecmonitor").status().await;
    }

    if has_systemctl {
        let _ = Command::new("systemctl").args(["disable", "agent_manager"]).status().await;
        let _ = fs::remove_file("/etc/systemd/system/agent_manager.service");
        let _ = Command::new("systemctl").args(["daemon-reload"]).status().await;
    } else if has_service {
        let _ = fs::remove_file("/etc/init.d/agent_manager");
    }

    log_info!("[agent_manager] Checking osec_base module...");
    let modinfo = Command::new("modinfo").arg("osec_base").output().await;

    if let Ok(out) = modinfo {
        if out.status.success() {
            let _ = Command::new("rmmod").arg("osec_base").status().await;

            if let Ok(text) = String::from_utf8(out.stdout) {
                for line in text.lines() {
                    if line.starts_with("filename:") {
                        let p = line.trim_start_matches("filename:").trim();
                        let _ = fs::remove_file(p);
                    }
                }
            }
        }
    }

    let install_path = "/opt/osec";
    if PathBuf::from(install_path).exists() {
        let _ = Command::new("rm").args(["-rf", install_path]).status().await;
    }

    log_info!("[agent_manager] ✅ 卸载流程完成");
}

