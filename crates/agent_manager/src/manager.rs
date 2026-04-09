//crates/agent_manager/src/manager.rs
use tokio::sync::mpsc::Receiver;
use tokio::time::{sleep, Duration, timeout};
use tokio::process::Command;
use chrono::{Utc, Datelike};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::fs;
use std::process::Stdio;
use logging::{log_info, log_error};
use netlink::netlink::NlSockInfo;

const MAX_WAIT_SECONDS: u64 = 30;
const POLL_INTERVAL_MILLIS: u64 = 500;

fn get_systemd_unit_dir() -> &'static str {
    if std::path::Path::new("/usr/lib/systemd/system").exists() {
        "/usr/lib/systemd/system"
    } else if std::path::Path::new("/lib/systemd/system").exists() {
        "/lib/systemd/system"
    } else {
        "/etc/systemd/system"
    }
}

async fn cleanup_all_service_files(service_name: &str) {
    let dirs = ["/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/system"];
    for dir in dirs {
        let path = format!("{}/{}", dir, service_name);
        if tokio::fs::remove_file(&path).await.is_ok() {
            log_info!("[agent_manager] 已清理 {}", path);
        }
    }
}

fn cleanup_all_service_files_sync(service_name: &str) {
    let dirs = ["/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/system"];
    for dir in dirs {
        let path = format!("{}/{}", dir, service_name);
        if fs::remove_file(&path).is_ok() {
            log_info!("[agent_manager] 已清理 {}", path);
        }
    }
}

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
                } else {
                    log_info!("[agent_manager] write_proc_self 成功");
                }

                log_info!("[agent_manager] 通知内核停止网络审计，释放资源");
                //notify_kernel_network_close().await;

                if let Err(e) = stop_osec_services().await {
                    log_error!("[agent_manager] stop_osec_services error: {}", e);
                } else {
                    log_info!("[agent_manager] stop_osec_services 成功");
                }

                cleanup_c2r_bridge().await;

                tokio::spawn(async {
                    if let Some(script_path) = find_upgrade_script("/tmp/osec_update") {
                        log_info!("[agent_manager] 找到升级脚本: {:?}", script_path);
                        run_script_and_cleanup(script_path, "/tmp/osec_update").await;
                    } else {
                        log_error!("[agent_manager] 未找到升级脚本 (osec-installer*.sh)");
                    }
                });
            }
            AgentCommand::Uninstall => {
                log_info!("[agent_manager] === Received 'uninstall' ===");
                if let Err(e) = write_proc_self().await {
                    log_error!("[Uninstall] write_proc_self error: {}", e);
                } else {
                    log_info!("[Uninstall] write_proc_self 成功");
                }

                if let Err(e) = stop_osec_services().await {
                    log_error!("[Uninstall] stop_osec_services error: {}", e);
                } else {
                    log_info!("[Uninstall] stop_osec_services 成功");
                }

                tokio::spawn(async {
                    uninstall_all().await;
                    log_info!("[Uninstall] 卸载流程已完成，进程即将退出");
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

    let year  = now.year() as u64;   // 2025
    let month = now.month() as u64;  // 1~12  (不补0)
    let day   = now.day() as u64;    // 1~31  (不补0)

    let concatenated = format!("{}{}{}", year, month, day);
    let num = concatenated.parse::<u64>()
        .map_err(|e| format!("日期拼接解析失败: {}", e))?;

    let final_value = num + 1;
    let formatted = final_value.to_string();


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

 /*
     let mut read_buf = String::new();
     fs::File::open(proc_path)
         .and_then(|mut f| f.read_to_string(&mut read_buf))
         .map_err(|e| format!("读取失败: {}", e))?;
 
     log_info!("[agent_manager] 读取结果: {}", read_buf.trim());
 */

    let output = Command::new("cat")
        .arg(proc_path)
        .output()
        .await
        .map_err(|e| format!("读取失败: {}", e))?;
    let result = String::from_utf8_lossy(&output.stdout);

    log_info!("[agent_manager] 读取结果: {}", result.trim());

    Ok(())
}

async fn is_process_running(name: &str) -> bool {
    let output = Command::new("pgrep").arg("-f").arg(name).output().await;
    match output {
        Ok(out) if out.status.success() => true,
        _ => false,
    }
}

async fn send_update_cmd_to_cpp_agent() {
    let socket_path = "/opt/osec/local_agent.socket";
    
    for attempt in 1..=10 {
        let output = Command::new("sh")
            .args(["-c", &format!("echo 'update' | socat - unix-client:{}", socket_path)])
            .output()
            .await;
        
        match output {
            Ok(out) if out.status.success() => {
                log_info!("[agent_manager] 已发送 update 命令给 c++ 版 MagicArmor_0");
                return;
            }
            Ok(_) => {
                sleep(Duration::from_millis(500)).await;
            }
            Err(e) => {
                log_error!("[agent_manager] 发送命令失败: {}", e);
                sleep(Duration::from_millis(500)).await;
            }
        }
    }
    log_error!("[agent_manager] 发送 update 命令超时");
}

async fn notify_kernel_network_close() {
    log_info!("[agent_manager] 创建 netlink socket 并发送 NL_POLICY_NETWORK_CLOSE");
    match NlSockInfo::create_socket() {
        Ok(nl_sock) => {
            if let Err(e) = nl_sock.send_network_close() {
                log_error!("[agent_manager] 发送 network close 失败: {:?}", e);
            } else {
                log_info!("[agent_manager] 已发送 NL_POLICY_NETWORK_CLOSE 给内核");
            }
        }
        Err(e) => {
            log_error!("[agent_manager] 创建 netlink socket 失败: {:?}", e);
        }
    }
}

async fn stop_osec_services() -> Result<(), String> {
    log_info!("[agent_manager] 开始停止并清理 osec 服务...");

    log_info!("[agent_manager] 步骤1: 停止 osec 服务");
    if Path::new("/run/systemd/system").exists() {
        let _ = Command::new("systemctl").args(["stop", "osec"]).status().await;
    } else {
        let _ = Command::new("service").args(["osec", "stop"]).status().await;
    }

    log_info!("[agent_manager] 步骤3: 等待内核完成处理 (15秒)");
    for i in 0..15 {
        sleep(Duration::from_secs(1)).await;
        if i % 2 == 0 {
            log_info!("[agent_manager] 已等待 {} 秒...", i + 1);
        }
    }

    sleep(Duration::from_millis(500)).await;

    log_info!("[agent_manager] 步骤4: 杀死残留进程");
    let _ = Command::new("pkill").arg("-9").arg("MagicArmor_0").status().await;
    let _ = Command::new("killall").arg("-9").arg("MagicArmor_0").status().await;
    let _ = Command::new("pkill").arg("-9").arg("osecmonitor").status().await;
    let _ = Command::new("killall").arg("-9").arg("osecmonitor").status().await;
    let _ = Command::new("pkill").arg("-9").arg("MagicArmor_cli").status().await;
    let _ = Command::new("killall").arg("-9").arg("MagicArmor_cli").status().await;
    let _ = Command::new("pkill").arg("-9").arg("osec_cli").status().await;

    sleep(Duration::from_millis(500)).await;

    log_info!("[agent_manager] 步骤5: 尝试卸载 osec_base 模块");
    let rmmod_result = Command::new("rmmod").arg("-f").arg("osec_base").status().await;
    if rmmod_result.is_err() || !rmmod_result.unwrap().success() {
        log_info!("[agent_manager] osec_base 卸载失败，跳过");
    } else {
        log_info!("[agent_manager] osec_base 卸载成功");
    }

    let lsmod_check = Command::new("bash").args(["-c", "lsmod | grep osec"]).output().await;
    log_info!("[agent_manager] lsmod 检查: {:?}", String::from_utf8_lossy(&lsmod_check.unwrap().stdout));

    log_info!("[agent_manager] 等待 MagicArmor_0 完全退出 (最多 {} 秒)...", MAX_WAIT_SECONDS);
    let wait_result = timeout(Duration::from_secs(MAX_WAIT_SECONDS), async {
        while is_process_running("MagicArmor_0").await {
            sleep(Duration::from_millis(POLL_INTERVAL_MILLIS)).await;
        }
    })
    .await;

    if wait_result.is_err() {
        log_error!("[agent_manager] 超时: MagicArmor_0 在 {} 秒内未退出", MAX_WAIT_SECONDS);
    } else {
        log_info!("[agent_manager] MagicArmor_0 已完全退出");
    }

    let has_service = Command::new("which")
        .arg("service")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    if has_service {
        log_info!("[agent_manager] 使用 service 停止 osec");
        let _ = Command::new("service").args(["osec", "stop"]).status().await;
        let _ = Command::new("pkill").arg("-9").arg("osecmonitor").status().await;

        if tokio::fs::remove_file("/etc/init.d/osec").await.is_ok() {
            log_info!("[agent_manager] 已删除 /etc/init.d/osec");
        }
        if tokio::fs::remove_file("/opt/osec/osec.monitor").await.is_ok() {
            log_info!("[agent_manager] 已删除 /opt/osec/osec.monitor");
        }
        let _ = Command::new("chkconfig").args(["--del", "osec"]).status().await;
        
        // 清理老版本残留
        if tokio::fs::remove_file("/etc/init.d/osecservicecentos").await.is_ok() {
            log_info!("[agent_manager] 已删除老版本 /etc/init.d/osecservicecentos");
            let _ = Command::new("chkconfig").args(["--del", "osecservicecentos"]).status().await;
        }
        let _ = tokio::fs::remove_file("/opt/osec/osecmonitor").await;
    } else {
        log_info!("[agent_manager] 直接使用 pkill 结束 osecmonitor");
        let _ = Command::new("pkill").arg("-9").arg("osecmonitor").status().await;
        // 清理老版本残留
        let _ = tokio::fs::remove_file("/etc/init.d/osecservicecentos").await;
        let _ = tokio::fs::remove_file("/opt/osec/osecmonitor").await;
    }

    // 删除 PID 文件
    let _ = tokio::fs::remove_file("/var/run/osec_backend.pid").await;
    let _ = tokio::fs::remove_file("/var/run/osec.pid").await;
    let _ = tokio::fs::remove_file("/var/run/osec_monitor.pid").await;
    let _ = tokio::fs::remove_file("/tmp/.osec_cli.pid").await;
    let _ = tokio::fs::remove_file("/tmp/.osec_cli.sock").await;

    log_info!("[agent_manager] 尝试卸载内核模块 osec_base");
    let rmmod_status = Command::new("rmmod").arg("osec_base").status().await;
    if rmmod_status.is_ok() && rmmod_status.unwrap().success() {
        log_info!("[agent_manager] osec_base 模块已成功卸载");
    } else {
        log_info!("[agent_manager] osec_base 模块未加载或卸载失败（可忽略）");
    }

    let uname_output = Command::new("uname").arg("-r").output().await;
    if let Ok(output) = uname_output {
        if output.status.success() {
            let kernel_release = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let ko_path = format!("/lib/modules/{}/kernel/drivers/base_osec.ko", kernel_release);
            match tokio::fs::remove_file(&ko_path).await {
                Ok(()) => {
                    log_info!("[agent_manager] 已成功删除 {}", ko_path);
                    log_info!("[agent_manager] 重新生成内核模块依赖关系 (depmod)");
                    let depmod_result = Command::new("depmod").status().await;
                    if depmod_result.is_ok() && depmod_result.unwrap().success() {
                        log_info!("[agent_manager] depmod 执行成功");
                    } else {
                        log_error!("[agent_manager] depmod 执行失败或返回非零状态");
                    }
                }
                Err(e) => {
                    log_info!("[agent_manager] 无法删除 {}（原因: {}，可忽略）", ko_path, e);
                }
            }
        } else {
            log_error!("[agent_manager] uname -r 返回非零状态，无法获取内核版本");
        }
    } else {
        log_error!("[agent_manager] 执行 uname -r 失败，跳过删除 base_osec.ko");
    }    log_info!("[agent_manager] osec 服务及进程清理完毕");
    Ok(())
}

/// 清理 c++2rust 版本遗留的 RPM/DEB 数据库记录和旧 service 文件
/// v1.0 和 c++2rust 版本的 MagicArmorAgent 都在 /opt/osec/ 下，路径相同，不需要删除二进制
async fn cleanup_c2r_bridge() {
    log_info!("[agent_manager] 检查是否需要清理 c++2rust 版本的 RPM/DEB 数据库记录...");

    // 1. 清理 RPM 数据库记录（只删记录，不删文件，不触发卸载脚本）
    // 使用 --allmatches 清理所有匹配的 osec 包
    let rpm_check = Command::new("rpm").args(["-q", "osec"]).status().await;
    if let Ok(status) = rpm_check {
        if status.success() {
            log_info!("[agent_manager] 发现 RPM 数据库记录，开始清理...");
            let _ = Command::new("rpm")
                .args(["-e", "--justdb", "--nodeps", "--allmatches", "osec"])
                .status()
                .await;
            log_info!("[agent_manager] RPM 数据库记录已清理");
        }
    }

    // 2. 清理 DEB 数据库记录
    // 直接操作 dpkg 数据库文件删除记录，避免 pre-removal script 失败
    let deb_output = Command::new("sh")
        .args(["-c", "dpkg -l | grep -q '^[ri].*osec'"])
        .status()
        .await;
    if let Ok(status) = deb_output {
        if status.success() {
            log_info!("[agent_manager] 发现 DEB 数据库记录，开始清理...");
            let _ = Command::new("sh")
                .args(["-c", "sed -i '/^Package: osec$/,/^$/d' /var/lib/dpkg/status"])
                .status()
                .await;
            let _ = Command::new("sh")
                .args(["-c", "rm -f /var/lib/dpkg/info/osec.*"])
                .status()
                .await;
            let _ = Command::new("sh")
                .args(["-c", "[ -f /var/lib/apt/extended_states ] && sed -i '/^Package: osec$/,/^$/d' /var/lib/apt/extended_states || true"])
                .status()
                .await;
            log_info!("[agent_manager] DEB 数据库记录已清理");
        }
    }

    // 3. 检查并清理不在标准路径的旧 service 文件
    // c++2rust 版本应该放在 /usr/lib/systemd/system/ 或 /lib/systemd/system/
    // 如果发现在 /etc/systemd/system/ 等其他路径，需要清理
    let etc_service = "/etc/systemd/system/agent_manager.service";
    if PathBuf::from(etc_service).exists() {
        log_info!("[agent_manager] 发现非标准路径的 service 文件，清理中...");
        match tokio::fs::remove_file(etc_service).await {
            Ok(()) => log_info!("[agent_manager] 已删除: {}", etc_service),
            Err(e) => log_error!("[agent_manager] 删除 {} 失败: {}", etc_service, e),
        }
        // 重新加载 systemd
        let _ = Command::new("systemctl").arg("daemon-reload").status().await;
    }

    log_info!("[agent_manager] c++2rust 版本清理完成");
}

async fn run_script_and_cleanup(script_path: PathBuf, cleanup_dir: &str) {
    log_info!("[agent_manager] 开始执行升级脚本: {:?}", script_path);

    let _ = Command::new("chmod").arg("+x").arg(&script_path).status().await;

    // 创建日志文件记录升级输出
    let log_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("/var/log/osec_upgrade.log")
        .ok();

    let result = if let Some(file) = log_file {
        let stdout = Stdio::from(file);
        // 需要再次打开文件用于 stderr
        let stderr_file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open("/var/log/osec_upgrade.log")
            .ok();
        let stderr = if let Some(f) = stderr_file {
            Stdio::from(f)
        } else {
            Stdio::inherit()
        };
        Command::new("/bin/bash")
            .arg(&script_path)
            .arg("--upgrade")
            .stdout(stdout)
            .stderr(stderr)
            .status()
            .await
    } else {
        // 回退到 inherit
        Command::new("/bin/bash")
            .arg(&script_path)
            .arg("--upgrade")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
    };

    match result {
        Ok(status) => {
            if status.success() {
                log_info!("[agent_manager] 升级脚本执行成功 (exit code 0)");
                if fs::remove_dir_all(cleanup_dir).is_ok() {
                    log_info!("[agent_manager] 已清理临时目录: {}", cleanup_dir);
                } else {
                    log_error!("[agent_manager] 清理临时目录失败: {}", cleanup_dir);
                }
            } else {
                log_error!("[agent_manager] 升级脚本执行失败，退出码: {:?}", status.code());
                log_error!("[agent_manager] 请查看 /var/log/osec_upgrade.log 获取详细错误信息");
            }
        }
        Err(e) => {
            log_error!("[agent_manager] 启动升级脚本失败: {}", e);
        }
    }
}

fn find_upgrade_script(dir: &str) -> Option<PathBuf> {
    match fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("osec-installer") && name.ends_with(".sh") {
                        log_info!("[agent_manager] 找到升级脚本: {:?}", path);
                        return Some(path);
                    }
                }
            }
            log_info!("[agent_manager] 在 {} 中未找到 osec-upgrade*.sh 脚本", dir);
            None
        }
        Err(e) => {
            log_error!("[agent_manager] 读取升级目录 {} 失败: {}", dir, e);
            None
        }
    }
}

async fn uninstall_all() {
    log_info!("[agent_manager] 开始执行完整卸载流程...");

    let has_service = Command::new("which")
        .arg("service")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    // 停止 osec 服务
    if has_service {
        let _ = Command::new("service").args(["osec", "stop"]).status().await;
        if fs::remove_file("/etc/init.d/osec").is_ok() {
            log_info!("[agent_manager] 已删除 /etc/init.d/osec");
        }
        if fs::remove_file("/opt/osec/osec.monitor").is_ok() {
            log_info!("[agent_manager] 已删除 /opt/osec/osec.monitor");
        }
        let _ = Command::new("chkconfig").args(["--del", "osec"]).status().await;
    } else {
        let _ = Command::new("pkill").arg("-f").arg("osecmonitor").status().await;
    }

    // 停止 agent_manager 自身服务
    if has_service {
        let _ = Command::new("service").args(["agent_manager", "stop"]).status().await;
        if fs::remove_file("/etc/init.d/agent_manager").is_ok() {
            log_info!("[agent_manager] 已删除 /etc/init.d/agent_manager");
        }
        if fs::remove_file("/opt/osec/agent_manager.monitor").is_ok() {
            log_info!("[agent_manager] 已删除 /opt/osec/agent_manager.monitor");
        }
        let _ = Command::new("chkconfig").args(["--del", "agent_manager"]).status().await;
    }

    // 删除 PID 文件
    let _ = fs::remove_file("/var/run/osec_backend.pid");
    let _ = fs::remove_file("/var/run/agent_manager.pid");
    let _ = fs::remove_file("/var/run/osec.pid");
    let _ = fs::remove_file("/var/run/agent_manager.pid");
    let _ = fs::remove_file("/var/run/osec_monitor.pid");
    let _ = fs::remove_file("/var/run/agent_manager_monitor.pid");

    log_info!("[agent_manager] 检查并卸载 osec_base 模块");
    let modinfo = Command::new("modinfo").arg("osec_base").output().await;
    if let Ok(out) = modinfo {
        if out.status.success() {
            let _ = Command::new("rmmod").arg("osec_base").status().await;
            if let Ok(text) = String::from_utf8(out.stdout) {
                for line in text.lines() {
                    if line.starts_with("filename:") {
                        let p = line.trim_start_matches("filename:").trim();
                        if fs::remove_file(p).is_ok() {
                            log_info!("[agent_manager] 已删除内核模块文件: {}", p);
                        }
                    }
                }
            }
        }
    }

    // 删除安装目录
    let install_path = "/opt/osec";
    if PathBuf::from(install_path).exists() {
        if Command::new("rm").args(["-rf", install_path]).status().await.is_ok() {
            log_info!("[agent_manager] 已删除安装目录: {}", install_path);
        } else {
            log_error!("[agent_manager] 删除 {} 失败", install_path);
        }
    } else {
        log_info!("[agent_manager] 安装目录 {} 不存在，跳过删除", install_path);
    }

    log_info!("[agent_manager] 所有卸载步骤已完成");
}

