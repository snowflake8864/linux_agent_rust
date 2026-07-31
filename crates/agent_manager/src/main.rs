// crates/agent_manager/src/main.rs
use std::io;
use tokio::sync::mpsc;

mod unix_socket_server;
mod manager;
mod common;

#[cfg(feature = "agent-cli")]
mod agent_cli_client;

#[cfg(feature = "agent-cli")]
mod agent_cli_server;

use logging::{log_info, log_error, CustomLogger};
use manager::{run_agent_manager, AgentCommand};

use std::fs;
use std::path::Path;

const PID_FILE: &str = "/var/run/agent_manager.pid";

fn pid_is_running(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

fn ensure_single_instance() {
    if Path::new(PID_FILE).exists() {
        if let Ok(content) = fs::read_to_string(PID_FILE) {
            if let Ok(old_pid) = content.trim().parse::<u32>() {
                if pid_is_running(old_pid) {
                    eprintln!("❌ osec_backend 已在运行 (PID={})！", old_pid);
                    std::process::exit(1);
                }
            }
        }
    }

    let current_pid = std::process::id();
    if let Err(e) = fs::write(PID_FILE, current_pid.to_string()) {
        eprintln!("⚠ 无法写入 PID 文件: {}", e);
    }

    println!("✔ 单实例检查通过，当前 PID={}", current_pid);
}

#[tokio::main]
async fn main() -> io::Result<()> {
    ensure_single_instance();

    let args: Vec<String> = std::env::args().collect();
    let mode = if args.len() < 2 {
        "client".to_string()
    } else {
        args[1].clone()
    };

    let conf_path = match mode.as_str() {
        "server" => "./agent_backend.conf",
        "client" => "/opt/osec/agent_backend.conf",
        _ => "/opt/osec/agent_backend.conf",
    };

    CustomLogger::init(conf_path)
        .await
        .unwrap_or_else(|_| panic!("日志初始化失败: {}", conf_path));

    log_info!("程序开始启动=========");

    // 清理上次升级残留（升级脚本可能 restart agent_manager，导致末尾清理未执行）
    if fs::remove_dir_all("/tmp/osec_update").is_ok() {
        log_info!("[agent_manager] 启动时清理残留目录: /tmp/osec_update");
    }

    let (cmd_tx, cmd_rx) = mpsc::channel::<AgentCommand>(16);
    tokio::spawn(unix_socket_server::start_unix_socket_server(
        "/tmp/osec_agent.sock",
        cmd_tx.clone(),
    ));

    #[cfg(feature = "agent-cli")]
    match mode.as_str() {
        "server" => {
            log_info!("启动 Agent 服务器模式 (后台运行)");
            let port = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10448);
            tokio::spawn(async move {
                if let Err(e) = agent_cli_server::start_server(port).await {
                    log_error!("Agent server 崩溃: {}", e);
                }
            });
        }
        "client" => {
            log_info!("启动 Agent 客户端模式 (后台运行)");
            tokio::spawn(async move {
                if let Err(e) = agent_cli_client::start_client().await {
                    log_error!("Agent client 崩溃: {}", e);
                }
            });
        }
        _ => {
            log_info!("无效模式");
        }
    }

    #[cfg(not(feature = "agent-cli"))]
    {
        if mode == "server" || mode == "client" {
            log_info!("⚠ agent-cli 功能已禁用，client/server 模式被忽略");
        }
    }

    log_info!("启动主管理循环 run_agent_manager");
    run_agent_manager(cmd_rx).await;

    Ok(())
}
