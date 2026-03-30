// crates/agent_manager/src/main.rs
use std::io;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use tokio::sync::mpsc;
use clap::Parser;

mod unix_socket_server;
mod manager;
mod common;

#[cfg(feature = "agent-cli")]
mod agent_cli_client;

#[cfg(feature = "agent-cli")]
mod agent_cli_server;

use logging::{log_info, log_error, log_warn, CustomLogger};
use manager::{run_agent_manager, AgentCommand};
use chrono::Local;

use std::fs;
use std::path::Path;

const PID_FILE: &str = "/var/run/agent_manager.pid";

#[derive(Parser, Debug)]
#[command(name = "MagicArmorAgent")]
#[command(version = "0.1.0")]
#[command(about = "Agent Manager Service", long_about = None)]
struct Args {
    #[arg(short, long, help = "Run in background (daemon mode)")]
    daemon: bool,
}

fn daemonize() {
    unsafe {
        use libc::{fork, setsid, dup2};
        
        if fork() != 0 {
            std::process::exit(0);
        }
        
        if setsid() == -1 {
            eprintln!("Failed to create new session");
            std::process::exit(1);
        }
        
        if fork() != 0 {
            std::process::exit(0);
        }
        
        let devnull = std::fs::OpenOptions::new()
            .write(true)
            .read(true)
            .open("/dev/null")
            .expect("Cannot open /dev/null");
        
        let _ = dup2(devnull.as_raw_fd(), 0);
        let _ = dup2(devnull.as_raw_fd(), 1);
        let _ = dup2(devnull.as_raw_fd(), 2);
    }
    
    let log_dir = "/var/log/osec";
    let _ = std::fs::create_dir_all(log_dir);
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("{}/agent_manager.log", log_dir))
        .ok();
    
    if let Some(mut f) = log_file {
        let _ = writeln!(f, "[{}] agent_manager started in daemon mode", Local::now().format("%Y-%m-%d %H:%M:%S"));
    }
}

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
    let args = Args::parse();
    
    if args.daemon {
        daemonize();
    }
    
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
    
    tokio::select! {
        _ = run_agent_manager(cmd_rx) => {},
        _ = shutdown_signal() => {
            log_info!("收到退出信号");
        },
    }

    Ok(())
}

fn is_self_protected() -> bool {
    if let Ok(content) = std::fs::read_to_string("/proc/osec/self") {
        content.contains("system is in self protect")
    } else {
        false
    }
}

async fn shutdown_signal() {
    let protected = is_self_protected();
    
    if protected {
        log_warn!("内核驱动已加载，进程处于保护模式，无法被 kill");
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        }
    }

    let mut sigint = unix_signal(SignalKind::interrupt()).expect("注册 SIGINT 失败");
    let mut sigterm = unix_signal(SignalKind::terminate()).expect("注册 SIGTERM 失败");

    tokio::select! {
        _ = sigint.recv() => log_info!("收到 SIGINT (Ctrl+C)"),
        _ = sigterm.recv() => log_info!("收到 SIGTERM"),
    }
}
