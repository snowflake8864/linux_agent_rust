// crates/agent_manager/src/main.rs
use std::io;
use tokio::sync::mpsc;

mod unix_socket_server;
mod manager;
mod common;
mod agent_cli_client;
mod agent_cli_server;

use logging::{log_info, log_error, CustomLogger};
use manager::{run_agent_manager, AgentCommand};

use scopeguard; 

const SINGLETON_SOCKET_PATH: &str = "/tmp/agent_manager_singleton.sock";

async fn ensure_single_instance_async() -> io::Result<()> {
    use tokio::net::UnixStream;
    use std::time::Duration;

    if std::path::Path::new(SINGLETON_SOCKET_PATH).exists() {
        // 尝试连接，带超时
        match tokio::time::timeout(
            Duration::from_millis(100),
            UnixStream::connect(SINGLETON_SOCKET_PATH)
        ).await {
            Ok(Ok(_)) => {
                eprintln!("【错误】osec_backend 已经在运行！另一个实例占用了单实例锁。");
                std::process::exit(1);
            }
            Ok(Err(_)) | Err(_) => {
                let _ = tokio::fs::remove_file(SINGLETON_SOCKET_PATH).await;
            }
        }
    }

    if let Err(e) = tokio::net::UnixListener::bind(SINGLETON_SOCKET_PATH) {
        eprintln!("【错误】无法绑定单实例 socket: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
#[tokio::main]
async fn main() -> io::Result<()> {
    // ==================== 单实例锁 ====================
    ensure_single_instance_async().await.unwrap();


    scopeguard::defer! {
        let _ = std::fs::remove_file(SINGLETON_SOCKET_PATH);
    }

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
    match mode.as_str() {
        "server" => {
            log_info!("启动 Agent 服务器模式 (后台运行)");
            let port = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10448);
            // 关键：spawn 出去，不要 .await！
            tokio::spawn(async move {
                if let Err(e) = agent_cli_server::start_server(port).await {
                    log_error!("Agent server 崩溃: {}", e);
                }
            });
        }
        "client" => {
            log_info!("启动 Agent 客户端模式 (后台运行)");
            // 同样 spawn 出去
            tokio::spawn(async move {
                if let Err(e) = agent_cli_client::start_client().await {
                    log_error!("Agent client 崩溃: {}", e);
                }
            });
        }
        _ => {
            log_info!("无效模式");
            return Ok(());
        }
    }

    log_info!("启动主管理循环 run_agent_manager");
    run_agent_manager(cmd_rx).await;

    Ok(())
}
