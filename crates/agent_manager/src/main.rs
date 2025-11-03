//crates/agent_manager/src/main.rs
use std::io;
use tokio::sync::mpsc;

mod unix_socket_server;
mod manager;
use logging::{log_info, CustomLogger, log_error};
use unix_socket_server::start_unix_socket_server;
use manager::{run_agent_manager, AgentCommand};

#[tokio::main]
async fn main() -> io::Result<()> {

    // 初始化日志
    CustomLogger::init("/opt/osec/agent_backend.conf")
        .await
        .expect("无法初始化日志");
    log_info!("程序开始启动");

    let (cmd_tx, cmd_rx) = mpsc::channel::<AgentCommand>(16);

    let socket_path = "/tmp/osec_agent.sock";
    tokio::spawn(start_unix_socket_server(socket_path, cmd_tx.clone()));

    run_agent_manager(cmd_rx).await;

    Ok(())
}

