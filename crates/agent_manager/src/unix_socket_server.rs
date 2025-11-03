//crates/agent_manager/src/unix_socket_server.rs
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use std::path::Path;
use logging::log_info;

use crate::manager::AgentCommand;   

pub async fn start_unix_socket_server(
    socket_path: &str,
    cmd_tx: mpsc::Sender<AgentCommand>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if Path::new(socket_path).exists() {
        std::fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    log_info!("[agent_manager] Listening on {}", socket_path);

    loop {
        let (stream, _) = listener.accept().await?;
        let tx = cmd_tx.clone();
        tokio::spawn(async move {
            let _ = handle_client(stream, tx).await;
        });
    }
}

async fn handle_client(
    stream: UnixStream,
    cmd_tx: mpsc::Sender<AgentCommand>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    log_info!("cmd line[{}]",line);
    match line.trim() {
        "update" => cmd_tx.send(AgentCommand::Update).await?,
        "uninstall" => cmd_tx.send(AgentCommand::Uninstall).await?,
        other => cmd_tx.send(AgentCommand::Unknown(other.to_string())).await?,
    }

    Ok(())
}

