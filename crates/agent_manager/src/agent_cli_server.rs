// crates/agent_manager/src/agent_cli_server.rs
use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::HashMap;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, AsyncBufReadExt, BufReader};
use logging::{log_info, log_plain,log_mod};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use rustls::{ServerConfig, pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer}};
use rustls_pemfile;
use std::fs::File;
use std::io::BufReader as StdBufReader;
use std::path::{Path, PathBuf};
use tokio::io::{ReadHalf, WriteHalf};
use crate::common::{FILE_START_MARKER, FILE_END_MARKER, BUFFER_SIZE};
use tokio::task::AbortHandle;

type ClientId = usize;

#[derive(Debug)]
struct ClientInfo {
    id: ClientId,
    uid: Option<String>,
    addr: std::net::SocketAddr,
    writer: Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>,
    abort_handle: AbortHandle, // 用于中止后台任务
}

type ClientsState = Arc<Mutex<HashMap<ClientId, ClientInfo>>>;
type CurrentState = Arc<Mutex<Option<ClientId>>>;

const HISTORY_SIZE: usize = 50;

pub async fn start_server(port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tls_cfg = load_tls_config("certs/cert.pem", "certs/cert.key.pem")?;
    let acceptor = TlsAcceptor::from(tls_cfg);
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    log_info!("Server listening on 0.0.0.0:{}", port);
    log_mod!("agent_server","Server listening on 0.0.0.0:{}", port);

    let clients: ClientsState = Arc::new(Mutex::new(HashMap::new()));
    let current: CurrentState = Arc::new(Mutex::new(None));
    let next_id: Arc<Mutex<ClientId>> = Arc::new(Mutex::new(0));
    let history: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    print_help();
    print_prompt(&current, &clients).await;

    let mut console_input = io::BufReader::new(io::stdin()).lines();

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((tcp, addr)) => {
                        let acceptor = acceptor.clone();
                        let clients = clients.clone();
                        let current = current.clone();
                        let next_id = next_id.clone();

                        let client_id = {
                            let mut id_guard = next_id.lock().await;
                            let id = *id_guard;
                            *id_guard += 1;
                            id
                        };

                        log_info!("New client incoming from {} assigned id {}", addr, client_id);

                        tokio::spawn(async move {
                            match acceptor.accept(tcp).await {
                                Ok(stream) => {
                                    let (reader, writer) = tokio::io::split(stream);
                                    let writer = Arc::new(Mutex::new(writer));

                                    // 启动读任务
                                    let read_task = tokio::spawn({
                                        let clients = clients.clone();
                                        let current = current.clone();
                                        async move {
                                            client_read_loop(client_id, reader, clients, current).await;
                                        }
                                    });

                                    let abort_handle = read_task.abort_handle();

                                    // 保存客户端信息
                                    {
                                        let mut guard = clients.lock().await;
                                        guard.insert(client_id, ClientInfo {
                                            id: client_id,
                                            uid: None,
                                            addr,
                                            writer: writer.clone(),
                                            abort_handle,
                                        });
                                    }
                                }
                                Err(e) => {
                                    log_info!("TLS accept error: {}", e);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        log_info!("Accept error: {}", e);
                    }
                }
            }

            line_result = console_input.next_line() => {
                match line_result {
                    Ok(Some(line)) => {
                        let cmd = line
                            .trim()
                            .trim_end_matches('\r')
                            .chars()
                            .filter(|c| c.is_ascii() && !c.is_ascii_control())
                            .collect::<String>();

                        if !cmd.is_empty() {
                            // 保存历史
                            {
                                let mut hist = history.lock().await;
                                if hist.len() >= HISTORY_SIZE {
                                    hist.remove(0);
                                }
                                hist.push(cmd.clone());
                            }

                            let clients_for_console = clients.clone();
                            let current_for_console = current.clone();
                            let history_for_console = history.clone();

                            tokio::spawn(async move {
                                handle_console(&cmd, clients_for_console, current_for_console, Some(history_for_console)).await;
                            });
                        } else {
                            print_prompt(&current, &clients).await;
                        }
                    }
                    Ok(None) => return Ok(()),
                    Err(e) => return Err(Box::new(e)),
                }
            }
        }
    }
}

async fn client_read_loop(
    client_id: ClientId,
    mut reader: ReadHalf<TlsStream<TcpStream>>,
    clients: ClientsState,
    current: CurrentState,
) {
    let mut buf = vec![0u8; BUFFER_SIZE];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                log_info!("read error client {}: {}", client_id, e);
                break;
            }
        };

        let data = String::from_utf8_lossy(&buf[..n]).to_string();
        let (maybe_uid, addr) = {
            let guard = clients.lock().await;
            if let Some(ci) = guard.get(&client_id) {
                (ci.uid.clone(), ci.addr)
            } else {
                (None, "0.0.0.0:0".parse().unwrap())
            }
        };

        if data.starts_with("I am agent client, my uid is ") {
            if let Some(pos) = data.find("uid is ") {
                let new_uid = data[pos + 7..].trim().to_string();
                {
                    let mut guard = clients.lock().await;
                    if let Some(ci) = guard.get_mut(&client_id) {
                        ci.uid = Some(new_uid.clone());
                    }
                }
                {
                    let mut cur = current.lock().await;
                    if cur.is_none() {
                        *cur = Some(client_id);
                        log_info!("Auto-selected client id {} (UID: {})", client_id, new_uid);
                    }
                }
                let writer = {
                    let guard = clients.lock().await;
                    guard.get(&client_id).map(|ci| ci.writer.clone())
                };
                if let Some(w) = writer {
                    let mut wlock = w.lock().await;
                    let _ = wlock.write_all(format!("hello, {}\n", new_uid).as_bytes()).await;
                    let _ = wlock.flush().await;
                }
                log_info!("Client connected: {} from {}", new_uid, addr);
            }
        } else if data.trim() == "heartbeat" {
            continue;
        } else if data.contains(FILE_START_MARKER) {
            if let Some(start_idx) = data.find(FILE_START_MARKER) {
                let leftover = data[start_idx..].as_bytes().to_vec();
                if let Err(e) = receive_file_from_reader(leftover, &mut reader).await {
                    log_info!("receive_file error from client {}: {}", client_id, e);
                }
            } else {
                log_info!("Received unexpected file marker for client {}", client_id);
            }
        } else {
            log_info!("{}: {}", maybe_uid.as_deref().unwrap_or("?"), data.trim_end());
            print_current_prompt(&current, &clients).await;
        }
    }

    {
        let mut guard = clients.lock().await;
        if let Some(client) = guard.remove(&client_id) {
            log_info!("Client id {} disconnected from {}", client_id, client.addr);

            client.abort_handle.abort();

            if let Ok(mut writer) = client.writer.try_lock() {
                let _ = writer.shutdown().await;
            }
        }
    }

    // 取消当前选中
    {
        let mut cur = current.lock().await;
        if cur.map(|v| v == client_id).unwrap_or(false) {
            *cur = None;
            print_prompt(&current, &clients).await;
        }
    }
}

async fn receive_file_from_reader(
    leftover: Vec<u8>,
    reader: &mut ReadHalf<TlsStream<TcpStream>>,
) -> Result<(), String> {
    let s = match std::str::from_utf8(&leftover) {
        Ok(s) => s.to_string(),
        Err(_) => return Err("invalid utf8 in leftover".to_string()),
    };
    let rest = s.strip_prefix(FILE_START_MARKER).ok_or("bad marker")?;
    let (size_str, path) = rest.split_once(':').ok_or("bad format")?;
    let size: u64 = size_str.parse().map_err(|_| "bad size")?;
    let path = path.trim().to_string();
    let final_path = Path::new(&path).to_path_buf();

    if let Some(parent) = final_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| e.to_string())?;
    }
    let mut file = tokio::fs::File::create(&final_path).await.map_err(|e| e.to_string())?;

    let header_bytes = format!("{}{}:{}", FILE_START_MARKER, size_str, path);
    let header_len = header_bytes.as_bytes().len();

    if leftover.len() > header_len {
        let payload_part = &leftover[header_len..];
        let to_write = std::cmp::min(payload_part.len() as u64, size) as usize;
        if to_write > 0 {
            file.write_all(&payload_part[..to_write]).await.map_err(|e| e.to_string())?;
        }
        let mut received = to_write as u64;
        let mut buf = vec![0u8; BUFFER_SIZE];
        while received < size {
            let need = std::cmp::min(BUFFER_SIZE as u64, size - received) as usize;
            let n = reader.read(&mut buf[..need]).await.map_err(|e| e.to_string())?;
            if n == 0 { break; }
            file.write_all(&buf[..n]).await.map_err(|e| e.to_string())?;
            received += n as u64;
        }
        let mut end_marker = vec![0u8; FILE_END_MARKER.len()];
        reader.read_exact(&mut end_marker).await.map_err(|e| e.to_string())?;
        let end_str = std::str::from_utf8(&end_marker).map_err(|_| "invalid end marker")?;
        if end_str == FILE_END_MARKER {
            log_info!("Received file {} ({} bytes)", final_path.display(), size);
            Ok(())
        } else {
            Err(format!("end marker mismatch: got {:?}", end_str))
        }
    } else {
        let mut received = 0u64;
        let mut buf = vec![0u8; BUFFER_SIZE];
        while received < size {
            let need = std::cmp::min(BUFFER_SIZE as u64, size - received) as usize;
            let n = reader.read(&mut buf[..need]).await.map_err(|e| e.to_string())?;
            if n == 0 { break; }
            file.write_all(&buf[..n]).await.map_err(|e| e.to_string())?;
            received += n as u64;
        }
        let mut end_marker = vec![0u8; FILE_END_MARKER.len()];
        reader.read_exact(&mut end_marker).await.map_err(|e| e.to_string())?;
        let end_str = std::str::from_utf8(&end_marker).map_err(|_| "invalid end marker")?;
        if end_str == FILE_END_MARKER {
            log_info!("Received file {} ({} bytes)", final_path.display(), size);
            Ok(())
        } else {
            Err(format!("end marker mismatch: got {:?}", end_str))
        }
    }
}

async fn handle_console(
    cmd: &str,
    clients: ClientsState,
    current: CurrentState,
    history: Option<Arc<Mutex<Vec<String>>>>,
) {
    let clean_cmd: String = cmd
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .collect();

    // 解析历史命令 !!

    let cmd_to_run = if clean_cmd == "!!" {
        if let Some(ref hist) = history {
            let hist_guard = hist.lock().await;
            if let Some(last_cmd) = hist_guard.iter().rev().find(|c| **c != "!!") {
                last_cmd.clone()
            } else {
                log_info!("No previous command in history");
                print_prompt(&current, &clients).await;
                return;
            }
        } else {
            log_info!("No history available");
            print_prompt(&current, &clients).await;
            return;
        }
    } else if clean_cmd.starts_with('!') {
        if let Ok(idx) = clean_cmd[1..].parse::<usize>() {
            if let Some(ref hist) = history {
                let hist_guard = hist.lock().await;
                if idx > 0 && idx <= hist_guard.len() {
                    hist_guard[idx - 1].clone()
                } else {
                    log_info!("History index out of range: {}", idx);
                    print_prompt(&current, &clients).await;
                    return;
                }
            } else {
                log_info!("No history available");
                print_prompt(&current, &clients).await;
                return;
            }
        } else {
            clean_cmd.clone()
        }
    } else {
        clean_cmd.clone()
    };
    // 保存历史：存解析后的真实命令
    if let Some(ref hist) = history {
        let mut hist_guard = hist.lock().await;
        if hist_guard.len() >= HISTORY_SIZE {
            hist_guard.remove(0);
        }
        hist_guard.push(cmd_to_run.clone());
    }

    let parts: Vec<&str> = cmd_to_run.split_whitespace().collect();

    match parts.as_slice() {
        ["history"] => {
            if let Some(ref hist) = history {
                let hist_guard = hist.lock().await;
                if hist_guard.is_empty() {
                    log_info!("No command history");
                } else {
                    log_info!("Command History:");
                    for (i, cmd) in hist_guard.iter().enumerate() {
                        log_info!(" {}: {}", i + 1, cmd);
                    }
                }
            }
        }
        ["set", "uid", id_str] => {
            if let Ok(client_id) = id_str.parse::<ClientId>() {
                let clients_guard = clients.lock().await;
                if let Some(client) = clients_guard.get(&client_id) {
                    if let Some(ref uid) = client.uid {
                        log_info!("Set UID for client {}: {}", client_id, uid);
                        let mut cur = current.lock().await;
                        if cur.is_none() {
                            *cur = Some(client_id);
                        }
                    } else {
                        log_info!("Client {} has no UID yet", client_id);
                    }
                } else {
                    log_info!("No client with id {}", client_id);
                }
            } else {
                log_info!("Invalid client id: {}", id_str);
            }
        }
        ["set", "uid", id_str, new_uid] => {
            if let Ok(client_id) = id_str.parse::<ClientId>() {
                let mut clients_guard = clients.lock().await;
                if let Some(client) = clients_guard.get_mut(&client_id) {
                    client.uid = Some(new_uid.to_string());
                    log_info!("Set UID for client {}: {}", client_id, new_uid);
                    let mut cur = current.lock().await;
                    if cur.is_none() {
                        *cur = Some(client_id);
                    }
                } else {
                    log_info!("No client with id {}", client_id);
                }
            } else {
                log_info!("Invalid client id: {}", id_str);
            }
        }
        ["list"] => {
            let snapshot = {
                let clients_guard = clients.lock().await;
                let current_id = *current.lock().await;
                clients_guard
                    .values()
                    .map(|c| {
                        let marker = if Some(c.id) == current_id { ">" } else { " " };
                        let uid = c.uid.clone().unwrap_or_else(|| "not set".to_string());
                        (marker, c.id, uid, c.addr)
                    })
                    .collect::<Vec<_>>()
            };
            log_info!("Connected Clients:");
            for (marker, id, uid, addr) in snapshot {
                log_info!("{} [{}] {} @ {}", marker, id, uid, addr);
            }
        }
        ["select", target] | ["use", target] => {
            let mut clients_guard = clients.lock().await;
            let mut current_lock = current.lock().await;
            if let Ok(id) = target.parse::<ClientId>() {
                if clients_guard.contains_key(&id) {
                    *current_lock = Some(id);
                    let uid_display = clients_guard.get(&id).and_then(|c| c.uid.clone()).unwrap_or_default();
                    log_info!("Selected client id {} (UID: {})", id, uid_display);
                } else {
                    log_info!("No client with id {}", id);
                }
            } else if let Some(client) = clients_guard.values().find(|c| c.uid.as_deref() == Some(target)) {
                *current_lock = Some(client.id);
                log_info!("Selected client UID {}", target);
            } else {
                log_info!("No client found");
            }
        }
        ["send_file", src, dst] => {
            let current_id = *current.lock().await;
            if let Some(client_id) = current_id {
                let writer_opt = { clients.lock().await.get(&client_id).map(|ci| ci.writer.clone()) };
                if let Some(writer) = writer_opt {
                    if let Err(e) = send_file_to_client_with_writer(writer, src, dst).await {
                        log_info!("send_file error: {}", e);
                    }
                } else {
                    log_info!("Client disconnected");
                }
            } else {
                log_info!("No client selected");
            }
        }
        ["get_file", src, dst] => {
            let (client_id_opt, uid) = {
                let guard = clients.lock().await;
                let current_id = *current.lock().await;
                if let Some(id) = current_id {
                    if let Some(client) = guard.get(&id) {
                        (Some(id), client.uid.clone().unwrap_or_default())
                    } else { (None, String::new()) }
                } else { (None, String::new()) }
            };
            if let Some(id) = client_id_opt {
                let cmd_str = format!("uid:{} get_file {} {}", uid, src, dst);
                let writer_opt = { clients.lock().await.get(&id).map(|ci| ci.writer.clone()) };
                if let Some(writer) = writer_opt {
                    let mut wlock = writer.lock().await;
                    if wlock.write_all(cmd_str.as_bytes()).await.is_err() {
                        clients.lock().await.remove(&id);
                        log_info!("Client {} disconnected during get_file", id);
                    } else {
                        let _ = wlock.flush().await;
                        log_info!("Sent get_file command to {}", uid);
                    }
                }
            } else {
                log_info!("No client selected");
            }
        }
        ["rkill"] => {
            let (client_id_opt, uid) = {
                let guard = clients.lock().await;
                let current_id = *current.lock().await;
                if let Some(id) = current_id {
                    if let Some(client) = guard.get(&id) {
                        (Some(id), client.uid.clone().unwrap_or_default())
                    } else { (None, String::new()) }
                } else { (None, String::new()) }
            };
            if let Some(id) = client_id_opt {
                let cmd_str = format!("uid:{} rkill", uid);
                let writer_opt = { clients.lock().await.get(&id).map(|ci| ci.writer.clone()) };
                if let Some(writer) = writer_opt {
                    let mut wlock = writer.lock().await;
                    if wlock.write_all(cmd_str.as_bytes()).await.is_err() {
                        clients.lock().await.remove(&id);
                        log_info!("Client {} disconnected during rkill command", id);
                    } else {
                        let _ = wlock.flush().await;
                        log_info!("Sent rkill command to {}", uid);
                    }
                }
            } else {
                log_info!("No client selected");
            }
        }
        ["exit"] => {
            if current.lock().await.is_none() {
                std::process::exit(0);
            } else {
                log_info!("Cannot exit: client is selected. Use 'select' to deselect.");
            }
        }

        ["help"] => print_help(),
        _ => {
            let (client_id_opt, uid) = {
                let guard = clients.lock().await;
                let current_id = *current.lock().await;
                if let Some(id) = current_id {
                    if let Some(client) = guard.get(&id) {
                        (Some(id), client.uid.clone().unwrap_or_default())
                    } else { (None, String::new()) }
                } else { (None, String::new()) }
            };
            if let Some(id) = client_id_opt {
                let full = format!("uid:{} {}", uid, cmd_to_run);
                let writer_opt = { clients.lock().await.get(&id).map(|ci| ci.writer.clone()) };
                if let Some(writer) = writer_opt {
                    let mut wlock = writer.lock().await;
                    log_info!("cmd:{}", full);
                    if wlock.write_all(full.as_bytes()).await.is_err() {
                        clients.lock().await.remove(&id);
                        log_info!("Client {} disconnected during command", id);
                    } else {
                        let _ = wlock.flush().await;
                    }
                }
            } else {
                log_info!("No client selected. Use 'select <id|uid>' or 'set uid <id>'");
            }
        }
    }

    print_prompt(&current, &clients).await;
}


async fn send_file_to_client_with_writer(
    writer: Arc<Mutex<WriteHalf<TlsStream<TcpStream>>>>,
    src: &str,
    dst: &str,
) -> Result<(), String> {
    let meta = tokio::fs::metadata(src).await.map_err(|e| e.to_string())?;
    if !meta.is_file() {
        log_info!("'{}' is not a file", src);
        return Ok(());
    }
    let size = meta.len();
    let dst_path = Path::new(dst);
    let final_dst = if tokio::fs::metadata(&dst_path).await.is_ok() {
        let dst_meta = tokio::fs::metadata(&dst_path).await.map_err(|e| e.to_string())?;
        if dst_meta.is_dir() {
            let src_filename = Path::new(src)
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or("无法获取源文件名")?;
            dst_path.join(src_filename)
        } else {
            dst_path.to_path_buf()
        }
    } else {
        dst_path.to_path_buf()
    };

    let header = format!("{}{}:{}", FILE_START_MARKER, size, final_dst.to_string_lossy());
    let mut file = tokio::fs::File::open(src).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; BUFFER_SIZE];
    let mut w = writer.lock().await;

    if w.write_all(header.as_bytes()).await.is_err() {
        return Err("write header failed".to_string());
    }

    let mut sent = 0u64;
    while sent < size {
        let n = file.read(&mut buf).await.map_err(|e| e.to_string())?;
        if n == 0 { break; }
        if w.write_all(&buf[..n]).await.is_err() {
            return Err("write payload failed".to_string());
        }
        sent += n as u64;
    }
    if w.write_all(FILE_END_MARKER.as_bytes()).await.is_err() {
        return Err("write end marker failed".to_string());
    }
    let _ = w.flush().await;
    log_info!("Sent {} -> {}", src, final_dst.display());
    Ok(())
}

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>, String> {
    let mut cert_reader = StdBufReader::new(File::open(cert_path).map_err(|e| e.to_string())?);
    let mut certs = Vec::new();
    for c in rustls_pemfile::certs(&mut cert_reader) {
        certs.push(CertificateDer::from(c.map_err(|e| e.to_string())?.into_owned()));
    }
    let mut key_reader = StdBufReader::new(File::open(key_path).map_err(|e| e.to_string())?);
    let key = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .next().ok_or("no key")?
        .map_err(|e| e.to_string())?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key));
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    Ok(Arc::new(cfg))
}

fn print_help() {
    log_plain!("=== Agent CLI Server Commands ===");
    log_plain!("");
    log_plain!("Client Management:");
    log_plain!("  list                            - List all connected clients");
    log_plain!("  select <id> | <uid>             - Switch to a specific client (alias: use)");
    log_plain!("  set uid <id>                    - Show or confirm UID of a client (does not switch)");
    log_plain!("  set uid <id> <uid>              - Manually assign a UID to a client");
    log_plain!("");
    log_plain!("File Transfer:");
    log_plain!("  send_file <local_path> <remote_path> - Upload a file to the selected client");
    log_plain!("  get_file <remote_path> <local_path>  - Download a file from the selected client");
    log_plain!("");
    log_plain!("Remote Commands:");
    log_plain!("  <any shell command>             - Execute command on the selected client");
    log_plain!("  rkill                           - Send a remote kill signal (e.g., terminate agent)");
    log_plain!("");
    log_plain!("History & Navigation:");
    log_plain!("  history                         - Show command history (last {} entries)", HISTORY_SIZE);
    log_plain!("  !!                              - Re-execute the last non-history command");
    log_plain!("");
    log_plain!("Miscellaneous:");
    log_plain!("  help                            - Show this help message");
    log_plain!("  exit                            - Exit server (only allowed when no client is selected)");
    log_plain!("");
    log_plain!("Notes:");
    log_plain!("- You must 'select' a client before sending commands or transferring files.");
    log_plain!("- The '!!' command skips other history-related commands (like '!!' itself).");
    log_plain!("- File paths with spaces must be handled by the underlying shell on the client side.");
}

async fn print_prompt(current: &CurrentState, clients: &ClientsState) {
    let current_id = *current.lock().await;
    let prompt = if let Some(id) = current_id {
        let clients_guard = clients.lock().await;
        if let Some(client) = clients_guard.get(&id) {
            client.uid.as_deref().unwrap_or("?").to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    print!("{}> ", prompt);
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

async fn print_current_prompt(current: &CurrentState, clients: &ClientsState) {
    print_prompt(current, clients).await;
}
