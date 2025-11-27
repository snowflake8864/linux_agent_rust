// crates/agent_manager/src/agent_cli_client.rs
use crate::common::*;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, AsyncBufReadExt};
use logging::{log_info, log_error};
use tokio_rustls::TlsConnector;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use tokio::time::{timeout, Duration};
use std::path::Path;
use std::process::Stdio;
use chrono::{Utc, Datelike};
use std::fs;
use std::io::{Read, Write};
use tokio::process::Command;

pub async fn start_client() -> Result<(), String> {
    if acquire_lock().is_err() {
        return Err("Failed to acquire single-instance lock".into());
    }

    let mut last_cfg: Option<ClientConfigData> = None;
    loop {
        match parse_ini_file(INI_FILE) {
            Ok(cfg) => {
                let need_restart = match &last_cfg {
                    None => true,
                    Some(old) => cfg.port != old.port || cfg.dev_uid != old.dev_uid || cfg.server_ip != old.server_ip,
                };
                if need_restart && cfg.port != 0 {
                    tokio::spawn(run_session(cfg.clone()));
                }
                last_cfg = Some(cfg);
            }
            Err(e) => log_error!("INI error: {}", e),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn run_session(cfg: ClientConfigData) {
    loop {
        log_info!("Attempting to connect to server {}:{}", cfg.server_ip, cfg.port);
        match connect_and_auth(&cfg).await {
            Ok(stream) => {
                log_info!("Session started");
                match handle_session(stream, &cfg).await {
                    Ok(()) => log_info!("Session ended normally"),
                    Err(e) => log_error!("Session error: {}", e),
                }
            }
            Err(e) => {
                log_error!("Connection failed: {}", e);
            }
        }
        log_info!("Retrying connection in 5 seconds...");
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn connect_and_auth(cfg: &ClientConfigData) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let tcp = TcpStream::connect(format!("{}:{}", cfg.server_ip, cfg.port))
        .await.map_err(|e| e.to_string())?;
    let connector = make_tls_connector()?;
    let server_name = rustls::pki_types::ServerName::try_from(cfg.server_ip.as_str())
        .map_err(|_| "Invalid IP address")?.to_owned();
    let stream = connector.connect(server_name, tcp).await.map_err(|e| e.to_string())?;
    let mut stream = stream;

    let uid_msg = format!("I am agent client, my uid is {}\n", cfg.dev_uid);
    stream.write_all(uid_msg.as_bytes()).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.map_err(|e| e.to_string())?;
    let expected = format!("hello, {}\n", cfg.dev_uid);
    if line != expected {
        return Err(format!("Authentication failed: received {:?}", line));
    }
    log_info!("Authentication successful: {}", cfg.dev_uid);

    Ok(stream)
}

fn make_tls_connector() -> Result<TlsConnector, String> {
    let mut root_store = RootCertStore::empty();
    let ca_pem = fs::read("/opt/osec/certs/root-ca.pem").map_err(|e| e.to_string())?;
    for cert in rustls_pemfile::certs(&mut std::io::Cursor::new(ca_pem)) {
        root_store.add(cert.map_err(|e| e.to_string())?.into_owned())
            .map_err(|e| e.to_string())?;
    }
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

async fn handle_session(
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    cfg: &ClientConfigData,
) -> Result<(), String> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buf = vec![0u8; BUFFER_SIZE];
    let mut last_heartbeat = std::time::Instant::now();

    loop {
        let timeout = Duration::from_secs(10);
        let result = tokio::time::timeout(timeout, reader.read(&mut buf)).await;

        match result {
            Ok(Ok(0)) => {
                log_info!("Server closed connection");
                break;
            }
            Ok(Ok(n)) => {
                last_heartbeat = std::time::Instant::now();
                let data = String::from_utf8_lossy(&buf[..n]);
                let lines: Vec<&str> = data.lines().collect();

                for line in lines {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    if trimmed.starts_with("uid:") {
                        if let Err(e) = process_command(&mut writer, trimmed, cfg).await {
                            if e == "exit" {
                                return Err("exit".to_string());
                            }
                            log_error!("Command processing error: {}", e);
                        }
                    } else if trimmed.starts_with(FILE_START_MARKER) {
                        if let Err(e) = receive_file(&mut reader, trimmed).await {
                            log_error!("File receive error: {}", e);
                        }
                    } else if trimmed == "heartbeat" {
                        // Ignore
                    } else {
                        log_info!("Unknown message: {:?}", trimmed);
                    }
                }
            }
            Ok(Err(e)) => {
                log_error!("Read error: {}", e);
                break;
            }
            Err(_) => {
                if last_heartbeat.elapsed() >= Duration::from_secs(10) {
                    if let Err(e) = writer.write_all(b"heartbeat\n").await {
                        log_error!("Failed to send heartbeat: {}", e);
                        break;
                    }
                    last_heartbeat = std::time::Instant::now();
                }
            }
        }
    }
    Ok(())
}

async fn read_all_with_timeout<R: AsyncReadExt + Unpin>(
    mut reader: R,
    timeout_duration: Duration,
) -> Result<Vec<u8>, ()> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];

    loop {
        let read_fut = reader.read(&mut chunk);
        match tokio::time::timeout(timeout_duration, read_fut).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buffer.extend_from_slice(&chunk[..n]),
            _ => break,
        }
    }
    Ok(buffer)
}

async fn write_proc_self() -> Result<(), String> {
    let now = Utc::now();
    let year = now.year() as u64;
    let month = now.month() as u64;
    let day = now.day() as u64;
    let date_num = year * 10000 + month * 100 + day;
    let incremented = date_num + 1;
    let inc_str = incremented.to_string();
    let inc_len = inc_str.len();

    let formatted = if inc_len == 8 {
        let y = &inc_str[0..4];
        let m = &inc_str[4..6];
        let d = &inc_str[6..8];
        let m_num: u64 = m.parse().unwrap();
        let d_num: u64 = d.parse().unwrap();
        format!("{}{}{}", y, m_num, d_num)
    } else if inc_len == 7 {
        let y = &inc_str[0..4];
        let rest: u64 = inc_str[4..].parse().unwrap();
        let m = rest / 100;
        let d = rest % 100;
        format!("{}{}{}", y, m, d)
    } else {
        inc_str
    };

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

async fn process_command<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    cmd: &str,
    cfg: &ClientConfigData,
) -> Result<(), String> {
    if !cmd.starts_with("uid:") {
        return Ok(());
    }

    let after_uid = &cmd[4..];
    let parts: Vec<&str> = after_uid.split_whitespace().collect();
    if parts.is_empty() {
        writer.write_all(b"Command error: missing UID\n").await.map_err(|e| e.to_string())?;
        return Ok(());
    }

    let uid = parts[0];
    if uid != cfg.dev_uid {
        return Ok(());
    }

    if parts.len() < 2 {
        writer.write_all(b"Command error: missing action\n").await.map_err(|e| e.to_string())?;
        return Ok(());
    }

    let action = parts[1];
    if action == "exit" {
        return Err("exit".into());
    }

    if action == "rkill" {
        log_info!("[agent_manager] === Received 'update' ===");
        if let Err(e) = write_proc_self().await {
            log_error!("[agent_manager] write_proc_self error: {}", e);
        } else {
            log_info!("[agent_manager] write_proc_self 成功");
        }

        log_info!("[agent_manager] 发送 SIGKILL 给残留的 MagicArmor_0");
        let _ = Command::new("pkill").arg("-9").arg("MagicArmor_0").status().await;

        return Ok(());
    }
    if action == "get_file" {
        if parts.len() < 4 {
            writer.write_all(b"get_file requires src and dst\n").await.map_err(|e| e.to_string())?;
            return Ok(());
        }
        let src = parts[2];
        let dst = parts[3];
        return send_file(writer, src, dst).await;
    }

    let shell_cmd = parts[1..].join(" ");
    log_info!("Executing command: {}", shell_cmd);

    let mut child = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(&shell_cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn process: {}", e))?;

    let stdout = child.stdout.take().ok_or("Failed to get stdout")?;
    let stderr = child.stderr.take().ok_or("Failed to get stderr")?;

    // 限制命令执行时间，比如 10 秒
    let exec_timeout = Duration::from_secs(10);

    // 同时读 stdout/stderr + 等待进程退出（都受超时保护）
    let run_result = timeout(exec_timeout, async {
        let (stdout_res, stderr_res) = tokio::join!(
            read_all_with_timeout(stdout, exec_timeout),
            read_all_with_timeout(stderr, exec_timeout)
        );

        let status = child.wait().await.ok();
        (stdout_res, stderr_res, status)
    })
    .await;

    match run_result {
        Ok((stdout_res, stderr_res, _status)) => {
            let stdout_data = stdout_res.unwrap_or_default();
            let stderr_data = stderr_res.unwrap_or_default();
            if !stdout_data.is_empty() {
                writer.write_all(&stdout_data).await.map_err(|e| e.to_string())?;
            }
            if !stderr_data.is_empty() {
                writer.write_all(&stderr_data).await.map_err(|e| e.to_string())?;
            }
            writer.write_all(b"\n").await.map_err(|e| e.to_string())?;
        }
        Err(_) => {
            // 超时 => 杀掉子进程
            let _ = child.kill().await;
            let _ = child.wait().await;
            writer.write_all(b"[WARN] Command timed out and was killed\n")
                .await.map_err(|e| e.to_string())?;
        }
    }

    Ok(())
}

async fn send_file<W: AsyncWriteExt + Unpin>(writer: &mut W, src: &str, dst: &str) -> Result<(), String> {
    let meta = tokio::fs::metadata(src).await.map_err(|e| e.to_string())?;
    if !meta.is_file() {
        writer.write_all(format!("Source path {} must be a file\n", src).as_bytes()).await.map_err(|e| e.to_string())?;
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
                .ok_or("invalid src filename")?;
            dst_path.join(src_filename)
        } else {
            dst_path.to_path_buf()
        }
    } else {
        dst_path.to_path_buf()
    };

    let header = format!("{}{}:{}\n", FILE_START_MARKER, size, final_dst.to_string_lossy());
    writer.write_all(header.as_bytes()).await.map_err(|e| e.to_string())?;

    let mut file = tokio::fs::File::open(src).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; BUFFER_SIZE];
    let mut sent = 0;
    while sent < size {
        let n = file.read(&mut buf).await.map_err(|e| e.to_string())?;
        if n == 0 { break; }
        writer.write_all(&buf[..n]).await.map_err(|e| e.to_string())?;
        sent += n as u64;
    }
    writer.write_all(FILE_END_MARKER.as_bytes()).await.map_err(|e| e.to_string())?;
    log_info!("文件 {} 已发送到 {}", src, final_dst.display());
    Ok(())
}

async fn receive_file<R: AsyncReadExt + Unpin>(reader: &mut R, header: &str) -> Result<(), String> {
    let rest = header.strip_prefix(FILE_START_MARKER).ok_or("bad marker")?;
    let (size_str, path) = rest.split_once(':').ok_or("bad format")?;
    let size: u64 = size_str.parse().map_err(|_| "bad size")?;

    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| e.to_string())?;
        }
    }

    let mut file = tokio::fs::File::create(path).await.map_err(|e| e.to_string())?;
    let mut received = 0;
    let mut buf = vec![0u8; BUFFER_SIZE];

    while received < size {
        let n = reader.read(&mut buf).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n]).await.map_err(|e| e.to_string())?;
        received += n as u64;
    }

    let mut end_marker = vec![0u8; FILE_END_MARKER.len()];
    reader.read_exact(&mut end_marker).await.map_err(|e| e.to_string())?;
    let end_str = std::str::from_utf8(&end_marker).map_err(|_| "invalid end marker")?;
    if end_str == FILE_END_MARKER {
        log_info!("File saved: {} ({} bytes)", path.display(), size);
    } else {
        log_error!("File end marker mismatch, expected {:?}, got {:?}", FILE_END_MARKER, end_str);
    }

    Ok(())
}
