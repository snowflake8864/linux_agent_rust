// crates/virus_scan_grpc/src/vigilixav_scanner.rs
use logging::{log_error, log_info};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub enum VigilixAVConnection {
    Tcp { host: String, port: u16 },
    Unix { socket_path: String },
}

#[derive(Debug, Clone)]
pub enum ScanResult {
    Clean,
    Virus { name: String },
    Error { message: String },
}

#[derive(Debug, Clone)]
pub enum DispositionAction {
    /// 移动到隔离目录（由 vigilixd.conf 配置决定目标路径，客户端无需指定）
    Move,
    Remove,
}

#[derive(Debug, Clone)]
pub enum DispositionResult {
    Success { message: String },
    Error { message: String },
}

pub struct VigilixAVConnectionPool {
    connection_info: VigilixAVConnection,
    timeout: Duration,
    semaphore: tokio::sync::Semaphore,
    pool_size: usize,
    quarantine_dir: String,
}

impl VigilixAVConnectionPool {
    pub fn new(connection: VigilixAVConnection, timeout: Duration, pool_size: usize, quarantine_dir: String) -> Self {
        // 确保隔离目录存在
        if let Err(e) = std::fs::create_dir_all(&quarantine_dir) {
            log_error!("VigilixAV: 无法创建隔离目录 {} - {}", quarantine_dir, e);
        }
        log_info!("VigilixAV: 创建连接池(完全异步模式)，大小={}, 隔离目录={}", pool_size, quarantine_dir);
        Self {
            connection_info: connection,
            timeout,
            semaphore: tokio::sync::Semaphore::new(pool_size),
            pool_size,
            quarantine_dir,
        }
    }

    pub async fn init(&self) -> Result<(), String> {
        log_info!("VigilixAV: 连接池初始化完成");
        Ok(())
    }

    pub async fn scan_file(&self, path: &str) -> Result<ScanResult, String> {
        let permits = self.semaphore.available_permits();
        //log_info!("VigilixAV: 获取连接，并发数={}, 路径={}", self.pool_size - permits, path);
        let _permit = self.semaphore.acquire().await.map_err(|e| format!("Semaphore error: {}", e))?;
        
        let path_owned = path.to_string();
        let connection_info = self.connection_info.clone();
        let timeout_duration = self.timeout;

        let response = async move {
            match &connection_info {
                VigilixAVConnection::Tcp { host, port } => {
                    let addr = format!("{}:{}", host, port);
                    let mut stream = timeout(timeout_duration, TcpStream::connect(&addr)).await
                        .map_err(|_| "TCP connect timeout")?
                        .map_err(|e| format!("TCP connect failed: {}", e))?;
                    
                    stream.write_all(b"zINSTREAM\0").await.map_err(|e| format!("Write failed: {}", e))?;
                    
                    let file_data = timeout(timeout_duration, tokio::fs::read(&path_owned)).await
                        .map_err(|_| "File read timeout")?
                        .map_err(|e| format!("Cannot read file {}: {}", path_owned, e))?;
                    
                    for chunk in file_data.chunks(4096) {
                        let len = (chunk.len() as u32).to_be_bytes();
                        stream.write_all(&len).await.map_err(|e| format!("Write len failed: {}", e))?;
                        stream.write_all(chunk).await.map_err(|e| format!("Write data failed: {}", e))?;
                    }
                    stream.write_all(&0u32.to_be_bytes()).await.map_err(|e| format!("Write end failed: {}", e))?;
                    stream.flush().await.map_err(|e| format!("Flush failed: {}", e))?;
                    
                    let mut response = String::new();
                    timeout(timeout_duration, stream.read_to_string(&mut response)).await
                        .map_err(|_| "Read timeout")?
                        .map_err(|e| format!("Read failed: {}", e))?;
                    Ok(response)
                }
                VigilixAVConnection::Unix { socket_path } => {
                    use tokio::net::UnixStream;
                    let mut stream = timeout(timeout_duration, UnixStream::connect(socket_path)).await
                        .map_err(|_| "Unix connect timeout")?
                        .map_err(|e| format!("Unix socket connect failed: {}", e))?;
                    
                    stream.write_all(b"zINSTREAM\0").await.map_err(|e| format!("Write failed: {}", e))?;
                    
                    let file_data = timeout(timeout_duration, tokio::fs::read(&path_owned)).await
                        .map_err(|_| "File read timeout")?
                        .map_err(|e| format!("Cannot read file {}: {}", path_owned, e))?;
                    
                    for chunk in file_data.chunks(4096) {
                        let len = (chunk.len() as u32).to_be_bytes();
                        stream.write_all(&len).await.map_err(|e| format!("Write len failed: {}", e))?;
                        stream.write_all(chunk).await.map_err(|e| format!("Write data failed: {}", e))?;
                    }
                    stream.write_all(&0u32.to_be_bytes()).await.map_err(|e| format!("Write end failed: {}", e))?;
                    stream.flush().await.map_err(|e| format!("Flush failed: {}", e))?;
                    
                    let mut response = String::new();
                    timeout(timeout_duration, stream.read_to_string(&mut response)).await
                        .map_err(|_| "Read timeout")?
                        .map_err(|e| format!("Read failed: {}", e))?;
                    Ok(response)
                }
            }
        }.await;

        let permits = self.semaphore.available_permits();
        //log_info!("VigilixAV: 释放连接，并发数={}", self.pool_size - permits);

        match response {
            Ok(resp) => {
                if resp.contains("FOUND") {
                    let virus_name = resp
                        .split("FOUND")
                        .next()
                        .unwrap_or("")
                        .split(':')
                        .nth(1)
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    log_info!("🚨 VigilixAV: 检测到病毒 {} - {}", path, virus_name);
                    Ok(ScanResult::Virus { name: virus_name })
                } else if resp.contains("OK") {
                    Ok(ScanResult::Clean)
                } else {
                    log_error!("⚠️ VigilixAV: 扫描结果异常 '{}'", resp);
                    Ok(ScanResult::Error { message: resp })
                }
            }
            Err(e) => Ok(ScanResult::Error { message: e }),
        }
    }

    // =========================================================================
    // 旧版 dispose_file：通过 vigilixd 协议隔离/删除（因 vigilixd 降权运行有权限限制，暂时保留代码）
    // =========================================================================
    /*
    pub async fn dispose_file_via_vigilixd(&self, file_path: &str, action: DispositionAction) -> DispositionResult {
        let timeout_duration = self.timeout;
        let connection_info = self.connection_info.clone();
        let file_path_send = file_path.to_string();

        let result = timeout(timeout_duration, async move {
            match &connection_info {
                VigilixAVConnection::Tcp { host, port } => {
                    let addr = format!("{}:{}", host, port);
                    let mut stream = tokio::net::TcpStream::connect(&addr).await
                        .map_err(|e| format!("TCP connect failed: {}", e))?;

                    let cmd = match &action {
                        DispositionAction::Move => {
                            format!("nMOVE {}\n", file_path_send)
                        }
                        DispositionAction::Remove => {
                            format!("nREMOVE {}\n", file_path_send)
                        }
                    };
                    stream.write_all(cmd.as_bytes()).await
                        .map_err(|e| format!("Write failed: {}", e))?;
                    stream.flush().await
                        .map_err(|e| format!("Flush failed: {}", e))?;

                    let mut response = Vec::new();
                    let mut buf = [0u8; 1024];
                    timeout(timeout_duration, async {
                        loop {
                            let n = stream.read(&mut buf).await
                                .map_err(|e| format!("Read failed: {}", e))?;
                            if n == 0 { break; }
                            response.extend_from_slice(&buf[..n]);
                            if response.contains(&b'\0') || response.contains(&b'\n') {
                                break;
                            }
                        }
                        Ok::<_, String>(response)
                    }).await
                        .map_err(|_| "Read timeout".to_string())?
                }
                VigilixAVConnection::Unix { socket_path } => {
                    use tokio::net::UnixStream;
                    let mut stream = UnixStream::connect(socket_path).await
                        .map_err(|e| format!("Unix socket connect failed: {}", e))?;

                    let cmd = match &action {
                        DispositionAction::Move => {
                            format!("nMOVE {}\n", file_path_send)
                        }
                        DispositionAction::Remove => {
                            format!("nREMOVE {}\n", file_path_send)
                        }
                    };
                    stream.write_all(cmd.as_bytes()).await
                        .map_err(|e| format!("Write failed: {}", e))?;
                    stream.flush().await
                        .map_err(|e| format!("Flush failed: {}", e))?;

                    let mut response = Vec::new();
                    let mut buf = [0u8; 1024];
                    timeout(timeout_duration, async {
                        loop {
                            let n = stream.read(&mut buf).await
                                .map_err(|e| format!("Read failed: {}", e))?;
                            if n == 0 { break; }
                            response.extend_from_slice(&buf[..n]);
                            if response.contains(&b'\0') || response.contains(&b'\n') {
                                break;
                            }
                        }
                        Ok::<_, String>(response)
                    }).await
                        .map_err(|_| "Read timeout".to_string())?
                }
            }
        }).await;

        match result {
            Ok(Ok(data)) => {
                let resp_str = String::from_utf8_lossy(&data);
                let resp_trimmed = resp_str.trim_matches(|c: char| c == '\0' || c == '\n').trim();
                if resp_trimmed.contains("OK") {
                    log_info!("VigilixAV: 处置成功 - {} - {}", file_path, resp_trimmed);
                    DispositionResult::Success { message: resp_trimmed.to_string() }
                } else {
                    log_error!("VigilixAV: 处置失败 - {} - {}", file_path, resp_trimmed);
                    DispositionResult::Error { message: resp_trimmed.to_string() }
                }
            }
            Ok(Err(e)) => {
                log_error!("VigilixAV: 处置失败 - {} - {}", file_path, e);
                DispositionResult::Error { message: e }
            }
            Err(_) => {
                log_error!("VigilixAV: 处置超时 - {}", file_path);
                DispositionResult::Error { message: "VigilixAV: 处置超时".to_string() }
            }
        }
    }
    */

    /// 直接在本地执行文件处置（隔离/删除），不走 vigilixd
    /// 本进程以 root 权限运行，无权限限制
    pub async fn dispose_file(&self, file_path: &str, action: DispositionAction) -> DispositionResult {
        let file_path_owned = file_path.to_string();
        let quarantine_dir = self.quarantine_dir.clone();

        let result = tokio::task::spawn_blocking(move || {
            match action {
                DispositionAction::Remove => {
                    match std::fs::remove_file(&file_path_owned) {
                        Ok(()) => {
                            log_info!("VigilixAV: 删除成功 - {}", file_path_owned);
                            DispositionResult::Success { message: format!("删除成功: {}", file_path_owned) }
                        }
                        Err(e) => {
                            log_error!("VigilixAV: 删除失败 - {} - {}", file_path_owned, e);
                            DispositionResult::Error { message: format!("删除失败: {}", e) }
                        }
                    }
                }
                DispositionAction::Move => {
                    let file_name = std::path::Path::new(&file_path_owned)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "unknown".to_string());

                    let dest_path = format!("{}/{}", quarantine_dir, file_name);

                    // 先尝试 rename（同设备快速移动），失败则 copy+delete
                    match std::fs::rename(&file_path_owned, &dest_path) {
                        Ok(()) => {
                            log_info!("VigilixAV: 隔离成功(rename) - {} -> {}", file_path_owned, dest_path);
                            DispositionResult::Success { message: format!("隔离成功: {} -> {}", file_path_owned, dest_path) }
                        }
                        Err(_) => {
                            // rename 失败（可能跨设备），尝试复制后删除
                            match std::fs::copy(&file_path_owned, &dest_path) {
                                Ok(_) => {
                                    match std::fs::remove_file(&file_path_owned) {
                                        Ok(()) => {
                                            log_info!("VigilixAV: 隔离成功(copy+delete) - {} -> {}", file_path_owned, dest_path);
                                            DispositionResult::Success { message: format!("隔离成功: {} -> {}", file_path_owned, dest_path) }
                                        }
                                        Err(e) => {
                                            log_error!("VigilixAV: 复制成功但删除原文件失败 - {} - {}", file_path_owned, e);
                                            DispositionResult::Error { message: format!("隔离成功(未删原文件): {}", e) }
                                        }
                                    }
                                }
                                Err(e) => {
                                    log_error!("VigilixAV: 隔离失败 - {} - {}", file_path_owned, e);
                                    DispositionResult::Error { message: format!("隔离失败: {}", e) }
                                }
                            }
                        }
                    }
                }
            }
        }).await;

        match result {
            Ok(r) => r,
            Err(e) => {
                log_error!("VigilixAV: 处置线程异常 - {} - {}", file_path, e);
                DispositionResult::Error { message: format!("内部错误: {}", e) }
            }
        }
    }

    pub async fn ping(&self) -> Result<(), String> {
        let connection_info = self.connection_info.clone();
        let timeout_duration = self.timeout;

        async move {
            match &connection_info {
                VigilixAVConnection::Tcp { host, port } => {
                    let addr = format!("{}:{}", host, port);
                    let mut stream = timeout(timeout_duration, TcpStream::connect(&addr)).await
                        .map_err(|_| "TCP connect timeout")?
                        .map_err(|e| format!("TCP connect failed: {}", e))?;
                    stream.write_all(b"PING\n").await.map_err(|e| format!("Write failed: {}", e))?;
                    stream.flush().await.map_err(|e| format!("Flush failed: {}", e))?;
                    let mut response = String::new();
                    timeout(timeout_duration, stream.read_to_string(&mut response)).await
                        .map_err(|_| "Read timeout")?
                        .map_err(|e| format!("Read failed: {}", e))?;
                    if response.trim().contains("PONG") {
                        Ok(())
                    } else {
                        Err(format!("Unexpected PING response: {}", response))
                    }
                }
                VigilixAVConnection::Unix { socket_path } => {
                    use tokio::net::UnixStream;
                    let mut stream = timeout(timeout_duration, UnixStream::connect(socket_path)).await
                        .map_err(|_| "Unix connect timeout")?
                        .map_err(|e| format!("Unix socket connect failed: {}", e))?;
                    stream.write_all(b"PING\n").await.map_err(|e| format!("Write failed: {}", e))?;
                    stream.flush().await.map_err(|e| format!("Flush failed: {}", e))?;
                    let mut response = String::new();
                    timeout(timeout_duration, stream.read_to_string(&mut response)).await
                        .map_err(|_| "Read timeout")?
                        .map_err(|e| format!("Read failed: {}", e))?;
                    if response.trim().contains("PONG") {
                        Ok(())
                    } else {
                        Err(format!("Unexpected PING response: {}", response))
                    }
                }
            }
        }.await
    }
}

#[derive(Debug, Clone)]
pub struct VigilixAVConfig {
    pub host: String,
    pub port: u16,
    pub timeout_secs: u64,
    pub pool_size: usize,
}
