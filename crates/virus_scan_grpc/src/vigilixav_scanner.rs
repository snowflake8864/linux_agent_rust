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

pub struct VigilixAVConnectionPool {
    connection_info: VigilixAVConnection,
    timeout: Duration,
    semaphore: tokio::sync::Semaphore,
    pool_size: usize,
}

impl VigilixAVConnectionPool {
    pub fn new(connection: VigilixAVConnection, timeout: Duration, pool_size: usize) -> Self {
        log_info!("VigilixAV: 创建连接池(完全异步模式)，大小={}", pool_size);
        Self {
            connection_info: connection,
            timeout,
            semaphore: tokio::sync::Semaphore::new(pool_size),
            pool_size,
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
