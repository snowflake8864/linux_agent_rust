// crates/virus_scan_grpc/src/clamav_scanner.rs
use logging::{log_error, log_info};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub enum ClamAVConnection {
    Tcp { host: String, port: u16 },
    Unix { socket_path: String },
}

#[derive(Debug, Clone)]
pub enum ScanResult {
    Clean,
    Virus { name: String },
    Error { message: String },
}

pub struct ClamAVConnectionPool {
    connection_info: ClamAVConnection,
    timeout: Duration,
    semaphore: tokio::sync::Semaphore,
    pool_size: usize,
}

impl ClamAVConnectionPool {
    pub fn new(connection: ClamAVConnection, timeout: Duration, pool_size: usize) -> Self {
        log_info!("ClamAV: 创建连接池(完全异步模式)，大小={}", pool_size);
        Self {
            connection_info: connection,
            timeout,
            semaphore: tokio::sync::Semaphore::new(pool_size),
            pool_size,
        }
    }

    pub async fn init(&self) -> Result<(), String> {
        log_info!("ClamAV: 连接池初始化完成");
        Ok(())
    }

    pub async fn scan_file(&self, path: &str) -> Result<ScanResult, String> {
        let timeout_duration = self.timeout;

        let _permit = timeout(timeout_duration, self.semaphore.acquire())
            .await
            .map_err(|_| "ClamAV: 获取扫描槽位超时".to_string())?
            .map_err(|e| format!("Semaphore error: {}", e))?;

        let path_owned = path.to_string();
        let connection_info = self.connection_info.clone();

        let response = timeout(timeout_duration, async move {
            match &connection_info {
                ClamAVConnection::Tcp { host, port } => {
                    let addr = format!("{}:{}", host, port);
                    let mut stream = timeout(timeout_duration, tokio::net::TcpStream::connect(&addr)).await
                        .map_err(|_| "TCP connect timeout")?
                        .map_err(|e| format!("TCP connect failed: {}", e))?;

                    timeout(timeout_duration, stream.write_all(b"zINSTREAM\0")).await
                        .map_err(|_| "Write command timeout")?
                        .map_err(|e| format!("Write failed: {}", e))?;

                    let file_data = timeout(timeout_duration, tokio::fs::read(&path_owned)).await
                        .map_err(|_| "File read timeout")?
                        .map_err(|e| format!("Cannot read file {}: {}", path_owned, e))?;

                    for chunk in file_data.chunks(4096) {
                        let len = (chunk.len() as u32).to_be_bytes();
                        timeout(timeout_duration, stream.write_all(&len)).await
                            .map_err(|_| "Write chunk len timeout")?
                            .map_err(|e| format!("Write len failed: {}", e))?;
                        timeout(timeout_duration, stream.write_all(chunk)).await
                            .map_err(|_| "Write chunk data timeout")?
                            .map_err(|e| format!("Write data failed: {}", e))?;
                    }
                    timeout(timeout_duration, stream.write_all(&0u32.to_be_bytes())).await
                        .map_err(|_| "Write end marker timeout")?
                        .map_err(|e| format!("Write end failed: {}", e))?;
                    timeout(timeout_duration, stream.flush()).await
                        .map_err(|_| "Flush timeout")?
                        .map_err(|e| format!("Flush failed: {}", e))?;

                    let mut response = String::new();
                    timeout(timeout_duration, stream.read_to_string(&mut response)).await
                        .map_err(|_| "Read timeout")?
                        .map_err(|e| format!("Read failed: {}", e))?;
                    Ok(response)
                }
                ClamAVConnection::Unix { socket_path } => {
                    use tokio::net::UnixStream;
                    let mut stream = timeout(timeout_duration, UnixStream::connect(socket_path)).await
                        .map_err(|_| "Unix connect timeout")?
                        .map_err(|e| format!("Unix socket connect failed: {}", e))?;

                    timeout(timeout_duration, stream.write_all(b"zINSTREAM\0")).await
                        .map_err(|_| "Write command timeout")?
                        .map_err(|e| format!("Write failed: {}", e))?;

                    let file_data = timeout(timeout_duration, tokio::fs::read(&path_owned)).await
                        .map_err(|_| "File read timeout")?
                        .map_err(|e| format!("Cannot read file {}: {}", path_owned, e))?;

                    for chunk in file_data.chunks(4096) {
                        let len = (chunk.len() as u32).to_be_bytes();
                        timeout(timeout_duration, stream.write_all(&len)).await
                            .map_err(|_| "Write chunk len timeout")?
                            .map_err(|e| format!("Write len failed: {}", e))?;
                        timeout(timeout_duration, stream.write_all(chunk)).await
                            .map_err(|_| "Write chunk data timeout")?
                            .map_err(|e| format!("Write data failed: {}", e))?;
                    }
                    timeout(timeout_duration, stream.write_all(&0u32.to_be_bytes())).await
                        .map_err(|_| "Write end marker timeout")?
                        .map_err(|e| format!("Write end failed: {}", e))?;
                    timeout(timeout_duration, stream.flush()).await
                        .map_err(|_| "Flush timeout")?
                        .map_err(|e| format!("Flush failed: {}", e))?;

                    let mut response = String::new();
                    timeout(timeout_duration, stream.read_to_string(&mut response)).await
                        .map_err(|_| "Read timeout")?
                        .map_err(|e| format!("Read failed: {}", e))?;
                    Ok(response)
                }
            }
        }).await;

        match response {
            Ok(Ok(resp)) => {
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
                    log_info!("🚨 ClamAV: 检测到病毒 {} - {}", path, virus_name);
                    Ok(ScanResult::Virus { name: virus_name })
                } else if resp.contains("OK") {
                    Ok(ScanResult::Clean)
                } else {
                    log_error!("⚠️ ClamAV: 扫描结果异常 '{}'", resp);
                    Ok(ScanResult::Error { message: resp })
                }
            }
            Ok(Err(e)) => Ok(ScanResult::Error { message: e }),
            Err(_) => Ok(ScanResult::Error { message: "ClamAV: 扫描超时".to_string() }),
        }
    }

    pub async fn ping(&self) -> Result<(), String> {
        let connection_info = self.connection_info.clone();
        let timeout_duration = self.timeout;

        async move {
            match &connection_info {
                ClamAVConnection::Tcp { host, port } => {
                    let addr = format!("{}:{}", host, port);
                    let mut stream = timeout(timeout_duration, tokio::net::TcpStream::connect(&addr)).await
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
                ClamAVConnection::Unix { socket_path } => {
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
pub struct ClamAVConfig {
    pub host: String,
    pub port: u16,
    pub timeout_secs: u64,
    pub pool_size: usize,
}
