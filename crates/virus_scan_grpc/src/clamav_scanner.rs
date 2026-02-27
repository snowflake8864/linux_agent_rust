// crates/virus_scan_grpc/src/clamav_scanner.rs
use logging::{log_error, log_info};
use std::time::Duration;
use std::io::{Read, Write};

/// ClamAV 连接类型
#[derive(Debug, Clone)]
pub enum ClamAVConnection {
    /// TCP 连接
    Tcp { host: String, port: u16 },
    /// Unix Socket 连接
    Unix { socket_path: String },
}

/// ClamAV 扫描结果
#[derive(Debug, Clone)]
pub enum ScanResult {
    /// 文件安全
    Clean,
    /// 检测到病毒
    Virus { name: String },
    /// 扫描错误
    Error { message: String },
}

/// ClamAV 扫描器封装
pub struct ClamAVScanner {
    connection: ClamAVConnection,
    timeout: Duration,
}

impl ClamAVScanner {
    /// 创建 TCP 方式的 ClamAV 扫描器
    pub fn new_tcp(host: String, port: u16, timeout: Duration) -> Self {
        Self {
            connection: ClamAVConnection::Tcp { host, port },
            timeout,
        }
    }

    /// 创建 Unix Socket 方式的 ClamAV 扫描器
    pub fn new_unix(socket_path: String, timeout: Duration) -> Self {
        Self {
            connection: ClamAVConnection::Unix { socket_path },
            timeout,
        }
    }

    /// 自动检测并连接 ClamAV
    /// 优先尝试 TCP，如果失败则尝试 Unix Socket
    pub async fn auto_connect(host: String, port: Option<u16>, timeout: Duration) -> Result<Self, String> {
        let port = port.unwrap_or(3310);
        log_info!("ClamAV: 开始自动连接检测 (host={}, port={})", host, port);

        // 先尝试 TCP
        let tcp_timeout = std::time::Duration::from_secs(3);
        let tcp_scanner = Self::new_tcp(host.clone(), port, tcp_timeout);
        match tcp_scanner.ping().await {
            Ok(_) => {
                log_info!("✅ ClamAV: TCP 连接成功 {}:{}", host, port);
                return Ok(tcp_scanner);
            }
            Err(e) => {
                log_info!("❌ ClamAV TCP 连接失败 {}:{} - {}，尝试 Unix Socket...", host, port, e);
            }
        }

        // 尝试默认的 Unix Socket 路径
        //let default_socket = "/run/clamav/clamd.ctl";
        let default_socket = "/opt/clamav/var/run/clamd.sock";
        let unix_scanner = Self::new_unix(default_socket.to_string(), tcp_timeout);
        match unix_scanner.ping().await {
            Ok(_) => {
                log_info!("✅ ClamAV: Unix Socket 连接成功 {}", default_socket);
                return Ok(unix_scanner);
            }
            Err(e) => {
                log_info!("❌ Unix Socket {} 连接失败: {}", default_socket, e);
            }
        }

        // 如果配置本身就是 Unix Socket 路径
        if host.starts_with('/') || host.contains(".sock") {
            let unix_scanner = Self::new_unix(host.clone(), tcp_timeout);
            match unix_scanner.ping().await {
                Ok(_) => {
                    log_info!("✅ ClamAV: Unix Socket 连接成功 {}", host);
                    return Ok(unix_scanner);
                }
                Err(e) => {
                    return Err(format!("所有连接方式都失败: TCP {}:{} 失败, Unix Socket {} 失败", host, port, e));
                }
            }
        }

        Err(format!("无法连接到 ClamAV: TCP {}:{} 和 Unix Socket {} 都不可用", host, port, default_socket))
    }

    /// 从配置创建，自动检测连接类型（已废弃）
    #[deprecated(note = "请使用 auto_connect 自动检测")]
    pub fn new_from_config(host_or_path: String, port: Option<u16>, timeout: Duration) -> Self {
        if host_or_path.starts_with('/') || host_or_path.contains(".sock") {
            Self::new_unix(host_or_path, timeout)
        } else {
            let port = port.unwrap_or(3310);
            Self::new_tcp(host_or_path, port, timeout)
        }
    }

    /// 获取连接地址描述
    fn get_address_str(&self) -> String {
        match &self.connection {
            ClamAVConnection::Tcp { host, port } => format!("{}:{}", host, port),
            ClamAVConnection::Unix { socket_path } => socket_path.clone(),
        }
    }

    /// 发送命令并读取响应
    fn send_command(&self, command: &str) -> Result<String, String> {
        let address = self.get_address_str();
        log_info!("ClamAV: 发送命令 '{}' 到 {}", command, address);

        match &self.connection {
            ClamAVConnection::Tcp { host, port } => {
                let addr = format!("{}:{}", host, port);
                log_info!("ClamAV TCP: 正在连接 {}", addr);
                
                let mut stream = std::net::TcpStream::connect_timeout(
                    &addr.parse().map_err(|e| format!("Invalid address: {}", e))?,
                    self.timeout,
                ).map_err(|e| format!("TCP connect failed: {}", e))?;

                log_info!("ClamAV TCP: 连接成功 {}", addr);

                // 命令结尾用 \n 不是 \r\n
                let cmd = format!("{}\n", command);
                stream.write_all(cmd.as_bytes())
                    .map_err(|e| format!("Write failed: {}", e))?;
                stream.flush()
                    .map_err(|e| format!("Flush failed: {}", e))?;

                log_info!("ClamAV TCP: 命令已发送，等待响应...");

                // 同一连接读取响应，不要 drop 后重连！
                let mut response = String::new();
                stream.read_to_string(&mut response)
                    .map_err(|e| format!("Read failed: {}", e))?;

                log_info!("ClamAV TCP: 收到响应 '{}'", response.trim());
                Ok(response.trim().to_string())
            }
            ClamAVConnection::Unix { socket_path } => {
                log_info!("ClamAV Unix: 正在连接 {}", socket_path);
                
                let mut stream = std::os::unix::net::UnixStream::connect(socket_path)
                    .map_err(|e| format!("Unix socket connect failed: {}", e))?;

                log_info!("ClamAV Unix: 连接成功 {}", socket_path);

                let cmd = format!("{}\n", command);
                stream.write_all(cmd.as_bytes())
                    .map_err(|e| format!("Write failed: {}", e))?;
                stream.flush()
                    .map_err(|e| format!("Flush failed: {}", e))?;

                log_info!("ClamAV Unix: 命令已发送，等待响应...");

                let mut response = String::new();
                stream.read_to_string(&mut response)
                    .map_err(|e| format!("Read failed: {}", e))?;

                log_info!("ClamAV Unix: 收到响应 '{}'", response.trim());
                Ok(response.trim().to_string())
            }
        }
    }
    pub async fn scan_file(&self, path: &str) -> Result<ScanResult, String> {
        let address = self.get_address_str();
        let path = path.to_string();
        //log_info!("ClamAV: 开始扫描文件 {} (连接：{})", path, address);

        tokio::task::spawn_blocking(move || {
            let result = std::panic::catch_unwind(|| {
                // 读取文件内容
                let file_data = std::fs::read(&path)
                    .map_err(|e| {
                        log_error!("ClamAV: 无法读取文件 {} - {}", path, e);
                        format!("Cannot read file {}: {}", path, e)
                    })?;
                //log_info!("ClamAV: 文件已读取 ({} 字节)，准备发送", file_data.len());

                // 根据连接类型发送 INSTREAM 请求
                let response = match &ClamAVScanner::get_connection_type(&address) {
                    ConnectionType::Unix => {
                        Self::send_instream_unix(&address, &file_data)?
                    }
                    ConnectionType::Tcp => {
                        Self::send_instream_tcp(&address, &file_data)?
                    }
                };

                //log_info!("ClamAV: 收到扫描结果 '{}'", response.trim());

                // 解析结果
                if response.contains("FOUND") {
                    let virus_name = response
                        .split("FOUND")
                        .next()
                        .unwrap_or("")
                        .split(':')
                        .nth(1)
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    log_info!("🚨 ClamAV: 检测到病毒 {} - {}", path, virus_name);
                    Ok((true, virus_name))
                } else if response.contains("OK") {
                    //log_info!("✅ ClamAV: 文件安全 {}", path);
                    Ok((false, String::new()))
                } else {
                    log_error!("⚠️ ClamAV: 扫描结果异常 '{}'", response);
                    Ok((false, String::new()))
                }
            });

            match result {
                Ok(Ok((is_virus, virus_name))) => {
                    if is_virus {
                        Ok(ScanResult::Virus { name: virus_name })
                    } else {
                        Ok(ScanResult::Clean)
                    }
                }
                Ok(Err(e)) => {
                    log_error!("❌ ClamAV scan error: {}", e);
                    Ok(ScanResult::Error { message: e })
                }
                Err(_) => {
                    let err_msg = format!("ClamAV scan panicked for {}", path);
                    log_error!("❌ {}", err_msg);
                    Ok(ScanResult::Error { message: err_msg })
                }
            }
        })
        .await
        .map_err(|e| format!("Task join error: {}", e))?
    }


    fn get_connection_type(address: &str) -> ConnectionType {
        if address.starts_with('/') || address.contains(".sock") {
            ConnectionType::Unix
        } else {
            ConnectionType::Tcp
        }
    }

    /// 通过 Unix Socket 发送 INSTREAM
    fn send_instream_unix(socket_path: &str, file_data: &[u8]) -> Result<String, String> {
        log_info!("ClamAV Unix: 建立 INSTREAM 连接 {}", socket_path);
        
        let mut stream = std::os::unix::net::UnixStream::connect(socket_path)
            .map_err(|e| {
                log_error!("ClamAV Unix: 连接失败 {} - {}", socket_path, e);
                format!("Unix socket connect failed: {}", e)
            })?;

        // 发送 INSTREAM 命令
        stream.write_all(b"INSTREAM\0")
            .map_err(|e| format!("Write INSTREAM failed: {}", e))?;
        log_info!("ClamAV Unix: INSTREAM 命令已发送");

        // 发送数据块：4 字节大端长度 + 数据
        for (i, chunk) in file_data.chunks(4096).enumerate() {
            let len = chunk.len() as u32;
            stream.write_all(&len.to_be_bytes())
                .map_err(|e| format!("Write len failed: {}", e))?;
            stream.write_all(chunk)
                .map_err(|e| format!("Write data failed: {}", e))?;
            log_info!("ClamAV Unix: 发送数据块 #{} ({} 字节)", i, chunk.len());
        }

        // 发送 0 长度表示结束
        stream.write_all(&0u32.to_be_bytes())
            .map_err(|e| format!("Write end failed: {}", e))?;
        stream.flush()
            .map_err(|e| format!("Flush failed: {}", e))?;
        log_info!("ClamAV Unix: 数据发送完毕，等待扫描结果...");

        // 同一连接读取响应
        let mut response = String::new();
        stream.read_to_string(&mut response)
            .map_err(|e| {
                log_error!("ClamAV Unix: 读取响应失败 - {}", e);
                format!("Read failed: {}", e)
            })?;

        Ok(response)
    }

    /// 辅助：通过 TCP 发送 INSTREAM
    fn send_instream_tcp(addr: &str, file_data: &[u8]) -> Result<String, String> {
        log_info!("ClamAV TCP: 建立 INSTREAM 连接 {}", addr);
        
        let socket_addr: std::net::SocketAddr = addr.parse()
            .map_err(|e| {
                log_error!("ClamAV TCP: 地址解析失败 {} - {}", addr, e);
                format!("Invalid address: {}", e)
            })?;
        
        let mut stream = std::net::TcpStream::connect_timeout(&socket_addr, Duration::from_secs(30))
            .map_err(|e| {
                log_error!("ClamAV TCP: 连接失败 {} - {}", addr, e);
                format!("TCP connect failed: {}", e)
            })?;

        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(30))).ok();

        // 发送 INSTREAM 命令
        stream.write_all(b"zINSTREAM\0")
            .map_err(|e| format!("Write INSTREAM failed: {}", e))?;
        log_info!("ClamAV TCP: INSTREAM 命令已发送");

        // 发送数据块
        for (i, chunk) in file_data.chunks(4096).enumerate() {
            let len = chunk.len() as u32;
            stream.write_all(&len.to_be_bytes())
                .map_err(|e| format!("Write len failed: {}", e))?;
            stream.write_all(chunk)
                .map_err(|e| format!("Write data failed: {}", e))?;
            //log_info!("ClamAV TCP: 发送数据块 #{} ({} 字节)", i, chunk.len());
        }

        // 发送 0 长度表示结束
        stream.write_all(&0u32.to_be_bytes())
            .map_err(|e| format!("Write end failed: {}", e))?;
        stream.flush()
            .map_err(|e| format!("Flush failed: {}", e))?;
        log_info!("ClamAV TCP: 数据发送完毕，等待扫描结果...");

        // 同一连接读取响应
        let mut response = String::new();
        stream.read_to_string(&mut response)
            .map_err(|e| {
                log_error!("ClamAV TCP: 读取响应失败 - {}", e);
                format!("Read failed: {}", e)
            })?;

        Ok(response)
    }

    /// 健康检查：PING ClamAV 服务
    pub async fn ping(&self) -> Result<(), String> {
        let address = self.get_address_str();
        let connection = self.connection.clone();
        let ping_timeout = std::time::Duration::from_secs(3);

        log_info!("ClamAV: 开始 PING 健康检查 {}", address);

        let address_clone = address.clone();
        let ping_result = tokio::time::timeout(ping_timeout, async move {
            let res: Result<(), String> = tokio::task::spawn_blocking(move || {
                let result = std::panic::catch_unwind(|| {
                    match &connection {
                        ClamAVConnection::Tcp { host, port } => {
                            let addr = format!("{}:{}", host, port);
                            log_info!("ClamAV TCP PING: 正在连接 {}", addr);
                            
                            // 同一连接发送 + 读取
                            let mut stream = std::net::TcpStream::connect_timeout(
                                &addr.parse().map_err(|e| format!("Invalid address: {}", e))?,
                                std::time::Duration::from_secs(2),
                            ).map_err(|e| format!("TCP connect failed: {}", e))?;

                            log_info!("ClamAV TCP PING: 连接成功 {}", addr);

                            // 发送 PING（用 \n 不是 \r\n）
                            stream.write_all(b"PING\n")
                                .map_err(|e| format!("Write failed: {}", e))?;
                            stream.flush()
                                .map_err(|e| format!("Flush failed: {}", e))?;

                            log_info!("ClamAV TCP PING: PING 命令已发送，等待 PONG...");

                            // ✅ 同一连接读取响应
                            let mut response = String::new();
                            stream.read_to_string(&mut response)
                                .map_err(|e| format!("Read failed: {}", e))?;

                            log_info!("ClamAV TCP PING: 收到响应 '{}'", response.trim());

                            if response.trim().contains("PONG") {
                                log_info!("✅ ClamAV TCP PING: 成功 {}", addr);
                                Ok(())
                            } else {
                                log_error!("❌ ClamAV TCP PING: 意外响应 '{}'", response);
                                Err(format!("Unexpected PING response: {}", response))
                            }
                        }
                        ClamAVConnection::Unix { socket_path } => {
                            log_info!("ClamAV Unix PING: 正在连接 {}", socket_path);
                            
                            let mut stream = std::os::unix::net::UnixStream::connect(socket_path)
                                .map_err(|e| format!("Unix socket connect failed: {}", e))?;

                            log_info!("ClamAV Unix PING: 连接成功 {}", socket_path);

                            stream.write_all(b"PING\n")
                                .map_err(|e| format!("Write failed: {}", e))?;
                            stream.flush()
                                .map_err(|e| format!("Flush failed: {}", e))?;

                            log_info!("ClamAV Unix PING: PING 命令已发送，等待 PONG...");

                            let mut response = String::new();
                            stream.read_to_string(&mut response)
                                .map_err(|e| format!("Read failed: {}", e))?;

                            log_info!("ClamAV Unix PING: 收到响应 '{}'", response.trim());

                            if response.trim().contains("PONG") {
                                log_info!("✅ ClamAV Unix PING: 成功 {}", socket_path);
                                Ok(())
                            } else {
                                log_error!("❌ ClamAV Unix PING: 意外响应 '{}'", response);
                                Err(format!("Unexpected PING response: {}", response))
                            }
                        }
                    }
                });

                match result {
                    Ok(Ok(_)) => {
                        log_info!("ClamAV PING successful at {}", address_clone);
                        Ok(())
                    }
                    Ok(Err(e)) => Err(e),
                    Err(_) => Err(format!("ClamAV PING panicked at {}", address_clone)),
                }
            }).await.map_err(|e| format!("Task join error: {}", e))?;
            res
        }).await;

        match ping_result {
            Ok(Ok(_)) => {
                log_info!("✅ ClamAV PING: 健康检查通过 {}", address);
                Ok(())
            }
            Ok(Err(e)) => {
                log_error!("❌ ClamAV PING: 健康检查失败 {} - {}", address, e);
                Err(e)
            }
            Err(_) => {
                let err = format!("PING timeout at {}", address);
                log_error!("⏱️ ClamAV PING: {}", err);
                Err(err)
            }
        }
    }
}

/// 辅助枚举：连接类型
#[derive(Debug)]
enum ConnectionType {
    Unix,
    Tcp,
}

/// ClamAV 配置
#[derive(Debug, Clone)]
pub struct ClamAVConfig {
    pub host: String,
    pub port: u16,
    pub timeout_secs: u64,
}
