// crates/virus_scan_grpc/src/vigilixav_scanner.rs
use logging::{log_error, log_info};
use std::ffi::CString;
use std::fs::Permissions;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
    /// 从隔离目录还原文件到原始位置
    Restore,
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
        // 设置隔离目录权限：1777 (rwxrwxrwt)，所有用户可读写，sticky bit 防误删
        if let Err(e) = std::fs::set_permissions(&quarantine_dir, Permissions::from_mode(0o1777)) {
            log_error!("VigilixAV: 无法设置隔离目录权限 {} - {}", quarantine_dir, e);
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

    /// 直接在本地执行文件处置（隔离/删除/还原），不走 vigilixd
    /// 本进程以 root 权限运行，无权限限制
    ///
    /// 隔离安全措施：
    ///   - 文件命名: {dev}_{ino}_{原始名}，以 (dev, ino) 作为唯一标识
    ///   - 保存原始路径、权限、属主到 .meta 文件，支持完整还原
    pub async fn dispose_file(&self, file_path: &str, action: DispositionAction, virus_name: Option<&str>) -> DispositionResult {
        let file_path_owned = file_path.to_string();
        let quarantine_dir = self.quarantine_dir.clone();
        let virus_name_owned = virus_name.map(|s| s.to_string());

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
                DispositionAction::Restore => {
                    Self::restore_from_quarantine(&file_path_owned, &quarantine_dir)
                }
                DispositionAction::Move => {
                    Self::quarantine_file(&file_path_owned, &quarantine_dir, virus_name_owned.as_deref())
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

    /// 将文件隔离到隔离目录
    /// 文件名格式: {dev}_{ino}_{原始名}，以 (dev, ino) 作为唯一标识
    fn quarantine_file(file_path: &str, quarantine_dir: &str, virus_name: Option<&str>) -> DispositionResult {
        let path = std::path::Path::new(file_path);
        let original_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // 获取文件完整元数据
        let meta = match std::fs::metadata(file_path) {
            Ok(m) => m,
            Err(e) => {
                return DispositionResult::Error {
                    message: format!("无法获取文件元数据 {}: {}", file_path, e)
                };
            }
        };

        let dev = meta.dev();
        let ino = meta.ino();
        let uid = meta.uid();
        let gid = meta.gid();
        let mode = meta.permissions().mode();
        let file_size = meta.len();

        // 隔离文件名: {dev}_{ino}_{原始名}
        let quar_name = format!("{}_{}_{}", dev, ino, original_name);
        let dest_path = format!("{}/{}", quarantine_dir, quar_name);

        // 如果同名文件已存在，说明同 (dev, ino) 的文件已隔离过，跳过
        if std::path::Path::new(&dest_path).exists() {
            log_info!("VigilixAV: 文件已隔离 (dev={}, ino={}), 跳过 - {}", dev, ino, file_path);
            return DispositionResult::Success {
                message: format!("已隔离(重复): {} -> {}", file_path, quar_name)
            };
        }

        // 先尝试 rename（同设备快速移动），失败则 copy+delete
        let move_result = match std::fs::rename(file_path, &dest_path) {
            Ok(()) => {
                log_info!("VigilixAV: 隔离成功(rename) - {} -> {}", file_path, dest_path);
                Ok(())
            }
            Err(_) => {
                // rename 失败（可能跨设备），尝试复制后删除
                match std::fs::copy(file_path, &dest_path) {
                    Ok(_) => {
                        match std::fs::remove_file(file_path) {
                            Ok(()) => {
                                log_info!("VigilixAV: 隔离成功(copy+delete) - {} -> {}", file_path, dest_path);
                                Ok(())
                            }
                            Err(e) => {
                                log_error!("VigilixAV: 复制成功但删除原文件失败 - {} - {}", file_path, e);
                                Err(format!("隔离成功(未删原文件): {}", e))
                            }
                        }
                    }
                    Err(e) => {
                        log_error!("VigilixAV: 隔离失败 - {} - {}", file_path, e);
                        Err(format!("隔离失败: {}", e))
                    }
                }
            }
        };

        match move_result {
            Ok(()) => {
                // chmod 000：彻底禁止读/写/执行，防止隔离区病毒被意外激活
                if let Err(e) = std::fs::set_permissions(&dest_path, Permissions::from_mode(0o000)) {
                    log_error!("VigilixAV: 设置隔离文件权限失败 {} - {}", dest_path, e);
                } else {
                    log_info!("VigilixAV: 隔离文件已加锁(chmod 000) - {}", dest_path);
                }

                // 写入 .meta 元数据文件（用于精确还原）
                let meta_path = format!("{}.meta", dest_path);
                let meta_content = serde_json::json!({
                    "dev": dev,
                    "ino": ino,
                    "original_path": file_path,
                    "uid": uid,
                    "gid": gid,
                    "mode": mode,
                    "file_size": file_size,
                    "virus_name": virus_name.unwrap_or(""),
                    "quarantined_at": chrono::Utc::now().to_rfc3339(),
                });
                if let Ok(json) = serde_json::to_string_pretty(&meta_content) {
                    if let Err(e) = std::fs::write(&meta_path, &json) {
                        log_error!("VigilixAV: 写入元数据文件失败 {} - {}", meta_path, e);
                    } else {
                        log_info!("VigilixAV: 元数据已保存 - {}", meta_path);
                    }
                }

                DispositionResult::Success {
                    message: format!("隔离成功: {} -> {}", file_path, quar_name)
                }
            }
            Err(e) => DispositionResult::Error { message: e },
        }
    }

    /// 从隔离目录还原文件
    /// file_path 支持多种格式：
    ///   - "{dev}_{ino}_{name}" : 按 (dev, ino) 精确还原单个文件
    ///   - "/original/path"     : 按原始路径反查还原
    ///   - "virus:{virus_name}" : 批量还原所有同名病毒
    ///   - "scan:all"           : 批量还原隔离区全部文件
    fn restore_from_quarantine(file_path: &str, quarantine_dir: &str) -> DispositionResult {
        // ── 批量模式 ──
        if file_path.starts_with("virus:") {
            let virus_name = &file_path["virus:".len()..];
            return Self::restore_all_by_virus(virus_name, quarantine_dir);
        }
        if file_path == "scan:all" {
            return Self::restore_all(quarantine_dir);
        }

        // ── 单文件模式：找到对应的 .meta ──
        let meta_path = match Self::find_meta_for_restore(file_path, quarantine_dir) {
            Some(p) => p,
            None => {
                return DispositionResult::Error {
                    message: format!("在隔离目录中未找到文件 {} 对应的元数据", file_path)
                };
            }
        };

        Self::restore_one_meta(&meta_path)
    }

    /// 查找用于还原的 .meta 文件
    fn find_meta_for_restore(file_path: &str, quarantine_dir: &str) -> Option<String> {
        // 策略1：file_path 本身就是 .meta 路径
        if file_path.ends_with(".meta") && std::path::Path::new(file_path).exists() {
            return Some(file_path.to_string());
        }

        // 策略2：file_path 在隔离目录中且同名 .meta 存在
        let candidate = format!("{}/{}.meta", quarantine_dir, file_path);
        if std::path::Path::new(&candidate).exists() {
            return Some(candidate);
        }

        // 策略3：file_path 可能是 {dev}_{ino}_{...} 格式，解析 (dev, ino) 查找
        let parts: Vec<&str> = file_path.split('_').collect();
        if parts.len() >= 2 {
            if let (Ok(dev), Ok(ino)) = (parts[0].parse::<u64>(), parts[1].parse::<u64>()) {
                return Self::find_meta_by_dev_inode(dev, ino, quarantine_dir);
            }
        }

        // 策略4：file_path 是原始路径，扫 .meta 匹配 original_path
        Self::find_meta_by_original_path(file_path, quarantine_dir)
    }

    /// 还原单个 .meta 对应的隔离文件
    fn restore_one_meta(meta_path: &str) -> DispositionResult {
        let meta_content = match std::fs::read_to_string(meta_path) {
            Ok(c) => c,
            Err(e) => {
                return DispositionResult::Error {
                    message: format!("无法读取元数据文件 {}: {}", meta_path, e)
                };
            }
        };

        let meta: serde_json::Value = match serde_json::from_str(&meta_content) {
            Ok(v) => v,
            Err(e) => {
                return DispositionResult::Error {
                    message: format!("元数据格式无效 {}: {}", meta_path, e)
                };
            }
        };

        let original_path = meta["original_path"].as_str().unwrap_or("");
        let mode = meta["mode"].as_u64().unwrap_or(0o644) as u32;
        let uid = meta["uid"].as_u64().unwrap_or(0) as u32;
        let gid = meta["gid"].as_u64().unwrap_or(0) as u32;

        if original_path.is_empty() {
            return DispositionResult::Error {
                message: format!("元数据中缺少 original_path: {}", meta_path)
            };
        }

        // 找到对应的隔离文件（.meta 去掉后缀）
        let quar_path = meta_path.strip_suffix(".meta").unwrap_or(meta_path).to_string();
        if !std::path::Path::new(&quar_path).exists() {
            return DispositionResult::Error {
                message: format!("隔离文件不存在: {}（可能已被手动删除）", quar_path)
            };
        }

        // 确保原始目录存在
        if let Some(parent) = std::path::Path::new(original_path).parent() {
            if !parent.exists() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    return DispositionResult::Error {
                        message: format!("无法创建原始目录 {}: {}", parent.display(), e)
                    };
                }
            }
        }

        // 移动文件回原始位置
        let move_ok = match std::fs::rename(&quar_path, original_path) {
            Ok(()) => true,
            Err(_) => {
                // rename 失败，尝试 copy+delete
                match std::fs::copy(&quar_path, original_path) {
                    Ok(_) => {
                        let _ = std::fs::remove_file(&quar_path);
                        log_info!("VigilixAV: 还原(copy) - {} -> {}", quar_path, original_path);
                        true
                    }
                    Err(e2) => {
                        log_error!("VigilixAV: 还原失败 - {} -> {}: {}", quar_path, original_path, e2);
                        return DispositionResult::Error {
                            message: format!("还原失败: {} -> {}: {}", quar_path, original_path, e2)
                        };
                    }
                }
            }
        };

        if !move_ok {
            return DispositionResult::Error {
                message: "还原移动失败".to_string()
            };
        }

        // 恢复属主（chown uid:gid）
        Self::chown_file(original_path, uid, gid);

        // 恢复权限（chmod mode）
        if let Err(e) = std::fs::set_permissions(original_path, Permissions::from_mode(mode)) {
            log_error!("VigilixAV: 还原权限失败 {} - {}", original_path, e);
        }

        // 清理元数据文件
        let _ = std::fs::remove_file(meta_path);
        log_info!("VigilixAV: 还原成功 - {} -> {}", quar_path, original_path);

        DispositionResult::Success {
            message: format!("还原成功: {}", original_path)
        }
    }

    /// 批量还原所有同一病毒名的隔离文件
    fn restore_all_by_virus(virus_name: &str, quarantine_dir: &str) -> DispositionResult {
        let metas = Self::find_all_meta_by_virus(virus_name, quarantine_dir);
        if metas.is_empty() {
            return DispositionResult::Error {
                message: format!("未找到病毒 {} 的隔离文件", virus_name)
            };
        }

        let total = metas.len();
        let mut ok = 0usize;
        let mut failed = Vec::new();

        for meta_path in &metas {
            match Self::restore_one_meta(meta_path) {
                DispositionResult::Success { .. } => ok += 1,
                DispositionResult::Error { message } => failed.push(message),
            }
        }

        if failed.is_empty() {
            DispositionResult::Success {
                message: format!("批量还原完成: {}/{}", ok, total)
            }
        } else {
            DispositionResult::Error {
                message: format!("批量还原: {}/{}, 失败: {:?}", ok, total, failed)
            }
        }
    }

    /// 还原隔离区全部文件
    fn restore_all(quarantine_dir: &str) -> DispositionResult {
        let metas = Self::find_all_meta(quarantine_dir);
        if metas.is_empty() {
            return DispositionResult::Error {
                message: "隔离区中没有可还原的文件".to_string()
            };
        }

        let total = metas.len();
        let mut ok = 0usize;

        for meta_path in &metas {
            match Self::restore_one_meta(meta_path) {
                DispositionResult::Success { .. } => ok += 1,
                _ => {}
            }
        }

        DispositionResult::Success {
            message: format!("全部还原完成: {}/{}", ok, total)
        }
    }

    /// chown(path, uid, gid)
    fn chown_file(path: &str, uid: u32, gid: u32) {
        if uid == 0 && gid == 0 {
            return; // 本来就不是 root，跳过也没什么意义；本来就是 root 也不需要改
        }
        let c_path = match CString::new(path) {
            Ok(p) => p,
            Err(_) => return,
        };
        let ret = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EPERM) {
                log_error!("VigilixAV: chown({}, {}, {}) 失败: {}", path, uid, gid, err);
            }
        } else {
            log_info!("VigilixAV: chown({}, {}, {}) ok", path, uid, gid);
        }
    }

    /// 按 (dev, ino) 查找 .meta 文件
    fn find_meta_by_dev_inode(dev: u64, ino: u64, quarantine_dir: &str) -> Option<String> {
        let dir = std::fs::read_dir(quarantine_dir).ok()?;
        for entry in dir.flatten() {
            let path = entry.path();
            let path_str = path.to_string_lossy();
            if !path_str.ends_with(".meta") {
                continue;
            }
            let content = std::fs::read_to_string(&path).ok()?;
            let meta: serde_json::Value = serde_json::from_str(&content).ok()?;
            if meta.get("dev").and_then(|v| v.as_u64()) == Some(dev)
                && meta.get("ino").and_then(|v| v.as_u64()) == Some(ino)
            {
                return Some(path_str.to_string());
            }
        }
        None
    }

    /// 在隔离目录中扫描所有 .meta 文件，找到 original_path 匹配的那个
    fn find_meta_by_original_path(original_path: &str, quarantine_dir: &str) -> Option<String> {
        let dir = std::fs::read_dir(quarantine_dir).ok()?;
        for entry in dir.flatten() {
            let path = entry.path();
            let path_str = path.to_string_lossy();
            if !path_str.ends_with(".meta") {
                continue;
            }
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let meta: serde_json::Value = match serde_json::from_str(&content) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if meta.get("original_path").and_then(|v| v.as_str()) == Some(original_path) {
                return Some(path_str.to_string());
            }
        }
        None
    }

    /// 查找所有匹配 virus_name 的 .meta 文件
    fn find_all_meta_by_virus(virus_name: &str, quarantine_dir: &str) -> Vec<String> {
        let dir = match std::fs::read_dir(quarantine_dir) {
            Ok(d) => d,
            Err(_) => return vec![],
        };
        let mut result = Vec::new();
        for entry in dir.flatten() {
            let path = entry.path();
            let path_str = path.to_string_lossy();
            if !path_str.ends_with(".meta") {
                continue;
            }
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let meta: serde_json::Value = match serde_json::from_str(&content) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if meta.get("virus_name").and_then(|v| v.as_str()) == Some(virus_name) {
                result.push(path_str.to_string());
            }
        }
        result
    }

    /// 查找隔离目录中所有 .meta 文件
    fn find_all_meta(quarantine_dir: &str) -> Vec<String> {
        let dir = match std::fs::read_dir(quarantine_dir) {
            Ok(d) => d,
            Err(_) => return vec![],
        };
        dir.flatten()
            .filter(|e| e.path().to_string_lossy().ends_with(".meta"))
            .map(|e| e.path().to_string_lossy().to_string())
            .collect()
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
