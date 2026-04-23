use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::process::Command;

use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};

const MAGIC: &[u8; 4] = b"SECV";
const VERSION: u8 = 0x01;
const KEY_SIZE: usize = 32;
const MAX_PACKET_SIZE: usize = 1024;

static KEY: [u8; KEY_SIZE] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
];

#[derive(Parser)]
#[command(name = "security_eval_server")]
#[command(about = "Security Evaluation UDP Server with Floweye Integration", long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "/etc/security_eval_server/config.toml")]
    config: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct ServerConfig {
    /// 分数阈值，大于等于此分数时添加IP，小于时删除IP
    score_threshold: u32,
    /// floweye 群组ID
    group_id: u32,
    /// 监听地址
    bind_host: String,
    /// 监听端口
    bind_port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            score_threshold: 80,
            group_id: 1,
            bind_host: "0.0.0.0".to_string(),
            bind_port: 62201,
        }
    }
}

struct FloweyeManager {
    /// 已添加到 floweye 的 IP 集合
    added_ips: RwLock<HashSet<String>>,
    /// 配置
    config: ServerConfig,
}

impl FloweyeManager {
    fn new(config: ServerConfig) -> Arc<Self> {
        Arc::new(Self {
            added_ips: RwLock::new(HashSet::new()),
            config,
        })
    }

    /// 根据分数处理 IP：高分数添加，低分数删除
    async fn process_ip(&self, ip: &str, score: u32) {
        let threshold = self.config.score_threshold;
        let group_id = self.config.group_id;

        if score >= threshold {
            // 高分数：添加到 floweye
            self.add_ip_if_not_exists(ip, group_id).await;
        } else {
            // 低分数：从 floweye 删除
            self.remove_ip_if_exists(ip, group_id).await;
        }
    }

    /// 添加 IP 到 floweye（先检查是否已存在）
    async fn add_ip_if_not_exists(&self, ip: &str, group_id: u32) {
        // 先查询 floweye 实际状态
        match Self::execute_floweye_get(group_id) {
            Ok(current_ips) => {
                if current_ips.iter().any(|x| x == ip) {
                    log::debug!("IP {} 已在 floweye 群组 {} 中，跳过添加", ip, group_id);
                    // 同步内存状态
                    let mut added_ips = self.added_ips.write().await;
                    added_ips.insert(ip.to_string());
                    return;
                }
            }
            Err(e) => {
                log::warn!("查询 floweye 群组 {} 状态失败，继续尝试添加: {}", group_id, e);
            }
        }

        match Self::execute_floweye_addip(group_id, ip) {
            Ok(_) => {
                log::info!("成功添加 IP {} 到 floweye 群组 {}", ip, group_id);
                let mut added_ips = self.added_ips.write().await;
                added_ips.insert(ip.to_string());
            }
            Err(e) => {
                log::error!("添加 IP {} 到 floweye 群组 {} 失败: {}", ip, group_id, e);
            }
        }
    }

    /// 从 floweye 删除 IP（先检查是否存在）
    async fn remove_ip_if_exists(&self, ip: &str, group_id: u32) {
        // 先查询 floweye 实际状态
        match Self::execute_floweye_get(group_id) {
            Ok(current_ips) => {
                if !current_ips.iter().any(|x| x == ip) {
                    log::debug!("IP {} 不在 floweye 群组 {} 中，跳过删除", ip, group_id);
                    // 同步内存状态
                    let mut added_ips = self.added_ips.write().await;
                    added_ips.remove(ip);
                    return;
                }
            }
            Err(e) => {
                log::warn!("查询 floweye 群组 {} 状态失败，继续尝试删除: {}", group_id, e);
            }
        }

        match Self::execute_floweye_rmvip(group_id, ip) {
            Ok(_) => {
                log::info!("成功从 floweye 群组 {} 删除 IP {}", group_id, ip);
                let mut added_ips = self.added_ips.write().await;
                added_ips.remove(ip);
            }
            Err(e) => {
                log::error!("从 floweye 群组 {} 删除 IP {} 失败: {}", group_id, ip, e);
            }
        }
    }

    /// 执行 floweye table get 命令，返回当前 IP 列表
    fn execute_floweye_get(group_id: u32) -> Result<Vec<String>, String> {
        let output = Command::new("floweye")
            .args(["table", "get", &format!("id={}", group_id)])
            .output()
            .map_err(|e| format!("执行 floweye get 命令失败: {}", e))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let ips: Vec<String> = stdout
                .lines()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            Ok(ips)
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
        }
    }

    /// 执行 floweye table addip 命令（成功时无输出）
    fn execute_floweye_addip(group_id: u32, ip: &str) -> Result<(), String> {
        let output = Command::new("floweye")
            .args(["table", "addip", &group_id.to_string(), ip])
            .output()
            .map_err(|e| format!("执行 floweye addip 命令失败: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
        }
    }

    /// 执行 floweye table rmvip 命令（成功时无输出）
    fn execute_floweye_rmvip(group_id: u32, ip: &str) -> Result<(), String> {
        let output = Command::new("floweye")
            .args(["table", "rmvip", &group_id.to_string(), ip])
            .output()
            .map_err(|e| format!("执行 floweye rmvip 命令失败: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
        }
    }


}

struct Rc4Context {
    s: [u8; 256],
}

impl Rc4Context {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }

        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        Rc4Context { s }
    }

    fn crypt(&mut self, data: &mut [u8]) {
        let mut i: u8 = 0;
        let mut j: u8 = 0;

        for k in 0..data.len() {
            i = i.wrapping_add(1);
            j = j.wrapping_add(self.s[i as usize]);

            self.s.swap(i as usize, j as usize);

            let t = self.s[(self.s[i as usize] as usize).wrapping_add(self.s[j as usize] as usize) % 256];
            data[k] ^= t;
        }
    }
}

fn calculate_checksum(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[derive(Debug)]
struct ProtocolHeader {
    version: u8,
    msg_type: u8,
    seq: u16,
    timestamp: u32,
    checksum: u32,
    enc_type: u8,
}

fn parse_protocol_header(data: &[u8]) -> Option<ProtocolHeader> {
    if data.len() < 20 || &data[0..4] != MAGIC {
        log::debug!("协议头长度不足或Magic错误, len={}", data.len());
        return None;
    }

    let version = data[4];
    let msg_type = data[5];
    let seq = u16::from_be_bytes([data[6], data[7]]);
    let timestamp = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let checksum = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let enc_type = data[16];

    log::debug!("收到数据包: version={}, msg_type={}, seq={}, enc_type={}",
        version, msg_type, seq, enc_type);

    let mut header_data = [0u8; 16];
    header_data[0..4].copy_from_slice(&data[0..4]);
    header_data[4] = version;
    header_data[5] = msg_type;
    header_data[6..12].copy_from_slice(&data[6..12]);
    header_data[12..16].copy_from_slice(&data[16..20]);

    let calc_crc = calculate_checksum(&header_data);
    if calc_crc != checksum {
        log::debug!("CRC校验失败: calc=0x{:08x}, expected=0x{:08x}", calc_crc, checksum);
        return None;
    }

    Some(ProtocolHeader {
        version,
        msg_type,
        seq,
        timestamp,
        checksum,
        enc_type,
    })
}

#[derive(Debug)]
struct SecurityEvalRequest {
    ip_type: u8,
    ip: String,
    mac: String,
    score: u32,
}

fn parse_security_eval_request(data: &[u8]) -> Option<SecurityEvalRequest> {
    if data.len() < 27 {
        return None;
    }

    let ip_type = data[0];
    let ip = if ip_type == 4 {
        format!("{}.{}.{}.{}", data[1], data[2], data[3], data[4])
    } else {
        format!(
            "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
            data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16]
        )
    };

    let mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        data[17], data[18], data[19], data[20], data[21], data[22]
    );

    let score = u32::from_be_bytes([data[23], data[24], data[25], data[26]]);

    Some(SecurityEvalRequest {
        ip_type,
        ip,
        mac,
        score,
    })
}

fn build_response(seq: u16, message: &str) -> Vec<u8> {
    let mut header = [0u8; 20];
    header[0..4].copy_from_slice(MAGIC);
    header[4] = VERSION;
    header[5] = 0x02;
    header[6..8].copy_from_slice(&seq.to_be_bytes());
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    header[8..12].copy_from_slice(&timestamp.to_be_bytes());

    let mut payload = vec![0u8; 4];
    payload.extend_from_slice(&(0u32).to_be_bytes());
    payload.push(message.len() as u8);
    payload.extend_from_slice(message.as_bytes());

    let mut header_for_crc = [0u8; 16];
    header_for_crc[0..4].copy_from_slice(&header[0..4]);
    header_for_crc[4] = header[4];
    header_for_crc[5] = header[5];
    header_for_crc[6..12].copy_from_slice(&header[6..12]);
    header_for_crc[12..16].copy_from_slice(&header[16..20]);

    let checksum = calculate_checksum(&header_for_crc);
    header[12..16].copy_from_slice(&checksum.to_be_bytes());

    let mut rc4 = Rc4Context::new(&KEY);
    rc4.crypt(&mut payload);

    let mut response = header.to_vec();
    response.extend_from_slice(&payload);
    response
}

async fn handle_packet(
    buf: &[u8], 
    addr: SocketAddr, 
    socket: &Arc<Mutex<UdpSocket>>,
    floweye_manager: &Arc<FloweyeManager>,
) {
    log::debug!("收到数据包, len={}", buf.len());

    let header = match parse_protocol_header(buf) {
        Some(h) => h,
        None => {
            log::error!("解析头部失败");
            return;
        }
    };

    if buf.len() < 20 + 27 {
        log::error!("消息体长度不足, len={}, expected={}", buf.len(), 20 + 27);
        return;
    }

    log::debug!("开始解密, payload_len={}", buf.len() - 20);

    let mut encrypted_payload = buf[20..].to_vec();
    let mut rc4 = Rc4Context::new(&KEY);
    rc4.crypt(&mut encrypted_payload);

    log::debug!("解密完成, 开始解析请求");

    let request = match parse_security_eval_request(&encrypted_payload) {
        Some(r) => r,
        None => {
            log::error!("解析请求失败");
            return;
        }
    };

    log::info!("收到安全评估请求 - IP: {}, MAC: {}, Score: {}", request.ip, request.mac, request.score);

    // 根据分数处理 floweye
    floweye_manager.process_ip(&request.ip, request.score).await;

    let response = build_response(header.seq, "success");

    let socket = socket.lock().await;
    if let Err(e) = socket.send_to(&response, addr).await {
        log::error!("发送响应失败: {}", e);
    } else {
        log::debug!("发送响应 to {}", addr);
    }
}

/// 加载配置文件
fn load_config(config_path: &str) -> ServerConfig {
    match std::fs::read_to_string(config_path) {
        Ok(content) => {
            match toml::from_str::<ServerConfig>(&content) {
                Ok(config) => {
                    log::info!("从 {} 加载配置成功", config_path);
                    config
                }
                Err(e) => {
                    log::warn!("解析配置文件失败: {}，使用默认配置", e);
                    ServerConfig::default()
                }
            }
        }
        Err(e) => {
            log::warn!("读取配置文件失败: {}，使用默认配置", e);
            ServerConfig::default()
        }
    }
}

/// 创建默认配置文件
fn create_default_config(config_path: &str) {
    let config_dir = std::path::Path::new(config_path).parent();
    if let Some(dir) = config_dir {
        let _ = std::fs::create_dir_all(dir);
    }

    let default_config = r#"# Security Eval Server Configuration
# 安全评估服务器配置文件

# 监听地址
bind_host = "0.0.0.0"

# 监听端口
bind_port = 62201

# 分数阈值
# 当接收到的分数 >= 此阈值时，执行 floweye table addip 添加 IP
# 当接收到的分数 < 此阈值时，执行 floweye table rmvip 删除 IP
score_threshold = 80

# floweye 群组 ID
# 指定要操作的 floweye 表群组号
group_id = 1
"#;

    if let Err(e) = std::fs::write(config_path, default_config) {
        log::warn!("创建默认配置文件失败: {}", e);
    } else {
        log::info!("创建默认配置文件: {}", config_path);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    // 如果配置文件不存在，创建默认配置
    if !std::path::Path::new(&cli.config).exists() {
        create_default_config(&cli.config);
    }

    // 加载配置
    let config = load_config(&cli.config);
    log::info!("配置: bind_host={}, bind_port={}, score_threshold={}, group_id={}",
        config.bind_host, config.bind_port, config.score_threshold, config.group_id);

    // 创建 FloweyeManager
    let floweye_manager = FloweyeManager::new(config.clone());

    let socket = UdpSocket::bind(format!("{}:{}", config.bind_host, config.bind_port)).await?;
    log::info!("服务端启动，监听地址 {}:{}", config.bind_host, config.bind_port);

    let socket = Arc::new(Mutex::new(socket));

    loop {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        let (len, addr) = socket.lock().await.recv_from(&mut buf).await?;
        let socket_clone = Arc::clone(&socket);
        let floweye_manager_clone = Arc::clone(&floweye_manager);
        
        tokio::spawn(async move {
            handle_packet(&buf[..len], addr, &socket_clone, &floweye_manager_clone).await;
        });
    }
}
