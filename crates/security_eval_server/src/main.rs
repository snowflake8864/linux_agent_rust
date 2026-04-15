use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

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
#[command(about = "Security Evaluation UDP Server", long_about = None)]
struct Cli {
    #[arg(short, long, default_value_t = 62201)]
    port: u16,
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

async fn handle_packet(buf: &[u8], addr: SocketAddr, socket: &Arc<Mutex<UdpSocket>>) {
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

    let response = build_response(header.seq, "success");

    let socket = socket.lock().await;
    if let Err(e) = socket.send_to(&response, addr).await {
        log::error!("发送响应失败: {}", e);
    } else {
        log::debug!("发送响应 to {}", addr);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();
    let port = cli.port;

    let socket = UdpSocket::bind(format!("0.0.0.0:{}", port)).await?;
    log::info!("服务端启动，监听端口 {}", port);

    let socket = Arc::new(Mutex::new(socket));

    loop {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        let (len, addr) = socket.lock().await.recv_from(&mut buf).await?;
        let socket_clone = Arc::clone(&socket);
        
        tokio::spawn(async move {
            handle_packet(&buf[..len], addr, &socket_clone).await;
        });
    }
}