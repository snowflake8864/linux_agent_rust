use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};
use crate::security::{CryptoManager, KeyManager};
use crate::protocol::{ProtocolHeader, SecurityEvalData, SecurityEvalResponse};

pub struct SecurityEvalClient {
    socket: UdpSocket,
    crypto: CryptoManager,
    seq: u16,
    server_addr: SocketAddr,
}

impl SecurityEvalClient {
    pub async fn new(server_addr: &str) -> Result<Self, String> {
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
        
        let key_manager = KeyManager::new();
        let crypto = CryptoManager::new(key_manager.get_key());
        
        let server_addr: SocketAddr = server_addr.parse().map_err(|e: std::net::AddrParseError| e.to_string())?;
        
        Ok(Self {
            socket,
            crypto,
            seq: 0,
            server_addr,
        })
    }

    pub async fn send_security_eval(&mut self, ip: &str, mac: &str, score: u32) -> Result<(), String> {
        let (ip_type, ip_bytes) = parse_ip(ip);
        let mac_bytes = parse_mac(mac)?;
        
        let eval_data = SecurityEvalData::new(ip_type, &ip_bytes, &mac_bytes, score);
        let payload = eval_data.to_bytes();
        
        let encrypted_payload = self.crypto.encrypt(&payload);
        
        let header = ProtocolHeader::new(0x01, self.seq);
        self.seq = self.seq.wrapping_add(1);
        
        let mut packet = header.to_bytes();
        packet.extend_from_slice(&encrypted_payload);
        
        self.socket.send_to(&packet, self.server_addr).await.map_err(|e| e.to_string())?;
        
        let mut buf = [0u8; 1024];
        match timeout(Duration::from_secs(5), self.socket.recv_from(&mut buf)).await {
            Ok(Ok((len, addr))) => {
                if addr != self.server_addr {
                    return Err("响应地址不匹配".to_string());
                }
                
                self.handle_response(&buf[..len])
            }
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("响应超时".to_string()),
        }
    }

    fn handle_response(&self, data: &[u8]) -> Result<(), String> {
        let header = ProtocolHeader::from_bytes(data)?;
        
        if header.msg_type != 0x02 {
            return Err("响应类型错误".to_string());
        }
        
        if data.len() < 20 {
            return Err("响应数据不足".to_string());
        }
        
        let encrypted_payload = &data[20..];
        let plaintext = self.crypto.decrypt(encrypted_payload)?;
        
        let response = SecurityEvalResponse::from_bytes(&plaintext)?;
        
        if response.code != 0 {
            return Err(response.get_message_string());
        }
        
        Ok(())
    }
}

fn parse_ip(ip: &str) -> (u8, Vec<u8>) {
    let first_ip = ip.split(',').next().unwrap_or(ip);
    if first_ip.contains(':') {
        eprintln!("DEBUG: parsing as IPv6");
        let parts: Vec<&str> = first_ip.split(':').collect();
        let mut bytes = Vec::new();
        for part in parts {
            if part.len() == 4 {
                bytes.push(u8::from_str_radix(&part[0..2], 16).unwrap_or(0));
                bytes.push(u8::from_str_radix(&part[2..4], 16).unwrap_or(0));
            } else if part.len() == 2 {
                bytes.push(u8::from_str_radix(part, 16).unwrap_or(0));
                bytes.push(0);
            }
        }
        while bytes.len() < 16 {
            bytes.push(0);
        }
        (6, bytes)
    } else {
        let parts: Vec<&str> = first_ip.split('.').collect();
        let bytes: Vec<u8> = parts.iter()
            .map(|p| p.parse().unwrap_or(0))
            .collect();
        let mut ip_bytes = vec![0u8; 16];
        ip_bytes[..4].copy_from_slice(&bytes);
        (4, ip_bytes)
    }
}

fn parse_mac(mac: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return Err("MAC 地址格式错误".to_string());
    }
    
    let mut mac_bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac_bytes[i] = u8::from_str_radix(part, 16).map_err(|_| "MAC 地址格式错误")?;
    }
    
    Ok(mac_bytes)
}
