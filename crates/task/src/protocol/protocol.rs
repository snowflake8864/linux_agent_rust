use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct ProtocolHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub msg_type: u8,
    pub seq: u16,
    pub timestamp: u32,
    pub checksum: u32,
    pub enc_type: u8,
    pub reserved: [u8; 3],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvalData {
    pub ip_type: u8,
    pub ip: [u8; 16],
    pub mac: [u8; 6],
    pub score: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvalResponse {
    pub code: i32,
    pub message_len: u8,
    pub message: Vec<u8>,
}

pub struct Rc4 {
    s: [u8; 256],
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }

        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        Self { s }
    }

    pub fn crypt(&mut self, data: &mut [u8]) {
        let mut i: u8 = 0;
        let mut j: u8 = 0;

        for byte in data.iter_mut() {
            i = i.wrapping_add(1);
            j = j.wrapping_add(self.s[i as usize]);
            self.s.swap(i as usize, j as usize);
            let k = self.s[(self.s[i as usize].wrapping_add(self.s[j as usize])) as usize];
            *byte ^= k;
        }
    }
}

impl ProtocolHeader {
    pub fn new(msg_type: u8, seq: u16) -> Self {
        let magic = *b"SECV";
        let version = 0x01;
        let timestamp = chrono::Utc::now().timestamp() as u32;

        let mut header = Self {
            magic,
            version,
            msg_type,
            seq,
            timestamp,
            checksum: 0,
            enc_type: 1,
            reserved: [0; 3],
        };

        header.checksum = header.calculate_checksum();
        header
    }

    pub fn calculate_checksum(&self) -> u32 {
        let mut data = Vec::new();
        data.extend_from_slice(&self.magic);
        data.push(self.version);
        data.push(self.msg_type);
        data.extend_from_slice(&self.seq.to_be_bytes());
        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data.push(self.enc_type);
        data.extend_from_slice(&self.reserved);

        let mut crc: u32 = 0xFFFFFFFF;
        for byte in &data {
            crc ^= *byte as u32;
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.magic);
        bytes.push(self.version);
        bytes.push(self.msg_type);
        bytes.extend_from_slice(&self.seq.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.checksum.to_be_bytes());
        bytes.push(self.enc_type);
        bytes.extend_from_slice(&self.reserved);
        bytes
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 20 {
            return Err("头部长度不足".to_string());
        }

        let magic = [data[0], data[1], data[2], data[3]];
        if magic != *b"SECV" {
            return Err("协议标识错误".to_string());
        }

        let version = data[4];
        let msg_type = data[5];
        let seq = u16::from_be_bytes([data[6], data[7]]);
        let timestamp = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let checksum = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let enc_type = data[16];
        let reserved = [data[17], data[18], data[19]];

        let header = Self {
            magic,
            version,
            msg_type,
            seq,
            timestamp,
            checksum,
            enc_type,
            reserved,
        };

        if header.calculate_checksum() != checksum {
            return Err("校验和错误".to_string());
        }

        Ok(header)
    }
}

impl SecurityEvalData {
    pub fn new(ip_type: u8, ip: &[u8], mac: &[u8; 6], score: u32) -> Self {
        let mut ip_arr = [0u8; 16];
        ip_arr[..ip.len()].copy_from_slice(ip);

        Self {
            ip_type,
            ip: ip_arr,
            mac: *mac,
            score,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.ip_type);
        bytes.extend_from_slice(&self.ip);
        bytes.extend_from_slice(&self.mac);
        bytes.extend_from_slice(&self.score.to_be_bytes());
        bytes
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 27 {
            return Err("数据长度不足".to_string());
        }

        let ip_type = data[0];
        let ip: [u8; 16] = data[1..17].try_into().unwrap();
        let mac: [u8; 6] = data[17..23].try_into().unwrap();
        let score = u32::from_be_bytes([data[23], data[24], data[25], data[26]]);

        Ok(Self {
            ip_type,
            ip,
            mac,
            score,
        })
    }

    pub fn get_ip_string(&self) -> String {
        if self.ip_type == 4 {
            format!(
                "{}.{}.{}.{}",
                self.ip[0], self.ip[1], self.ip[2], self.ip[3]
            )
        } else {
            let parts: Vec<String> = self
                .ip
                .chunks(2)
                .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                .collect();
            parts.join(":")
        }
    }

    pub fn get_mac_string(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]
        )
    }
}

impl SecurityEvalResponse {
    pub fn new(code: i32, message: &str) -> Self {
        let message_bytes = message.as_bytes();
        let message_len = message_bytes.len() as u8;

        Self {
            code,
            message_len,
            message: message_bytes.to_vec(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.code.to_be_bytes());
        bytes.push(self.message_len);
        bytes.extend_from_slice(&self.message);
        bytes
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 5 {
            return Err("响应数据长度不足".to_string());
        }

        let code = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let message_len = data[4] as usize;

        if data.len() < 5 + message_len {
            return Err("消息内容长度不足".to_string());
        }

        let message = data[5..5 + message_len].to_vec();

        Ok(Self {
            code,
            message_len: message_len as u8,
            message,
        })
    }

    pub fn get_message_string(&self) -> String {
        String::from_utf8_lossy(&self.message).to_string()
    }
}
