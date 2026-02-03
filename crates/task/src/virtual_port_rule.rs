// crates/task/src/virtual_port_rule.rs

use serde::{Deserialize, Deserializer};
use serde::de;
use std::str::FromStr;

// 自定义反序列化函数，解析 "1000-2000" 格式的 source_port

pub fn deserialize_port_range<'de, D>(deserializer: D) -> Result<(u16, u16), D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let parts: Vec<&str> = s.split('-').collect();

    let parse_port = |p: &str| {
        u16::from_str(p).map_err(|_| de::Error::custom(format!("Invalid port: {}", p)))
    };

    let (start, end) = match parts.len() {
        1 => {
            let port = parse_port(parts[0])?;
            (port, port)
        }
        2 => {
            let start = parse_port(parts[0])?;
            let end = parse_port(parts[1])?;
            if start > end {
                return Err(de::Error::custom("start_port must be <= end_port"));
            }
            (start, end)
        }
        _ => {
            return Err(de::Error::custom(
                "Invalid port format, expected 'port' or 'start-end'",
            ));
        }
    };

    Ok((start, end))
}

// 自定义反序列化函数，处理空 dest_port
pub fn deserialize_dest_port<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
        Ok("0".to_string()) // 默认值，空 dest_port 设为 0
    } else {
        Ok(s)
    }
}

#[derive(Debug, Deserialize)]
pub struct VirtualPortRule {
    pub alarm_level: u32,
    pub dest_ip: String,
    #[serde(deserialize_with = "deserialize_dest_port")]
    pub dest_port: String,
    pub dest_port_type: u32,
    pub id: u32,
    pub protocol: String,
    pub source_ip: String,
    #[serde(deserialize_with = "deserialize_port_range")]
    #[serde(rename = "source_port")]
    pub source_port_range: (u16, u16), // (start_port, end_port)
    pub r#type: String,
}
