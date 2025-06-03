// crates/task/src/virtual_port_rule.rs

use serde::{Deserialize, Deserializer};
use std::str::FromStr;

// 自定义反序列化函数，解析 "1000-2000" 格式的 source_port
pub fn deserialize_port_range<'de, D>(deserializer: D) -> Result<(u16, u16), D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 2 {
        return Err(serde::de::Error::custom("Invalid source_port format, expected 'start-end'"));
    }
    let start = u16::from_str(parts[0]).map_err(|_| serde::de::Error::custom("Invalid start_port"))?;
    let end = u16::from_str(parts[1]).map_err(|_| serde::de::Error::custom("Invalid end_port"))?;
    if start > end {
        return Err(serde::de::Error::custom("start_port must be less than or equal to end_port"));
    }
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
