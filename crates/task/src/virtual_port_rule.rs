// crates/task/src/virtual_port_rule.rs

use serde::{Deserialize, Deserializer, Serialize};
use serde::de;
use std::str::FromStr;

// 自定义反序列化函数，解析 "1000-2000" 格式的 source_port

pub fn deserialize_port_range<'de, D>(deserializer: D) -> Result<(u16, u16), D::Error>
where
    D: Deserializer<'de>,
{
    // 兼容三种形式：字符串 "1000-2000"/"1000"、数组 [1000, 2000]（旧快照由 derive 序列化产生）、单个数字 1000。
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum PortRangeRepr {
        Text(String),
        Pair([u16; 2]),
        Single(u16),
    }

    let validate = |start: u16, end: u16| -> Result<(u16, u16), D::Error> {
        if start > end {
            return Err(de::Error::custom("start_port must be <= end_port"));
        }
        Ok((start, end))
    };

    match PortRangeRepr::deserialize(deserializer)? {
        PortRangeRepr::Pair([start, end]) => validate(start, end),
        PortRangeRepr::Single(port) => Ok((port, port)),
        PortRangeRepr::Text(s) => {
            let parts: Vec<&str> = s.split('-').collect();
            let parse_port = |p: &str| {
                u16::from_str(p).map_err(|_| de::Error::custom(format!("Invalid port: {}", p)))
            };
            match parts.len() {
                1 => {
                    let port = parse_port(parts[0])?;
                    Ok((port, port))
                }
                2 => {
                    let start = parse_port(parts[0])?;
                    let end = parse_port(parts[1])?;
                    validate(start, end)
                }
                _ => Err(de::Error::custom(
                    "Invalid port format, expected 'port' or 'start-end'",
                )),
            }
        }
    }
}

// 与 deserialize_port_range 对称：序列化为 "start-end"（单端口时为 "port"），避免快照中写入数组导致回读失败。
pub fn serialize_port_range<S>(range: &(u16, u16), serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if range.0 == range.1 {
        serializer.serialize_str(&range.0.to_string())
    } else {
        serializer.serialize_str(&format!("{}-{}", range.0, range.1))
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualPortRule {
    pub alarm_level: u32,
    pub dest_ip: String,
    #[serde(deserialize_with = "deserialize_dest_port")]
    pub dest_port: String,
    pub dest_port_type: u32,
    pub id: u32,
    pub protocol: String,
    pub source_ip: String,
    #[serde(deserialize_with = "deserialize_port_range", serialize_with = "serialize_port_range")]
    #[serde(rename = "source_port")]
    pub source_port_range: (u16, u16), // (start_port, end_port)
    pub r#type: String,
}
