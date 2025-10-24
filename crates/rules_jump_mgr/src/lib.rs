// src/lib.rs

pub mod ip_manager;
pub mod pw_manager;
pub mod utils;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PutPwJumpInfo {
    pub user: String,
    pub pw: String,
    pub status: u8,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PutIpJumpInfo {
    pub source_ip: String,
    pub target_ip: String,
    pub gateway: String,
    pub agent_ip: String,
    pub status: u8,
    pub reason: String,
}

#[derive(Debug)]
pub struct IpJumpConfig {
    pub source_ip: String,
    pub target_ip: String, // CIDR or single IP
    pub gateway: String,
}

// SecondaryIPInfo needed by ip_manager
#[derive(Debug, Clone)]
pub struct SecondaryIPInfo {
    pub interface: String,
    pub ip: String,
    pub netmask: String,
    pub prefix_len: u8,
    pub added_tick: u64,
}
pub use ip_manager::IpJumpManager;
pub use pw_manager::PasswordManager;

