// udisk/src/device.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbInfo {
    pub perpheral_eid: String,         
    pub perpheral_name: String,
    #[serde(default)]
    pub intro: String,
    #[serde(default)]
    pub type_: String,
    #[serde(default)]
    pub allow: bool,
}

impl UsbInfo {
    pub fn new(perpheral_eid: String, perpheral_name: String, intro: String, type_: String, allow: bool) -> Self {
        Self {
            perpheral_eid,
            perpheral_name,
            intro,
            type_,
            allow,
        }
    }
}
