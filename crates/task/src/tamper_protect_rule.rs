
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct TamperProtectRule {
    pub id: u32,
    pub dir: String,

    #[serde(rename = "type")]
    pub typ: u32,

    pub hash: String,
    pub protect_rw: u32,

    #[serde(rename = "protect_file")]
    pub file_ext: String,

    pub include_file: String,
    pub is_extend: u32,

    #[serde(rename = "protect_folder")]
    pub protect_folder: String,

    pub process: Vec<ProcessItem>,
}

#[derive(Debug, Deserialize)]
pub struct ProcessItem {
    pub hash: String,
}
