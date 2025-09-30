use serde::Deserialize;
pub mod pattern_rules_mgr;
pub mod process_pattern_rules_mgr;
pub use process_pattern_rules_mgr::{ProcessPatternRulesMgr};

#[derive(Debug, Deserialize)]
pub struct GlobalTrustDir {
    pub dir: String,
    #[serde(rename = "type")]
    pub typ: u8,
    pub is_extend: u8,
}
