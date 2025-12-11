// crates/task/src/net_reach_rule.rs

use serde::{Deserialize,Serialize};
use std::sync::{Arc, Mutex};
use once_cell::sync::Lazy;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use logging::log_info;
use net_client::core::NetClient; 
use serde_json;

#[derive(Serialize)]
struct DomainLogItem {
    level: i32,
    time: i64,
    #[serde(rename = "type")]
    log_type: i32,
    #[serde(rename = "domain_name")]
    domain_name: String,
    #[serde(rename = "res_ip")]
    res_ip: String,
}
#[derive(Debug, Clone)]
pub struct DomainLog {
    pub n_time: i64,
    pub n_type: i32,   // 固定 4002
    pub n_level: i32,  // 成功 = 1
    pub url: String,   // 原始 addr
    pub ipaddr: String, 
}

#[derive(Debug, Clone)]
pub struct OutreachDetect {
    pub data_list: Vec<DomainLog>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OutreachDetectRule {
    pub addr: String,
    pub method: String,
    pub r#type: u32,
}

impl OutreachDetectRule {
    pub async fn probe(
        &self,
        net_client: &NetClient,
        timeout: Duration,
        token: Option<&str>,
    ) -> Option<DomainLog> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let url = if self.addr.starts_with("http://") || self.addr.starts_with("https://") {
            self.addr.clone()
        } else {
            format!("http://{}", self.addr)
        };

        log_info!("Probing: {} (method: {})", &url, &self.method);

        let result = match self.method.to_lowercase().as_str() {
            "get" => {
                net_client
                    .get_data_with_ip_async(&url, timeout, token)
                    .await
                    .map(|resp| (resp.body, resp.domain_ips))
            }
            "post" => {
                net_client
                    .post_data_with_ip_async(&url, "", timeout, token)
                    .await
                    .map(|resp| (resp.body, resp.domain_ips))
            }
            _ => {
                log_info!("Unsupported method: {}, skipping", self.method);
                return None;
            }
        };

        match result {
            Ok((body, ips)) => {
                let ip_str = ips.join(","); // 多个 IP 用逗号分隔

                log_info!(
                    "✅ Probe success: {} (response len: {}, ips: {})",
                    &url,
                    body.len(),
                    ip_str
                );

                Some(DomainLog {
                    n_time: now,
                    n_type: 4002,
                    n_level: 1,
                    url: self.addr.clone(),
                    ipaddr: ip_str,
                })
            }
            Err(e) => {
                log_info!("❌ Probe failed: {} | error: {}", &url, e);
                None
            }
        }
    }
}

static GLOBAL_OUTREACH_RULES: Lazy<Arc<Mutex<Vec<OutreachDetectRule>>>> =
    Lazy::new(|| Arc::new(Mutex::new(Vec::new())));

pub fn update_global_outreach_rules(rules: Vec<OutreachDetectRule>) {
    let mut guard = GLOBAL_OUTREACH_RULES.lock().unwrap();
    *guard = rules;
    log_info!("Updated global outreach rules, count: {}", guard.len());
}

pub fn get_global_outreach_rules() -> Vec<OutreachDetectRule> {
    GLOBAL_OUTREACH_RULES.lock().unwrap().clone()
}

pub async fn run_outreach_detection(
    net_client: &NetClient,
    token: Option<&str>,
    timeout_secs: u64,
) -> Result<OutreachDetect, String> {
    let rules = get_global_outreach_rules();
    if rules.is_empty() {
        log_info!("No outreach rules, skipping detection");
        return Ok(OutreachDetect { data_list: vec![] });
    }

    use futures::stream::{self, StreamExt};
    const MAX_CONCURRENT: usize = 10;
    let timeout = Duration::from_secs(timeout_secs);

    let logs: Vec<DomainLog> = stream::iter(rules)
        .map(|rule| async move {
            rule.probe(net_client, timeout, token).await
        })
        .buffer_unordered(MAX_CONCURRENT)
        .filter_map(|x| async { x })
        .collect()
        .await;

    log_info!("Outreach detection: {} succeeded", logs.len());
    Ok(OutreachDetect { data_list: logs })
}
pub fn build_outreach_detect_list_json(logs: &[DomainLog]) -> Result<String, String> {
    if logs.is_empty() {
        return Err("No valid domain log entries".to_string());
    }

    let items: Vec<DomainLogItem> = logs
        .iter()
        .map(|log| DomainLogItem {
            level: log.n_level,
            time: log.n_time,
            log_type: log.n_type,
            domain_name: log.url.clone(),
            res_ip: log.ipaddr.clone(),
        })
        .collect();

    let inner_json = serde_json::to_string(&items)
        .map_err(|e| format!("Failed to serialize inner JSON array: {}", e))?;

    let outer = serde_json::json!({
        "alert": inner_json
    });

    let final_json = serde_json::to_string(&outer)
        .map_err(|e| format!("Failed to serialize outer JSON: {}", e))?;

    Ok(final_json)
}
