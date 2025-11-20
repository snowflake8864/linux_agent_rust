// crates/task/src/baseline_task.rs
// crates/task/src/baseline_task.rs

use std::fs;
use std::sync::OnceLock;
use net_client::core::NetClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use logging::log_info;
use tokio::time::Duration;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BaselineItem {
    pub val: u64,
    pub name: String,
    pub pass: i32,
}

static LOCAL_OS_TYPE: OnceLock<i32> = OnceLock::new();

fn detect_local_os_type() -> i32 {
    let content = fs::read_to_string("/etc/os-release")
        .unwrap_or_default()
        .to_lowercase();

    if content.contains("kylin") {
        1130
    } else if content.contains("neokylin") {
        1131
    } else if content.contains("uos") || content.contains("uniontech") {
        1132
    } else if content.contains("centos") {
        1133
    } else if content.contains("ubuntu") {
        1134
    } else if content.contains("red hat")
        || content.contains("rhel")
        || content.contains("rocky")
        || content.contains("almalinux")
        || content.contains("openeuler")
    {
        1135
    } else {
        -1
    }
}

pub fn get_local_os_type() -> i32 {
    *LOCAL_OS_TYPE.get_or_init(|| detect_local_os_type())
}

pub async fn process_baselines_from_client(
    net_client: &NetClient,
    url: &str,
    token: Option<&str>,
) -> Result<(), String> {
    let response = net_client
        .post_data_async(url, "", Duration::from_secs(10), token)
        .await
        .map_err(|e| format!("获取 netblock 策略失败: {}", e))?;

    let parsed: Value = serde_json::from_str(&response)
        .map_err(|e| format!("解析 netblock 响应失败: {}", e))?;

    if parsed["code"] != "000000" {
        let code = parsed["code"].as_str().unwrap_or("未知代码");
        return Err(format!("netblock 响应代码无效: {}", code));
    }

    let list = parsed["data"]["list"]
        .as_array()
        .ok_or("响应中缺少 data.list 或其格式不是数组")?;

    let mut baselines: Vec<BaselineItem> = Vec::new();

    for item in list {
        let val = item["val"].as_u64().ok_or("baseline.val 缺失或不是数字")?;
        let name = item["name"]
            .as_str()
            .ok_or("baseline.name 缺失或不是字符串")?
            .to_string();
        let pass = item["pass"]
            .as_i64()
            .ok_or("baseline.pass 缺失或不是数字")? as i32;

        baselines.push(BaselineItem { val, name, pass });
    }

    if baselines.is_empty() {
        return Err("baseline 列表为空".to_string());
    }

    let local_os_type = get_local_os_type();
    //log_info!("本机 OS 类型：{}", local_os_type);

    for b in baselines.iter_mut() {
        if b.val as i32 == local_os_type {
            b.pass = 1;
        }
    }


    let baselines_array_str = serde_json::to_string(&baselines)
        .map_err(|e| format!("baseline 数组序列化失败: {}", e))?;

    let report_body = serde_json::json!({
        "list": baselines_array_str
    });

    let baselines_json = serde_json::to_string(&report_body)
        .map_err(|e| format!("report body 序列化失败: {}", e))?;

    //log_info!("生成 baseline JSON: {}", baselines_json);

    let report_url = format!("{}/v1/putBaselines", net_client.get_base_url().unwrap_or_default());
    match net_client
        .post_data_async(&report_url, &baselines_json, Duration::from_secs(10), token)
        .await
    {
        Ok(response) => {/*log_info!("服务器响应: {}", response)*/},
        Err(e) => {
            log_info!("Baseline 上报失败: {}", e);
        }
    }

    Ok(())
}
