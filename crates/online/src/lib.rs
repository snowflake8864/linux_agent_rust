use net_client::core::NetClient;
use config::net_info;
use system_metrics::get_system_metrics;
use serde::{Serialize, Deserialize};
use std::pin::Pin;
use common::{
    manager::boot::{BootManager},
};
use std::future::Future;
use tokio::time::{interval, Duration};
use tokio::task::JoinHandle;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
#[derive(Deserialize)]
struct AuthResponse {
    code: String,
    data: AuthData,
    msg: String,
}

#[derive(Deserialize)]
struct AuthData {
    token: String,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct BaseOnline {
    pub uid: String,
    pub macid: String,
    pub ip: String,
    pub ver: String,
    #[serde(rename = "type")] // 将 Rust 的 type_ 映射为 JSON 中的 "type"
    pub type_: i32,  // type 是 Rust 关键字，所以我们使用 type_ 代替
    pub os: String,
    pub memsize: String,
    pub cpu: String,
    pub hdsize: String,
    pub asstarttime: String,
    pub osstarttime: String,
    pub auth: String,
    pub userid: String,
    pub host_name: String,
}

impl BaseOnline {
    pub fn new(cfg:net_info::NetInfoConfig) -> Self {
        BaseOnline {
            uid: cfg.dev_uid,
            macid: cfg.macid,
            ip: cfg.ips,
            ver: cfg.ver,
            type_: 1,
            os: cfg.os,
            memsize: cfg.memsize,
            cpu: cfg.cpu,
            hdsize: cfg.hdsize,
            //astarttime: String::new(),
            //osstarttime: String::new(),
            auth: cfg.auth,
            userid: cfg.user_id,
            host_name: cfg.host_name,
            asstarttime: "1731309829".to_string(),
            osstarttime:"1731309829".to_string(),
        }
    }


    pub async fn run(net_client: &mut NetClient, cfg:net_info::NetInfoConfig) -> Result<String, String> {
        let mut base_online = BaseOnline::new(cfg);
        let json_str = serde_json::to_string(&base_online)
            .map_err(|e| format!("Failed to serialize to JSON: {}", e))?;

        println!("Serialized JSON: {}", json_str);

        let url = format!("{}/v1/auth", net_client.base_url);
        println!("==url:{}", url);
        match net_client.post_data_async(&url, &json_str, Duration::from_secs(10), None).await {
            Ok(response) => {
                println!("response: {:?}", response);
                // 尝试将响应解析为 AuthResponse 结构
                match serde_json::from_str::<AuthResponse>(&response) {
                    Ok(auth_response) => {
                        // 成功解析 token
                        println!("Token: {}", auth_response.data.token);
                        return Ok(auth_response.data.token);  // 返回 token
                    }
                    Err(e) => {
                        eprintln!("Failed to parse response: {}", e);
                        return Err("Failed to parse token from response".to_string());
                    }
                }
            }

            Err(err) => eprintln!("Error: {}", err),
        }

        Err("Failed to get token.".to_string()) // 如果没有 token，返回错误
    }

}

pub trait StartOnline {
    fn start_services(&mut self, token_tx: mpsc::Sender<String>, host_is_offline_rx: mpsc::Receiver<bool>) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>;
}

impl StartOnline for BootManager {
    fn start_services(&mut self, token_tx: mpsc::Sender<String>, mut host_is_offline_rx: mpsc::Receiver<bool>) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {
            let mut interval = interval(Duration::from_secs(30));

            loop {
                let base_url = self.get_base_url();
                let mut net_client = match NetClient::new(base_url, true) {
                    Ok(client) => client,
                    Err(err) => {
                        eprintln!("创建 NetClient 失败: {}", err);
                        return Err("创建 NetClient 失败".to_string());
                    }
                };

                let netinfo_config = self.get_netinfocfg();
                match BaseOnline::run(&mut net_client, netinfo_config).await {
                    Ok(token) => {
                        if let Err(err) = token_tx.send(token.clone()).await {
                            eprintln!("发送 token 失败: {}", err);
                            continue;
                        }
                        println!("Token 已成功发送！");

                        println!("开始监听 host_is_offline 信号和系统资源...");
                        loop {
                            tokio::select! {
                                _ = interval.tick() => {
                                    if let Some(json_data) = get_system_metrics() {
                                        //println!("系统指标: {}", json_data);

                                        // 发送到服务器
                                        let url = format!("{}/v1/puthardwareinfo", net_client.base_url);
                                        match net_client.post_data_async(
                                            &url,
                                            &json_data,
                                            Duration::from_secs(10),
                                            Some(&token)
                                        ).await {
                                            Ok(response) => println!("服务器响应: {}", response),
                                            Err(err) => eprintln!("发送指标失败: {}", err),
                                        }
                                    } else {
                                        eprintln!("获取系统指标失败");
                                    }
                                }
                                result = host_is_offline_rx.recv() => {
                                    match result {
                                        Some(true) => {
                                            println!("收到 host_is_offline 为 true 的信号，重新获取 token...");
                                            break;
                                        }
                                        Some(false) => {
                                            println!("收到 host_is_offline 为 false 的信号，继续监听...");
                                        }
                                        None => {
                                            println!("host_is_offline_rx 信号通道已关闭，退出任务。");
                                            return Ok("后台任务已启动.".to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("获取 token 时发生错误: {}", err);
                        continue;
                    }
                }
            }
        })
    }
}
