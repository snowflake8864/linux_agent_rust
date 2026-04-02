// crates/task/src/timer_task.rs
use std::pin::Pin;
use common::manager::boot::BootManager;
use std::future::Future;
use tokio::time::{interval, Duration, Interval};
use net_client::core::NetClient;
use logging::{log_info,log_error};
use hostinfo::net_app::parser_netstat::update_netstat_info;
use hostinfo::net_app::parser_dnat::update_dnat_info;
use hostinfo::net_app::parser_docker::update_docker_info;
use hostinfo::net_app::model::write_business_ports_to_proc;
use config::net_info::NETINFO_CONFIG;
use hostinfo::ip_mac;
use crate::baseline_task::{process_baselines_from_client};
use crate::run_outreach_detection;
use crate::net_reach_rule::build_outreach_detect_list_json;
use crate::security::SecurityEvalClient;
pub trait TimerTask {
    fn start_timer_task(&mut self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>;
}

impl TimerTask for BootManager {
    fn start_timer_task(&mut self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        let base_url = self.get_base_url();
        let shared_net_client = match NetClient::new(Some(base_url), true) {
            Ok(client) => client,
            Err(e) => {
                return Box::pin(async move {
                    Err(format!("Failed to initialize shared NetClient: {}", e))
                });
            }
        };
        Box::pin(async move {
            let mut local_interval = interval(Duration::from_secs(30));
            let mut baseline_interval: Option<Interval> = None;
            let mut baseline_enabled = false;
            let mut outreach_interval: Option<Interval> = None;
            let mut outreach_enabled = false;
            let mut security_eval_interval: Option<Interval> = None;
            let mut security_eval_enabled = false;
            let mut security_client: Option<SecurityEvalClient> = None;

            loop {
                let (switch, time_secs) = self.get_baseline_info();

                if switch && time_secs > 0 {
                    if !baseline_enabled || baseline_interval.is_none() {
                        log_info!("启用 Baseline 拉取，间隔: {} 秒", time_secs);
                        baseline_interval = Some(interval(Duration::from_secs(time_secs as u64)));
                        baseline_enabled = true;
                    }
                } else if baseline_enabled {
                    log_info!("停用 Baseline 拉取");
                    baseline_interval = None;
                    baseline_enabled = false;
                }
                let (outreach_switch, outreach_time) = self.get_outreach_info();
                if outreach_switch && outreach_time > 0 {
                    if !outreach_enabled || outreach_interval.is_none() {
                        log_info!("启用 Outreach Detect，间隔: {} 秒", outreach_time);
                        outreach_interval = Some(interval(Duration::from_secs(outreach_time as u64)));
                        outreach_enabled = true;
                    }
                } else if outreach_enabled {
                    log_info!("停用 Outreach Detect");
                    outreach_interval = None;
                    outreach_enabled = false;
                }
                
                let sec_eval_switch = NETINFO_CONFIG.lock().unwrap().security_eval_enabled;
                let sec_eval_time = NETINFO_CONFIG.lock().unwrap().security_eval_interval;
                log_info!("安全评估配置: enabled={}, interval={}s, addr={}", 
                    sec_eval_switch, sec_eval_time, 
                    NETINFO_CONFIG.lock().unwrap().security_eval_server_addr);
                if sec_eval_switch && sec_eval_time > 0 {
                    if !security_eval_enabled || security_eval_interval.is_none() {
                        log_info!("启用安全评估，间隔: {} 秒", sec_eval_time);
                        security_eval_interval = Some(interval(Duration::from_secs(sec_eval_time as u64)));
                        security_eval_enabled = true;
                        
                        if security_client.is_none() {
                            let server_addr = NETINFO_CONFIG.lock().unwrap().security_eval_server_addr.clone();
                            match SecurityEvalClient::new(&server_addr).await {
                                Ok(client) => {
                                    security_client = Some(client);
                                    log_info!("安全评估客户端初始化成功");
                                }
                                Err(e) => {
                                    log_error!("安全评估客户端初始化失败: {}", e);
                                }
                            }
                        }
                    }
                } else if security_eval_enabled {
                    log_info!("停用安全评估");
                    security_eval_interval = None;
                    security_eval_enabled = false;
                }
                tokio::select! {
                    _ = local_interval.tick() => {
                        update_netstat_info();
                        update_dnat_info();
                        update_docker_info();
                        write_business_ports_to_proc();
                    }

                    _ = async {
                        if let Some(ref mut bi) = baseline_interval {
                            bi.tick().await
                        } else {
                            std::future::pending().await
                        }
                    }, if baseline_interval.is_some() => {
                        /*
                        let base_url = self.get_base_url();
                        match NetClient::new(Some(base_url), true) {
                            Ok(net_client) => {
                                let url = format!(
                                    "{}/v1/getBaselines",
                                    net_client.get_base_url().unwrap_or_default()
                                );
                                let token = self.get_token().await;
                                let _ = process_baselines_from_client(&net_client, &url, token.as_deref()).await;
                            }
                            Err(err) => {
                                eprintln!("创建 NetClient 失败: {}", err);
                            }
                        }
                        */
                        let url = format!("{}/v1/getBaselines", shared_net_client.get_base_url().unwrap_or_default());
                        let token = self.get_token().await;
                        let _ = process_baselines_from_client(&shared_net_client, &url, token.as_deref()).await;

                    }

                    _ = async {
                        if let Some(ref mut oi) = outreach_interval {
                            oi.tick().await
                        } else {
                            std::future::pending().await
                        }
                    }, if outreach_interval.is_some() => {
                        let token = self.get_token().await;
                        match run_outreach_detection(&shared_net_client, None, 30).await {
                            Ok(result) => {
                                if !result.data_list.is_empty() {
                                    match build_outreach_detect_list_json(&result.data_list) {
                                        Ok(json_body) => {
                                            let url = format!("{}/v1/alertupload", shared_net_client.get_base_url().unwrap_or(""));
                                            //log_info!("Uploading url:{},outreach log {:?}", url,json_body);
                                            let _ = shared_net_client.post_data_async(
                                                &url,
                                                &json_body,
                                                Duration::from_secs(10),
                                                token.as_deref(),
                                            ).await;
                                        }
                                        Err(e) => log_error!("Failed to build outreach JSON: {}", e),
                                    }
                                }
                            }
                            Err(e) => log_error!("Outreach detection error: {}", e),
                        }

                    }

                    _ = async {
                        if let Some(ref mut sei) = security_eval_interval {
                            sei.tick().await
                        } else {
                            std::future::pending().await
                        }
                    }, if security_eval_interval.is_some() => {
                        if let Some(ref mut client) = security_client {
                            // 获取系统 IP 和 MAC
                            let ip_opt = ip_mac::get_ip();
                            let mac_opt = ip_mac::get_mac();
                            
                            let ip = ip_opt.clone().unwrap_or_else(|| "127.0.0.1".to_string());
                            let mac_str = mac_opt.unwrap_or_else(|| "00:00:00:00:00:00".to_string());
                            
                            log_info!("发送安全评估: IP={}, MAC={}, Score=95", ip, mac_str);
                            
                            match client.send_security_eval(&ip, &mac_str, 95).await {
                                Ok(_) => {
                                    log_info!("安全评估请求成功");
                                }
                                Err(e) => {
                                    log_error!("安全评估请求失败: {}", e);
                                }
                            }
                        } else {
                            log_error!("安全评估客户端未初始化");
                        }
                    }
                }
            }
        })
    }
}
