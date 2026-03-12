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
use crate::baseline_task::{process_baselines_from_client};
use crate::run_outreach_detection;
use crate::net_reach_rule::build_outreach_detect_list_json;
use crate::ssh_login_task::SshLoginCollector;
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
        // Create SSH login collector once — state (offsets + dedup) must persist across ticks
        let ssh_login_collector = SshLoginCollector::new();
        Box::pin(async move {
            let mut local_interval = interval(Duration::from_secs(30));
            let mut baseline_interval: Option<Interval> = None;
            let mut baseline_enabled = false;
            let mut outreach_interval: Option<Interval> = None;
            let mut outreach_enabled = false;

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

                // SSH登录日志采集开关
                let ssh_login_switch = self.get_ssh_login_info();
                if ssh_login_switch {
                    // 每分钟检查一次
                    if local_interval.period().as_secs() != 60 {
                        local_interval = interval(Duration::from_secs(60));
                        log_info!("启用 SSH 登录日志采集，间隔: 60 秒");
                    }
                }

                tokio::select! {
                    _ = local_interval.tick() => {
                        update_netstat_info();
                        update_dnat_info();
                        update_docker_info();
                        write_business_ports_to_proc();
                        
                        // SSH登录日志采集
                        if ssh_login_switch {
                            let token = self.get_token().await;
                            ssh_login_collector.collect_and_report(&shared_net_client, token.as_deref()).await;
                        }
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
                }
            }
        })
    }
}
