
// crates/task/src/timer_task.rs

use std::pin::Pin;
use common::manager::boot::BootManager;
use std::future::Future;
use tokio::time::{interval, Duration, Interval};
use net_client::core::NetClient;
use logging::log_info;
use hostinfo::net_app::parser_netstat::update_netstat_info;
use hostinfo::net_app::parser_dnat::update_dnat_info;
use hostinfo::net_app::parser_docker::update_docker_info;
use hostinfo::net_app::model::write_business_ports_to_proc;

use crate::baseline_task::{process_baselines_from_client, BaselineItem};

pub trait TimerTask {
    fn start_timer_task(&mut self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>;
}

impl TimerTask for BootManager {
    fn start_timer_task(&mut self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {
            let mut local_interval = interval(Duration::from_secs(30));
            let mut baseline_interval: Option<Interval> = None;
            let mut baseline_enabled = false;

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
                    }
                }
            }
        })
    }
}
