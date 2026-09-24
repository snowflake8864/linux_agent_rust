// crates/task/src/timer_task.rs
use std::pin::Pin;
use common::manager::boot::BootManager;
use std::future::Future;
use tokio::time::{interval, Duration, Interval};
use std::time::SystemTime;
use net_client::core::NetClient;
use logging::{log_info, log_error, CustomLogger};
use hostinfo::net_app::parser_netstat::update_netstat_info;
use hostinfo::net_app::parser_dnat::update_dnat_info;
use hostinfo::net_app::parser_docker::update_docker_info;
use hostinfo::net_app::model::write_business_ports_to_proc;
use config::net_info::NETINFO_CONFIG;
use crate::baseline_task::{process_baselines_from_client};
use crate::run_outreach_detection;
use crate::net_reach_rule::build_outreach_detect_list_json;
use crate::ssh_login_task::SshLoginCollector;

// 日志等配置所在路径（与 main.rs 中 CustomLogger::init 使用的一致）
const BACKEND_CONFIG_PATH: &str = "/opt/osec/osec_backend.conf";

/// 动态热更新 backend 配置（日志级别等）。
/// 第一步：先看文件修改时间戳（mtime），没变就直接跳过；
/// 第二步：mtime 变了再读内容比对，内容确实变化才触发 CustomLogger::reload()。
async fn reload_backend_config_if_changed(
    path: &str,
    last_mtime: &mut Option<SystemTime>,
    last_content: &mut Option<String>,
) {
    let new_mtime = match std::fs::metadata(path).and_then(|m| m.modified()) {
        Ok(t) => t,
        Err(e) => {
            log_error!("获取配置文件 {} 的时间戳失败: {}", path, e);
            *last_mtime = None;
            return;
        }
    };

    // 第一步：时间戳没变 → 内容没变，跳过
    if *last_mtime == Some(new_mtime) {
        return;
    }

    // 第二步：时间戳变了，读内容确认
    let new_content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            log_error!("读取配置文件 {} 失败: {}", path, e);
            return;
        }
    };

    // 首次观测：启动时已加载过一次，只记录基线，不重复重载
    if last_content.is_none() {
        *last_content = Some(new_content);
        *last_mtime = Some(new_mtime);
        return;
    }

    // 时间戳变了但内容没变（如 touch），只更新时间戳
    if *last_content == Some(new_content.clone()) {
        *last_mtime = Some(new_mtime);
        return;
    }

    match CustomLogger::reload(path).await {
        Ok(true) => {
            log_info!("检测到 {} 配置变更，已热更新生效", path);
            *last_content = Some(new_content);
            *last_mtime = Some(new_mtime);
        }
        Ok(false) => {
            log_info!("配置文件 {} 内容有变化但解析结果一致，无需重载", path);
            *last_content = Some(new_content);
            *last_mtime = Some(new_mtime);
        }
        Err(e) => {
            log_error!("热更新配置文件 {} 失败: {}", path, e);
            // 保留 last_content（保持上一份已生效的内容），下一次 mtime 变化再重试
            *last_mtime = Some(new_mtime);
        }
    }
}

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
            // backend 配置文件热更新观测状态（时间戳 + 内容）
            let mut backend_cfg_mtime: Option<SystemTime> = None;
            let mut backend_cfg_content: Option<String> = None;

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

                        // 热更新 /opt/osec/osec_backend.conf（日志级别等）：先看时间戳，再看内容
                        reload_backend_config_if_changed(
                            BACKEND_CONFIG_PATH,
                            &mut backend_cfg_mtime,
                            &mut backend_cfg_content,
                        ).await;
                        
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
