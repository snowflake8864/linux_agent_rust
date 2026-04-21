// src/ip_manager.rs
use crate::{IpJumpConfig, PutIpJumpInfo, SecondaryIPInfo};
use ipnet::Ipv4Net;
use crate::utils::*;
use tokio::sync::RwLock;
use std::sync::Arc;
use logging::{log_info, log_error, log_warn};
use tokio::time::{interval, Duration};
use net_client::core::NetClient;
use serde_json::{json, Value};
use tokio::sync::watch;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::path::Path;
use tokio::fs;
use std::time::Instant;


// ===== 全局通道 =====
static IP_JUMP_INSTRUCTION_TX: OnceLock<watch::Sender<Option<IpJumpInstruction>>> = OnceLock::new();
static IP_JUMP_DAEMON_STARTED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Debug)]
struct IpJumpInstruction {
    source_ip: String,
    target_ip: String,
    gateway: String,
    active_time: u32,
    aging_time: u32,  // 单位：分钟
    mode: u32,
}

#[derive(Debug, Clone)]
pub struct NetworkBackup {
    pub ip: String,
    pub netmask: String,
    pub gateway: Option<String>,
    pub interface: String,
}

// 默认老化时间 2 分钟（服务端未返回时使用）
const DEFAULT_AGING_TIME_SECS: u64 = 120;

type SharedSecondaryList = Arc<RwLock<Vec<SecondaryIPInfo>>>;

// 待持久化信息
#[derive(Debug, Clone)]
struct PendingPersistInfo {
    old_ip: String,  // 跳变前的主IP，用于定位 netplan 配置中的条目
    gateway: Option<String>,
}

pub struct IpJumpManager {
    secondary_ips: SharedSecondaryList,
    main_interface: String,
    last_upload_failed: Arc<RwLock<bool>>,
    aging_time_secs: Arc<RwLock<u64>>,
    pending_persist: Arc<RwLock<Option<PendingPersistInfo>>>,
}

/// 带指数退避重试的 HTTP POST 请求
async fn post_data_async_with_retry(
    client: &NetClient,
    url: &str,
    json_data: &str,
    timeout: Duration,
    token: Option<&str>,
    max_retries: u32,
) -> Result<String, String> {
    let mut last_err = String::new();
    for attempt in 0..=max_retries {
        match client.post_data_async(url, json_data, timeout, token).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                last_err = e;
                if attempt < max_retries {
                    let delay = Duration::from_secs(2_u64.pow(attempt));
                    log_warn!("HTTP POST 第 {} 次失败，等待 {:?} 后重试: {}", attempt + 1, delay, last_err);
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
    Err(format!("HTTP POST 在 {} 次尝试后仍然失败: {}", max_retries + 1, last_err))
}

impl IpJumpManager {
    pub fn new(main_interface: &str) -> Arc<Self> {
        Arc::new(IpJumpManager {
            secondary_ips: Arc::new(RwLock::new(Vec::new())),
            main_interface: main_interface.to_string(),
            last_upload_failed: Arc::new(RwLock::new(false)),
            aging_time_secs: Arc::new(RwLock::new(DEFAULT_AGING_TIME_SECS)),
            pending_persist: Arc::new(RwLock::new(None)),
        })
    }

    pub fn send_instruction(
        &self,
        source_ip: String,
        target_ip: String,
        gateway: String,
        active_time: u32,
        aging_time: u32,
        mode: u32,
    ) -> Result<(), String> {
        if let Some(tx) = IP_JUMP_INSTRUCTION_TX.get() {
            let instr = IpJumpInstruction {
                source_ip,
                target_ip,
                gateway,
                active_time,
                aging_time,
                mode,
            };
            tx.send(Some(instr)).map_err(|_| "Failed to send instruction".to_string())?;
            Ok(())
        } else {
            Err("IP Jump daemon not initialized".to_string())
        }
    }

    pub async fn start_ip_jump_daemon(
        self: Arc<Self>,
        base_url: String,
        token: Option<String>,
    ) {
        if IP_JUMP_DAEMON_STARTED.compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed).is_err() {
            return;
        }

        let (tx, mut rx) = watch::channel(None::<IpJumpInstruction>);
        IP_JUMP_INSTRUCTION_TX.set(tx).unwrap();

        let upload_url = format!("{}/v1/putIpJump", base_url);
        let get_url = format!("{}/v1/getIpJump", base_url);
        let token_for_req = token.clone();
        let base_url_for_req = base_url.clone();
        log_info!("IP Jump daemon starting, fetching initial configuration...");
/*
        let mut need_wait = false;
        match self.fetch_latest_instruction(&get_url, &token_for_req, &base_url_for_req).await {
            Ok(Some(instr)) => {
                log_info!("Initial instruction fetched: active_time={}", instr.active_time);
                self.execute_instruction(&instr, &upload_url, &token_for_req, &base_url_for_req).await;

                if instr.active_time > 0 {
                    self.run_periodic_loop(
                        instr,
                        &get_url,
                        &upload_url,
                        &token_for_req,
                        &base_url_for_req,
                        &mut rx,
                    ).await;
                }
            }
            Ok(None) => {
                log_info!("Initial instruction is empty, waiting for external trigger.");
                need_wait = true;
            }
            Err(e) => {
                log_error!("Failed to fetch initial instruction: {}", e);
                need_wait = true;
            }
        }
*/
        let mut need_wait = true;
        loop {
            if need_wait {
                let _ = rx.changed().await;
                need_wait = false;
            }

            let instr_opt = rx.borrow().clone();
            let Some(instr) = instr_opt else {
                let _ = rx.changed().await;
                continue;
            };

            self.execute_instruction(&instr, &upload_url, &token_for_req, &base_url_for_req).await;

            log_info!("IP Jump daemon received instruction: active_time={}", instr.active_time);
            if instr.active_time > 0 {
                self.run_periodic_loop(
                    instr,
                    &get_url,
                    &upload_url,
                    &token_for_req,
                    &base_url_for_req,
                    &mut rx,
                ).await;
                need_wait = true;
                continue;
            }

            let _ = rx.changed().await;
        }
    }


    async fn execute_instruction(
        &self,
        instr: &IpJumpInstruction,
        upload_url: &str,
        token: &Option<String>,
        base_url: &str,
    ) {
        // 更新 aging_time 配置（分钟转秒）
        if instr.aging_time > 0 {
            let new_aging_secs = instr.aging_time as u64 * 60;
            let mut aging = self.aging_time_secs.write().await;
            if *aging != new_aging_secs {
                log_info!(
                    "[IP-JUMP] aging_time 更新: {} 分钟 ({} 秒) -> {} 分钟 ({} 秒)",
                    *aging / 60, *aging,
                    instr.aging_time, new_aging_secs
                );
                *aging = new_aging_secs;
            }
        }
        
        let mut info = PutIpJumpInfo {
            source_ip: "".to_string(),
            target_ip: "".to_string(),
            gateway: "".to_string(),
            agent_ip: "".to_string(),
            status: 0,
            reason: "".to_string(),
        };

        let mut jump_success = false;
        if !instr.source_ip.is_empty() || !instr.target_ip.is_empty() {
            let config = IpJumpConfig {
                source_ip: instr.source_ip.clone(),
                target_ip: instr.target_ip.clone(),
                gateway: instr.gateway.clone(),
            };
            match self.do_ip_jump_async(config, &mut info, instr.mode).await {
                Ok(_) => {
                    log_info!("IP jump success: {:?}", info);
                    info.status = 1;
                    jump_success = true; 
                }
                Err(e) => {
                    log_error!("IP jump failed: {:?}", e);
                    info.status = 2;
                    info.reason = e.to_string();
                }
            }
        }

        match self.upload_result_direct(upload_url, &info, token, base_url).await {
            Ok(_) => {
                log_info!("[IP-JUMP] 上报跳变结果成功: source_ip={}, target_ip={}, status={}",
                    info.source_ip, info.target_ip, info.status);
            }
            Err(e) => {
                log_error!("[IP-JUMP] 上报跳变结果失败: source_ip={}, target_ip={}, status={}, error={}",
                    info.source_ip, info.target_ip, info.status, e);
            }
        }

        if jump_success {
            let gw = if instr.gateway.is_empty() {
                None
            } else {
                Some(instr.gateway.as_str())
            };

            if instr.mode == 2 {
                // mode=2: 立即持久化，不等待
                log_info!("[IP-JUMP] mode=2 立即执行持久化");
                self.do_persist_ip(&instr.source_ip, gw).await;
            } else {
                // 检查是否有 secondary IP，如果有则延后持久化
                let has_secondary = {
                    let list = self.secondary_ips.read().await;
                    !list.is_empty()
                };

                if has_secondary {
                    log_info!("[IP-JUMP] 有 {} 个 secondary IP 存在，延后持久化直到老化清理完成",
                        self.secondary_ips.read().await.len());
                    // 保存持久化所需信息，供后续使用
                    self.save_pending_persist_info(&instr.source_ip, gw).await;
                } else {
                    // 没有 secondary IP，立即持久化
                    self.do_persist_ip(&instr.source_ip, gw).await;
                }
            }

            if let Some(mut agent_ip) = get_local_ips_all().await {
                if !instr.target_ip.is_empty() {
                    let target_ip_no_prefix = strip_ip_prefix(&instr.target_ip);
                    if !ip_list_contains(&agent_ip, target_ip_no_prefix) {
                        if agent_ip.is_empty() {
                            agent_ip = target_ip_no_prefix.to_string();
                        } else {
                            agent_ip = format!("{},{}", agent_ip, target_ip_no_prefix);
                        }
                    }
                }
                match self.upload_ip_jump_periodic_result(base_url, token.clone(), &agent_ip).await {
                    Ok(_) => {
                        log_info!("Periodic IP jump result uploaded successfully: {}", agent_ip);
                    }
                    Err(e) => {
                        log_error!("Failed to upload periodic IP jump result: {}, will retry next time", e);
                    }
                }


            }
        }
    }

    /// 保存待持久化信息
    /// old_ip: 跳变前的主IP，用于定位 netplan 配置中的条目
    async fn save_pending_persist_info(&self, old_ip: &str, gateway: Option<&str>) {
        let info = PendingPersistInfo {
            old_ip: old_ip.to_string(),
            gateway: gateway.map(|s| s.to_string()),
        };
        let mut pending = self.pending_persist.write().await;
        *pending = Some(info);
        log_info!("[IP-JUMP] 保存待持久化信息: old_ip={}, gateway={:?}", old_ip, gateway);
    }

    /// 执行持久化
    /// old_ip: 跳变前的主IP，用于定位 netplan 配置中的条目
    async fn do_persist_ip(&self, old_ip: &str, gateway: Option<&str>) {
        if self.is_netplan_system().await {
            if let Ok(new_primary_ip) = self.get_primary_ip_of_main_interface().await {
                if let Err(e) = self.netplan_update_primary_ip(
                    &self.main_interface,
                    old_ip,
                    &new_primary_ip,
                    gateway,
                ).await {
                    log_error!("netplan persist ip failed: {}", e);
                } else {
                    log_info!("[IP-JUMP] netplan 持久化成功: {}", new_primary_ip);
                }
            }
        } else if self.has_nmcli().await {
            if let Ok(new_primary_ip) = self.get_primary_ip_of_main_interface().await {
                if let Err(e) = self.nmcli_update_primary_ip(
                    &self.main_interface,
                    &new_primary_ip,
                    gateway,
                ).await {
                    log_error!("nmcli persist ip failed: {}", e);
                } else {
                    log_info!("[IP-JUMP] nmcli 持久化成功: {}", new_primary_ip);
                }
            }
        }
    }

    async fn run_periodic_loop(
        &self,
        initial_instr: IpJumpInstruction,
        get_url: &str,
        upload_url: &str,
        token: &Option<String>,
        base_url: &str,
        rx: &mut watch::Receiver<Option<IpJumpInstruction>>,
    ) {
        let mut current_active_time = initial_instr.active_time;
        log_info!("[IP-JUMP-DEBUG] 进入周期循环, 初始 active_time={} 秒", current_active_time);
        
        let mut interval = tokio::time::interval(Duration::from_secs(current_active_time as u64));
        let mut loop_count: u64 = 0;
        let start_time = std::time::Instant::now();

        loop {
            let tick_start = std::time::Instant::now();
            tokio::select! {
                _ = interval.tick() => {
                    loop_count += 1;
                    let elapsed_since_start = start_time.elapsed().as_secs();
                    let elapsed_since_tick = tick_start.elapsed().as_millis();
                    log_info!(
                        "[IP-JUMP-DEBUG] tick #{}: 距启动 {} 秒, tick耗时 {} ms, 当前周期 {} 秒",
                        loop_count, elapsed_since_start, elapsed_since_tick, current_active_time
                    );
                    
                    match self.fetch_latest_instruction(get_url, token, base_url).await {
                        Ok(Some(latest_instr)) => {
                            log_info!(
                                "[IP-JUMP-DEBUG] 获取到指令: active_time={}, source_ip={}, target_ip={}",
                                latest_instr.active_time, latest_instr.source_ip, latest_instr.target_ip
                            );
                            self.execute_instruction(&latest_instr, upload_url, token, base_url).await;

                            if latest_instr.active_time == 0 {
                                log_info!("[IP-JUMP-DEBUG] Periodic task received active_time=0, stopping interval.");
                                break;
                            }

                            if latest_instr.active_time != current_active_time {
                                log_info!(
                                    "[IP-JUMP-DEBUG] active_time 变化: {} -> {} 秒, 重建 interval",
                                    current_active_time, latest_instr.active_time
                                );
                                current_active_time = latest_instr.active_time;
                                interval = tokio::time::interval(Duration::from_secs(current_active_time as u64));
                            }
                        }
                        Ok(None) => {
                            log_warn!("[IP-JUMP-DEBUG] Received empty instruction in periodic mode, skipping.");
                        }
                        Err(e) => {
                            log_error!("[IP-JUMP-DEBUG] Failed to fetch latest instruction: {}", e);
                            break;
                        }
                    }
                },
                _ = rx.changed() => {
                    log_info!("[IP-JUMP-DEBUG] New instruction received during periodic mode, breaking to handle it.");
                    break;
                }
            }
        }
    }

    async fn fetch_latest_instruction(
        &self,
        url: &str,
        token: &Option<String>,
        base_url: &str,
    ) -> Result<Option<IpJumpInstruction>, String> {
        let client = NetClient::new(Some(base_url.to_string()), true)
            .map_err(|e| e.to_string())?;
        let token_str = token.as_deref();
        let resp = post_data_async_with_retry(
            &client, url, "", Duration::from_secs(30), token_str, 3,
        )
        .await
        .map_err(|e| e.to_string())?;
        let parsed: Value = serde_json::from_str(&resp)
            .map_err(|e| e.to_string())?;

        if parsed["code"] != "000000" {
            return Err("API error".to_string());
        }

        if let Some(data) = parsed["data"].as_object() {
            let gateway = data
                .get("gateway")
                .and_then(|v: &Value| v.as_str())
                .unwrap_or("");
            let source_ip = data
                .get("source_ip")
                .and_then(|v: &Value| v.as_str())
                .unwrap_or("");
            let target_ip = data
                .get("target_ip")
                .and_then(|v: &Value| v.as_str())
                .unwrap_or("");
            let active_time = data
                .get("active_time")
                .and_then(|v: &Value| v.as_u64())
                .unwrap_or(0) as u32;
            let aging_time = data
                .get("aging_time")
                .and_then(|v: &Value| v.as_u64())
                .unwrap_or(2) as u32;  // 默认 2 分钟
            let mode = data
                .get("mode")
                .and_then(|v: &Value| v.as_u64())
                .unwrap_or(1) as u32;

            if source_ip.is_empty() && target_ip.is_empty() {
                return Ok(None);
            }

            Ok(Some(IpJumpInstruction {
                source_ip: source_ip.to_string(),
                target_ip: target_ip.to_string(),
                gateway: gateway.to_string(),
                active_time,
                aging_time,
                mode,
            }))
        } else {
            Ok(None)
        }
    }

    async fn upload_result_direct(
        &self,
        url: &str,
        info: &PutIpJumpInfo,
        token: &Option<String>,
        base_url: &str,
    ) -> Result<(), String> {
        let json_body = self.build_upload_ip_jump_json(
            &info.source_ip,
            &info.target_ip,
            &info.gateway,
            &info.agent_ip,
            info.status,
            &info.reason,
        );
        let client = NetClient::new(Some(base_url.to_string()), true)
            .map_err(|e| e.to_string())?;
        log_info!("上报跳变结果:url:{},json:{}",url, json_body);
        match post_data_async_with_retry(
            &client, &url, &json_body, Duration::from_secs(30), token.as_deref(), 3,
        ).await {
            Ok(response) => {log_info!("服务器响应: {}", response)},
            Err(err) => eprintln!("发送指标失败: {}", err),
        }




        Ok(())
    }

    fn build_upload_ip_jump_json(
        &self,
        source_ip: &str,
        target_ip: &str,
        gateway: &str,
        agent_ip: &str,
        state: u8,
        fail_reason: &str,
    ) -> String {
        json!({
            "source_ip": source_ip,
            "target_ip": target_ip,
            "gateway": gateway,
            "agent_ip": agent_ip,
            "status": state,
            "reason": fail_reason,
        }).to_string()
    }

    pub async fn start_periodic_cleanup(self: Arc<Self>, base_url: &str, token: Option<String>, interval_duration: Duration) {
        let mut interval = interval(interval_duration);
        loop {
            interval.tick().await;
            self.do_periodic_cleanup(base_url, token.clone()).await;
        }
    }

    async fn get_primary_ip(&self, source_ip: &str) -> Result<(String, String), String> {
        let out = run_cmd_capture("ip", &["-o", "-4", "addr", "show", "dev", &self.main_interface]).await
            .map_err(|e| format!("ip addr show dev {} failed: {}", self.main_interface, e))?;
        let re = regex::Regex::new(r"^\d+:\s+([^:\s]+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)(?:\s+secondary)?").unwrap();
        let mut primary_ip = None;
        let mut source_ip_found = false;
        let mut is_source_ip_secondary = false;

        for line in out.lines() {
            if let Some(cap) = re.captures(line) {
                let iface = cap.get(1).unwrap().as_str();
                let addr = cap.get(2).unwrap().as_str();
                let is_secondary = line.contains("secondary");

                if addr == source_ip {
                    source_ip_found = true;
                    if is_secondary {
                        is_source_ip_secondary = true;
                    } else {
                        primary_ip = Some(addr.to_string());
                    }
                }
                if !is_secondary && primary_ip.is_none() {
                    primary_ip = Some(addr.to_string());
                }
            }
        }

        if source_ip_found {
            if is_source_ip_secondary {
                if let Some(primary) = primary_ip {
                    //log_info!("Source IP {} is secondary, using primary IP {} on {}", source_ip, primary, self.main_interface);
                    return Ok((primary, self.main_interface.clone()));
                }
            } else {
                log_info!("Source IP {} is already primary on {}", source_ip, self.main_interface);
                return Ok((source_ip.to_string(), self.main_interface.clone()));
            }
        } else {
            log_info!("Source IP {} not found, using primary IP on {}", source_ip, self.main_interface);
        }

        if let Some(primary) = primary_ip {
            Ok((primary, self.main_interface.clone()))
        } else {
            Err(format!("No primary IP found on interface {}", self.main_interface))
        }
    }

    pub async fn do_ip_jump_async(&self, mut config: IpJumpConfig, info: &mut PutIpJumpInfo, mode: u32) -> Result<(), String> {
        //log_info!("Starting IP jump: {} -> {} (gw={})", config.source_ip, config.target_ip, config.gateway);

        let (source_ip, _interface) = self.get_primary_ip(&config.source_ip).await?;
        if source_ip != config.source_ip {
            log_info!("Adjusted source_ip from {} to primary IP {}", config.source_ip, source_ip);
            config.source_ip = source_ip.clone();
        }

        // 不再调用 cleanup_old_secondary，让老化时间控制 secondary IP 的删除
        // self.cleanup_old_secondary(&config.source_ip).await;

        //log_info!("Backing up interface for IP: {}", config.source_ip);
        let backup = self.backup_interface(&config.source_ip).await.map_err(|e| {
            log_error!("backup_interface failed: {}", e);
            e
        })?;
        //log_info!("Backup created: {:?}", backup);

        let src_prefix = netmask_to_prefix(&backup.netmask).map_err(|e| e.to_string())?;
        let (target_ip, target_prefix) = parse_cidr(&config.target_ip).map_err(|e| e.to_string())?;
        //log_info!("Source prefix: {}, Target IP: {}, Target prefix: {}", src_prefix, target_ip, target_prefix);

        // 重要：确保 target_ip 成为唯一的主IP
        // 步骤：
        // 1. 添加 target_ip → 变成 secondary
        // 2. 临时移除所有老的 secondary IP（避免它们提升为主IP）
        // 3. 删除 source_ip → target_ip 自动提升为主IP
        // 4. 把老的 secondary IP 加回系统
        
        //log_info!("Adding target IP: {}/{} to {}", target_ip, target_prefix, backup.interface);
        if let Err(e) = self.run_ip_cmd(&["addr", "add", &format!("{}/{}", target_ip, target_prefix), "dev", &backup.interface]).await {
            log_error!("addr add failed: {}, restoring", e);
            let _ = self.restore_backup(&backup).await;
            return Err(format!("addr add failed: {}", e));
        }

        if mode == 2 {
            // mode=2: 直接删除原 IP，同时清理所有残留的 secondary IP
            if let Err(e) = self.run_ip_cmd(&["addr", "del", &format!("{}/{}", config.source_ip, src_prefix), "dev", &backup.interface]).await {
                log_error!("addr del failed: {}, attempt restore", e);
                let _ = self.restore_backup(&backup).await;
                return Err(format!("addr del failed: {}", e));
            }
            // 清理系统上所有该接口的 secondary IP，并清空跟踪列表
            {
                let mut list = self.secondary_ips.write().await;
                for info in list.iter() {
                    if info.interface == backup.interface {
                        let _ = self.run_ip_cmd(&[
                            "addr", "del",
                            &format!("{}/{}", info.ip, info.prefix_len),
                            "dev", &info.interface
                        ]).await;
                    }
                }
                list.clear();
                log_info!("[IP-JUMP] mode=2 已清理所有 secondary IP 并清空跟踪列表");
            }
        } else {
            // mode=1: 原逻辑，保留原 IP 作为 secondary
            // 临时移除所有老的 secondary IP（保留在列表中，只从系统移除）
            let old_secondaries = self.temporarily_remove_old_secondaries(&backup.interface, &target_ip).await;

            //log_info!("Removing source IP: {}/{} from {}", config.source_ip, src_prefix, backup.interface);
            if let Err(e) = self.run_ip_cmd(&["addr", "del", &format!("{}/{}", config.source_ip, src_prefix), "dev", &backup.interface]).await {
                log_error!("addr del failed: {}, attempt restore", e);
                // 恢复老的 secondary IP
                self.restore_temp_secondaries(&old_secondaries).await;
                let _ = self.restore_backup(&backup).await;
                return Err(format!("addr del failed: {}", e));
            }

            // 恢复老的 secondary IP
            self.restore_temp_secondaries(&old_secondaries).await;

            log_info!("[IP-JUMP] 将老IP {} 作为 secondary 加回系统", config.source_ip);
            if let Err(e) = self.add_secondary_ip(&backup.interface, &config.source_ip, &backup.netmask, src_prefix).await {
                log_error!("add_secondary_ip failed: {}", e);
            } else {
                log_info!("[IP-JUMP] add_secondary_ip 成功: {} on {}", config.source_ip, backup.interface);
            }
        }

        if !config.gateway.trim().is_empty() {
            log_info!("Setting gateway: {} on {}", config.gateway, backup.interface);
            if let Err(e) = self.set_gateway(&config.gateway, &backup.interface).await {
                log_error!("set_gateway failed: {}, restoring", e);
                let _ = self.restore_backup(&backup).await;
                return Err(format!("set gateway failed: {}", e));
            }
        }

        info.source_ip = config.source_ip.clone();
        info.target_ip = config.target_ip.clone();
        info.gateway = config.gateway.clone();
        let agent_ips = get_local_ips_exclude(&config.source_ip).await;
        info.agent_ip = agent_ips.join(",");
        info.status = 1;
        info.reason = "IP jump completed".to_string();

        log_info!("IP jump completed successfully. Secondary IPs: {:?}", *self.secondary_ips.read().await);
        Ok(())
    }

    pub async fn backup_interface(&self, ip: &str) -> Result<NetworkBackup, String> {
        let out = run_cmd_capture("ip", &["-o", "-4", "addr", "show"]).await
            .map_err(|e| format!("ip addr show failed: {}", e))?;
        let re = regex::Regex::new(r"^\d+:\s+([^:\s]+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)").unwrap();
        for line in out.lines() {
            if let Some(cap) = re.captures(line) {
                let iface = cap.get(1).unwrap().as_str();
                let addr = cap.get(2).unwrap().as_str();
                let prefix = cap.get(3).unwrap().as_str().parse::<u8>().unwrap_or(24);
                if addr == ip {
                    let netmask = prefix_to_netmask(prefix).map_err(|e| e.to_string())?;
                    let gw = self.get_default_gateway().await.ok();
                    return Ok(NetworkBackup {
                        ip: addr.to_string(),
                        netmask,
                        gateway: gw,
                        interface: iface.to_string(),
                    });
                }
            }
        }
        Err(format!("interface for ip {} not found", ip))
    }

    pub async fn get_default_gateway(&self) -> Result<String, String> {
        let out = run_cmd_capture("ip", &["route", "show", "default"]).await.map_err(|e| e)?;
        for line in out.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 3 && cols[0] == "default" && cols[1] == "via" {
                return Ok(cols[2].to_string());
            }
        }
        Err("no default gateway".to_string())
    }

    pub async fn run_ip_cmd(&self, args: &[&str]) -> Result<(), String> {
        run_cmd_status("ip", args).await.map_err(|e| e)
    }

    pub async fn set_gateway(&self, gateway: &str, iface: &str) -> Result<(), String> {
        let _ = run_cmd_status("ip", &["route", "del", "default", "dev", iface]).await;
        run_cmd_status("ip", &["route", "add", "default", "via", gateway, "dev", iface]).await
            .map_err(|e| format!("set_gateway failed: {}", e))
    }

    pub async fn restore_backup(&self, backup: &NetworkBackup) -> Result<(), String> {
        let prefix = netmask_to_prefix(&backup.netmask).map_err(|e| e.to_string())?;
        let _ = self.run_ip_cmd(&["addr", "add", &format!("{}/{}", backup.ip, prefix), "dev", &backup.interface]).await;
        if let Some(gw) = &backup.gateway {
            let _ = self.set_gateway(gw, &backup.interface).await;
        }
        Ok(())
    }

    pub async fn add_secondary_ip(&self, iface: &str, ip: &str, netmask: &str, prefix: u8) -> Result<(), String> {
        log_info!("Attempting to add secondary IP: {} on {}", ip, iface);
        
        const MAX_SECONDARY_IPS: usize = 3;
        
        let mut list = self.secondary_ips.write().await;

        // 如果已存在，更新时间并返回
        if let Some(e) = list.iter_mut().find(|x| x.interface == iface && x.ip == ip) {
            e.added_time = Instant::now();
            log_info!("Updated existing secondary IP: {} on {}", ip, iface);
            return Ok(());
        }

        // 如果数量已达上限，移除最老的 secondary IP
        if list.len() >= MAX_SECONDARY_IPS {
            if let Some(oldest) = list.first() {
                let old_iface = oldest.interface.clone();
                let old_ip = oldest.ip.clone();
                let old_prefix = oldest.prefix_len;
                
                log_info!(
                    "Secondary IP list full ({}), removing oldest: {} on {}",
                    MAX_SECONDARY_IPS, old_ip, old_iface
                );
                
                // 从系统中移除
                if ip_exists_on_iface(&old_iface, &old_ip).await {
                    let _ = self.run_ip_cmd(&["addr", "del", &format!("{}/{}", old_ip, old_prefix), "dev", &old_iface]).await;
                    log_info!("Removed old secondary IP from system: {} on {}", old_ip, old_iface);
                }
                
                // 从列表中移除
                list.remove(0);
            }
        }

        // 添加新的 secondary IP
        list.push(SecondaryIPInfo {
            interface: iface.to_string(),
            ip: ip.to_string(),
            netmask: netmask.to_string(),
            prefix_len: prefix,
            added_time: Instant::now(),
        });

        // 添加到系统（第二个及以后的 IP 会自动成为 secondary，不需要显式指定）
        if !ip_exists_on_iface(iface, ip).await {
            self.run_ip_cmd(&["addr", "add", &format!("{}/{}", ip, prefix), "dev", iface])
                .await
                .map_err(|e| format!("failed to add secondary ip to system: {}", e))?;
            log_info!("Added secondary IP to system: {} on {}", ip, iface);
        }

        log_info!("Added secondary IP: {} on {}, list len: {}", ip, iface, list.len());
        Ok(())
    }

    /// 临时移除所有老的 secondary IP（保留在列表中，只从系统移除）
    /// 返回被移除的 IP 列表，用于后续恢复
    async fn temporarily_remove_old_secondaries(&self, iface: &str, exclude_ip: &str) -> Vec<(String, String, u8)> {
        let snapshot = {
            let list = self.secondary_ips.read().await;
            list.clone()
        };
        
        let mut removed: Vec<(String, String, u8)> = Vec::new();
        
        for info in snapshot.iter() {
            // 只移除同接口的、不是 exclude_ip 的 secondary IP
            if info.interface == iface && info.ip != exclude_ip {
                if ip_exists_on_iface(&info.interface, &info.ip).await {
                    log_info!(
                        "[IP-JUMP] 临时移除 secondary IP: {} on {}",
                        info.ip, info.interface
                    );
                    if self.run_ip_cmd(&[
                        "addr", "del",
                        &format!("{}/{}", info.ip, info.prefix_len),
                        "dev", &info.interface
                    ]).await.is_ok() {
                        removed.push((info.interface.clone(), info.ip.clone(), info.prefix_len));
                    }
                }
            }
        }
        
        log_info!("[IP-JUMP] 临时移除了 {} 个 secondary IP", removed.len());
        removed
    }

    /// 恢复临时移除的 secondary IP
    async fn restore_temp_secondaries(&self, secondaries: &[(String, String, u8)]) {
        for (iface, ip, prefix) in secondaries {
            log_info!(
                "[IP-JUMP] 恢复 secondary IP: {} on {}",
                ip, iface
            );
            // 不需要 secondary 关键字，第二个及以后的 IP 会自动成为 secondary
            let _ = self.run_ip_cmd(&[
                "addr", "add",
                &format!("{}/{}", ip, prefix),
                "dev", iface
            ]).await;
        }
    }

    pub async fn find_iface_for_gateway(&self, gateway: &str) -> Option<String> {
        if let Ok(out) = run_cmd_capture("ip", &["-o", "-4", "addr", "show"]).await {
            for line in out.lines() {
                if let Some(parts) = line.split_whitespace().nth(1) {
                    if let Some(cidr) = line.split_whitespace().nth(3) {
                        if let Ok(net) = cidr.parse::<Ipv4Net>() {
                            if let Ok(gw) = gateway.parse::<std::net::Ipv4Addr>() {
                                if net.contains(&gw) {
                                    return Some(parts.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    pub fn has_established_connection(&self, target_ip: &str) -> bool {
        crate::utils::has_established_connection(target_ip)
    }

    pub async fn do_periodic_cleanup(&self, base_url: &str, token: Option<String>) {
        let aging_secs = *self.aging_time_secs.read().await;
        let now = Instant::now();
        let mut expired: Vec<(String, String, u8)> = Vec::new();
        {
            let list = self.secondary_ips.read().await;
            for info in list.iter() {
                let elapsed = now.duration_since(info.added_time).as_secs();
                if elapsed >= aging_secs {
                    log_info!(
                        "Secondary IP {} on {} aged out: {}s >= {}s",
                        info.ip, info.interface, elapsed, aging_secs
                    );
                    expired.push((info.interface.clone(), info.ip.clone(), info.prefix_len));
                }
            }
        }

        let mut any_removed = false;

        for (iface, ip, prefix) in expired.iter() {
            match self.try_remove_ip_from_system(iface, ip, *prefix).await {
                Ok(()) => {
                    let mut list = self.secondary_ips.write().await;
                    list.retain(|x| !(x.interface == *iface && x.ip == *ip));
                    any_removed = true;
                }
                Err(e) => {
                    log_error!("Failed to remove aged IP {} on {}: {}", ip, iface, e);
                }
            }
        }

        let mut need_upload = any_removed;
        {
            let failed = self.last_upload_failed.read().await;
            if *failed {
                need_upload = true;
            }
        }

        if need_upload {
            if let Some(agent_ip) = get_local_ips_all().await {
                match self.upload_ip_jump_periodic_result(base_url, token.clone(), &agent_ip).await {
                    Ok(_) => {
                        log_info!("Periodic IP jump result uploaded successfully: {}", agent_ip);
                        let mut failed = self.last_upload_failed.write().await;
                        *failed = false;
                    }
                    Err(e) => {
                        log_error!("Failed to upload periodic IP jump result: {}, will retry next time", e);
                        let mut failed = self.last_upload_failed.write().await;
                        *failed = true;
                    }
                }
            } else {
                log_error!("Cannot get local agent IP for periodic upload");
            }
        }

        // 检查是否所有 secondary IP 都已清理，如果是则执行延后的持久化
        {
            let list = self.secondary_ips.read().await;
            if list.is_empty() {
                drop(list); // 释放锁
                let pending = self.pending_persist.write().await.take();
                if let Some(info) = pending {
                    log_info!("[IP-JUMP] 所有 secondary IP 已清理，执行延后的持久化");
                    self.do_persist_ip(&info.old_ip, info.gateway.as_deref()).await;
                }
            }
        }
    }
/*
    async fn try_remove_ip_from_system(&self, iface: &str, ip: &str, prefix: u8) -> Result<(), String> {
        let with_prefix = format!("{}/{}", ip, prefix);
        //log_info!("try_remove_ip_from_system: running: ip addr del {} dev {}", with_prefix, iface);
        match run_cmd_capture("ip", &["addr", "del", &with_prefix, "dev", iface]).await {
            Ok(out) => {
                //log_info!("ip addr del (with prefix) stdout: {}", out);
                if !ip_exists_on_iface(iface, ip).await {
                    return Ok(());
                } else {
                    log_error!("After deleting {} (with prefix), ip still exists on {}", with_prefix, iface);
                }
            }
            Err(err) => {
                log_error!("ip addr del (with prefix) failed: {} (cmd stderr/stdout)", err);
            }
        }

        log_info!("try_remove_ip_from_system: trying fallback delete without prefix: ip addr del {} dev {}", ip, iface);
        match run_cmd_capture("ip", &["addr", "del", ip, "dev", iface]).await {
            Ok(out2) => {
                log_info!("ip addr del (no prefix) stdout: {}", out2);
                if !ip_exists_on_iface(iface, ip).await {
                    return Ok(());
                } else {
                    return Err(format!("fallback delete executed but IP still present: {} on {}", ip, iface));
                }
            }
            Err(err2) => {
                return Err(format!("both prefix and fallback delete failed: with_prefix_err: {}, fallback_err: {}", err2, err2));
            }
        }
    }
*/
    async fn try_remove_ip_from_system(
        &self,
        iface: &str,
        ip: &str,
        prefix: u8,
    ) -> Result<(), String> {
        let with_prefix = format!("{}/{}", ip, prefix);

        if !ip_exists_on_iface(iface, ip).await {
            log_info!(
                "try_remove_ip_from_system: {} not present on {}, treat as success",
                ip,
                iface
            );
            return Ok(());
        }

        match run_cmd_capture("ip", &["addr", "del", &with_prefix, "dev", iface]).await {
            Ok(_) => {
                if !ip_exists_on_iface(iface, ip).await {
                    return Ok(());
                }
                log_warn!(
                    "ip addr del {} succeeded but IP still exists on {}",
                    with_prefix,
                    iface
                );
            }
            Err(e) => {
                log_warn!(
                    "ip addr del {} failed: {}, will try fallback",
                    with_prefix,
                    e
                );
            }
        }

        match run_cmd_capture("ip", &["addr", "del", ip, "dev", iface]).await {
            Ok(_) => {
                if !ip_exists_on_iface(iface, ip).await {
                    return Ok(());
                }
                Err(format!(
                        "fallback delete executed but IP still present: {} on {}",
                        ip, iface
                ))
            }
            Err(e) => Err(format!(
                    "both delete attempts failed or ineffective: {}",
                    e
            )),
        }
    }

    pub async fn remove_secondary_ip(&self, iface: &str, ip: &str) -> Result<(), String> {
        let prefix_opt = {
            let list = self.secondary_ips.read().await;
            list.iter().find(|x| x.interface == iface && x.ip == ip).map(|x| x.prefix_len)
        };

        if let Some(p) = prefix_opt {
            log_info!("remove_secondary_ip: found prefix {} for {} on {}", p, ip, iface);
            match self.try_remove_ip_from_system(iface, ip, p).await {
                Ok(()) => {
                    let mut list = self.secondary_ips.write().await;
                    list.retain(|x| !(x.interface == iface && x.ip == ip));
                    log_info!("Removed secondary IP {} on {} from both system and list", ip, iface);
                    Ok(())
                }
                Err(e) => {
                    log_error!("remove_secondary_ip: failed to remove {} on {}: {}", ip, iface, e);
                    Err(e)
                }
            }
        } else {
            log_info!("remove_secondary_ip: prefix not found for {} on {}, trying without prefix", ip, iface);
            match self.try_remove_ip_from_system(iface, ip, 0).await {
                Ok(()) => {
                    let mut list = self.secondary_ips.write().await;
                    let before = list.len();
                    list.retain(|x| !(x.interface == iface && x.ip == ip));
                    let after = list.len();
                    log_info!("Removed secondary IP {} on {} from system and list (before {}, after {})", ip, iface, before, after);
                    Ok(())
                }
                Err(e) => {
                    log_error!("remove_secondary_ip: failed fallback delete {} on {}: {}", ip, iface, e);
                    Err(e)
                }
            }
        }
    }

    async fn upload_ip_jump_periodic_result(
        &self,
        base_url: &str,
        token: Option<String>,
        agent_ip: &str,
    ) -> Result<(), String> {
        let token_str = token.as_ref().map(|s| s.as_str());
        let url = format!("{}/v1/uploadIp", base_url);
        let json_data = self.build_upload_agent_ip_json(agent_ip);
        log_info!("Reporting uploadIp: {} => {}", url, json_data);

        let net_client = NetClient::new(Some(base_url.to_string()), true)
            .map_err(|e| format!("创建 NetClient 失败: {}", e))?;

        let response = post_data_async_with_retry(
            &net_client, &url, &json_data, Duration::from_secs(30), token_str, 3,
        )
        .await
        .map_err(|err| {
            log_info!("发送指标失败: {}", err);
            eprintln!("发送指标失败: {}", err);
            format!("发送指标失败: {}", err)
        })?;

        log_info!("服务器响应: {}", response);
        Ok(())
    }

    /*
    pub async fn nmcli_update_primary_ip(&self, iface: &str, ip: &str) -> Result<(), String> {
        let out = run_cmd_capture("ip", &["-o", "-4", "addr", "show", "dev", iface]).await
            .map_err(|e| format!("ip addr show failed: {}", e))?;

        let mut prefix: Option<u8> = None;
        let re = regex::Regex::new(r"^\d+:\s+[^:\s]+\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)").unwrap();

        for line in out.lines() {
            if let Some(cap) = re.captures(line) {
                let addr = cap.get(1).unwrap().as_str();
                let pre: u8 = cap.get(2).unwrap().as_str().parse().unwrap_or(24);
                if addr == ip && !line.contains("secondary") {
                    prefix = Some(pre);
                    break;
                }
            }
        }

        let prefix = match prefix {
            Some(p) => p,
            None => return Err(format!("Cannot find primary IP {} on interface {}", ip, iface)),
        };

        let conn_out = run_cmd_capture("nmcli", &["-t", "-f", "NAME,DEVICE", "connection", "show"]).await
            .map_err(|e| format!("nmcli connection show failed: {}", e))?;

        let mut conn_name: Option<String> = None;
        for line in conn_out.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 2 && parts[1] == iface {
                conn_name = Some(parts[0].to_string());
                break;
            }
        }

        let conn_name = match conn_name {
            Some(c) => c,
            None => return Err(format!("No nmcli connection found for interface {}", iface)),
        };

        let addr = format!("{}/{}", ip, prefix);
        run_cmd_status("nmcli", &["connection", "modify", &conn_name, "ipv4.addresses", &addr]).await
            .map_err(|e| format!("nmcli modify ipv4.addresses failed: {}", e))?;
        run_cmd_status("nmcli", &["connection", "modify", &conn_name, "ipv4.method", "manual"]).await
            .map_err(|e| format!("nmcli modify ipv4.method failed: {}", e))?;
        run_cmd_status("nmcli", &["connection", "up", &conn_name]).await
            .map_err(|e| format!("nmcli connection up failed: {}", e))?;

        log_info!("Primary IP {} on {} persisted via nmcli (connection: {})", ip, iface, conn_name);
        Ok(())
    }
    */
    pub async fn nmcli_update_primary_ip(
        &self,
        iface: &str,
        ip: &str,
        gateway: Option<&str>,
    ) -> Result<(), String> {
        let out = run_cmd_capture("ip", &["-o", "-4", "addr", "show", "dev", iface]).await
            .map_err(|e| format!("ip addr show failed: {}", e))?;

        let mut prefix: Option<u8> = None;
        let re = regex::Regex::new(r"^\d+:\s+[^:\s]+\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)").unwrap();

        for line in out.lines() {
            if let Some(cap) = re.captures(line) {
                let addr = cap.get(1).unwrap().as_str();
                let pre: u8 = cap.get(2).unwrap().as_str().parse().unwrap_or(24);
                if addr == ip && !line.contains("secondary") {
                    prefix = Some(pre);
                    break;
                }
            }
        }

        let prefix = prefix.ok_or_else(|| format!("Cannot find primary IP {} on interface {}", ip, iface))?;

        let conn_out = run_cmd_capture(
            "nmcli",
            &["-t", "-f", "NAME,DEVICE", "connection", "show"],
        )
            .await
            .map_err(|e| format!("nmcli connection show failed: {}", e))?;

        let mut conn_name: Option<String> = None;
        for line in conn_out.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 2 && parts[1] == iface {
                conn_name = Some(parts[0].to_string());
                break;
            }
        }

        let conn_name =
            conn_name.ok_or_else(|| format!("No nmcli connection found for interface {}", iface))?;

        let addr = format!("{}/{}", ip, prefix);

        run_cmd_status(
            "nmcli",
            &["connection", "modify", &conn_name, "ipv4.addresses", &addr],
        )
            .await
            .map_err(|e| format!("nmcli modify ipv4.addresses failed: {}", e))?;

        run_cmd_status(
            "nmcli",
            &["connection", "modify", &conn_name, "ipv4.method", "manual"],
        )
            .await
            .map_err(|e| format!("nmcli modify ipv4.method failed: {}", e))?;

        if let Some(gw) = gateway {
            run_cmd_status(
                "nmcli",
                &["connection", "modify", &conn_name, "ipv4.gateway", gw],
            )
                .await
                .map_err(|e| format!("nmcli modify ipv4.gateway failed: {}", e))?;
        }

        log_info!(
            "Primary IP {} on {} persisted via nmcli (connection: {}, gateway: {:?})",
            ip,
            iface,
            conn_name,
            gateway
        );

        Ok(())
    }
    pub async fn has_nmcli(&self) -> bool {
        run_cmd_status("which", &["nmcli"]).await.is_ok()
    }

    pub async fn is_netplan_system(&self) -> bool {
        let dir = Path::new("/etc/netplan");
        if !dir.is_dir() {
            return false;
        }

        match fs::read_dir(dir).await {
            Ok(mut rd) => {
                while let Ok(Some(ent)) = rd.next_entry().await {
                    let p = ent.path();
                    if let Some(ext) = p.extension() {
                        if ext == "yaml" || ext == "yml" {
                            return true;
                        }
                    }
                }
                false
            }
            Err(_) => false,
        }
    }


pub async fn netplan_update_primary_ip(
    &self,
    iface: &str,
    source_ip: &str,
    primary_ip: &str,
    gw: Option<&str>,
) -> Result<(), String> {
    use regex::Regex;
    use std::net::Ipv4Addr;
    use std::path::Path;
    use tokio::fs;

    fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
        if prefix == 0 {
            return false;
        }
        let mask = u32::MAX << (32 - prefix);
        (u32::from(a) & mask) == (u32::from(b) & mask)
    }

    let source_v4: Ipv4Addr = source_ip
        .parse()
        .map_err(|_| format!("invalid source_ip {}", source_ip))?;
    let primary_v4: Ipv4Addr = primary_ip
        .parse()
        .map_err(|_| format!("invalid primary_ip {}", primary_ip))?;

    let netplan_dir = Path::new("/etc/netplan");
    if !netplan_dir.is_dir() {
        return Err("not a netplan system".into());
    }

    let mut target_file = None;
    let mut rd = fs::read_dir(netplan_dir)
        .await
        .map_err(|e| format!("read /etc/netplan failed: {}", e))?;

    while let Some(ent) = rd.next_entry().await.map_err(|e| e.to_string())? {
        let path = ent.path();
        if !path
            .extension()
            .map(|s| s == "yaml" || s == "yml")
            .unwrap_or(false)
        {
            continue;
        }

        let content = fs::read_to_string(&path)
            .await
            .map_err(|e| format!("read {:?} failed: {}", path, e))?;

        if content.contains(&format!("{}:", iface)) {
            target_file = Some(path);
            break;
        }
    }

    let file = target_file.ok_or_else(|| {
        format!("no netplan yaml contains interface {}", iface)
    })?;

    let mut content = fs::read_to_string(&file)
        .await
        .map_err(|e| format!("read {:?} failed: {}", file, e))?;

    let addr_re =
        Regex::new(r"addresses:\s*\[([^\]]*)\]").unwrap();

    let caps = addr_re
        .captures(&content)
        .ok_or_else(|| "addresses field not found".to_string())?;

    let raw_list = caps.get(1).unwrap().as_str();

    #[derive(Clone)]
    enum AddrEntry {
        V4 { ip: Ipv4Addr, prefix: u8 },
        Other(String), 
    }

    let mut entries: Vec<AddrEntry> = Vec::new();
    let mut chosen_idx: Option<usize> = None;

    for item in raw_list.split(',') {
        let item = item.trim();

        if let Some((ip_str, pre_str)) = item.split_once('/') {
            if let Ok(v4) = ip_str.parse::<Ipv4Addr>() {
                let prefix: u8 = pre_str.parse().unwrap_or(24);
                let idx = entries.len();

                entries.push(AddrEntry::V4 {
                    ip: v4,
                    prefix,
                });

                if v4 == source_v4 {
                    chosen_idx = Some(idx);
                }
                else if chosen_idx.is_none()
                    && same_subnet(v4, source_v4, prefix)
                {
                    chosen_idx = Some(idx);
                }

                continue;
            }
        }

        entries.push(AddrEntry::Other(item.to_string()));
    }

    match chosen_idx {
        Some(i) => {
            if let AddrEntry::V4 { prefix, .. } = entries[i] {
                entries[i] = AddrEntry::V4 {
                    ip: primary_v4,
                    prefix,
                };
            }
        }
        None => {
            // 没有任何 IPv4，直接 append
            entries.push(AddrEntry::V4 {
                ip: primary_v4,
                prefix: 24,
            });
        }
    }

    let new_addr_list = entries
        .iter()
        .map(|e| match e {
            AddrEntry::V4 { ip, prefix } => {
                format!("{}/{}", ip, prefix)
            }
            AddrEntry::Other(s) => s.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ");

    let new_addr_line = format!("addresses: [{}]", new_addr_list);
    content = addr_re
        .replace(&content, new_addr_line)
        .to_string();

    if let Some(gw) = gw {
        let gw_re =
            Regex::new(r"(?m)^\s*gateway4:\s*.+$").unwrap();
        if gw_re.is_match(&content) {
            content = gw_re
                .replace(&content, format!("      gateway4: {}", gw))
                .to_string();
        }
    }

    fs::write(&file, content)
        .await
        .map_err(|e| format!("write {:?} failed: {}", file, e))?;

    run_cmd_status("netplan", &["apply"])
        .await
        .map_err(|e| format!("netplan apply failed: {}", e))?;

    log_info!(
        "netplan persisted iface={} source={} -> primary={}",
        iface,
        source_ip,
        primary_ip
    );

    Ok(())
}

    pub async fn get_primary_ip_of_main_interface(&self) -> Result<String, String> {
        let out = run_cmd_capture("ip", &["-o", "-4", "addr", "show", "dev", &self.main_interface]).await
            .map_err(|e| format!("ip addr show failed: {}", e))?;

        let re = regex::Regex::new(r"^\d+:\s+[^:\s]+\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)").unwrap();

        for line in out.lines() {
            if let Some(cap) = re.captures(line) {
                let addr = cap.get(1).unwrap().as_str();
                if !line.contains("secondary") {
                    return Ok(addr.to_string());
                }
            }
        }

        Err(format!("No primary IP found on interface {}", self.main_interface))
    }

    fn build_upload_agent_ip_json(&self, agent_ip: &str) -> String {
        json!({ "ip": agent_ip }).to_string()
    }
}
fn ip_list_contains(ip_list: &str, ip: &str) -> bool {
    ip_list
        .split(',')
        .map(|s| s.trim())
        .any(|item| item == ip)
}
fn strip_ip_prefix(ip: &str) -> &str {
    match ip.find('/') {
        Some(pos) => &ip[..pos],
        None => ip,
    }
}

