//src/ip_manager.rs
use crate::{IpJumpConfig, PutIpJumpInfo, SecondaryIPInfo};
use ipnet::Ipv4Net;
use crate::utils::*;
use tokio::sync::RwLock;
use std::sync::Arc;
use logging::{log_info, log_error};
use tokio::time::{interval, Duration};
use net_client::core::NetClient;
use serde_json::json;

#[derive(Debug, Clone)]
pub struct NetworkBackup {
    pub ip: String,
    pub netmask: String,
    pub gateway: Option<String>,
    pub interface: String,
}

const AGING_TICKS: u64 = 2;

type SharedSecondaryList = Arc<RwLock<Vec<SecondaryIPInfo>>>;

pub struct IpJumpManager {
    secondary_ips: SharedSecondaryList,
    tick_counter: Arc<RwLock<u64>>,
    main_interface: String,
    last_upload_failed: Arc<RwLock<bool>>, 
}

impl IpJumpManager {
    pub fn new(main_interface: &str) -> Arc<Self> {
        Arc::new(IpJumpManager {
            secondary_ips: Arc::new(RwLock::new(Vec::new())),
            tick_counter: Arc::new(RwLock::new(0)),
            main_interface:main_interface.to_string(),
            last_upload_failed: Arc::new(RwLock::new(false)),
        })
    }

    async fn cleanup_old_secondary(&self, keep_ip: &str) {
        let snapshot = {
            let list = self.secondary_ips.read().await;
            list.clone()
        };

        for entry in snapshot.iter() {
            if entry.ip != keep_ip {
                let iface = entry.interface.clone();
                let ip = entry.ip.clone();
                let prefix = entry.prefix_len;

                log_info!(
                    "cleanup_old_secondary: removing old secondary {} on {} (prefix {})",
                    ip, iface, prefix
                );

                // 删除系统 IP
                let _ = self.try_remove_ip_from_system(&iface, &ip, prefix).await;
                // 删除内存记录
                let mut list = self.secondary_ips.write().await;
                list.retain(|x| x.ip != ip || x.interface != iface);
            }
        }
    }

    async fn increment_tick(&self) -> u64 {
        let mut tick = self.tick_counter.write().await;
        *tick = tick.wrapping_add(1);
        *tick
    }

    pub async fn start_periodic_cleanup(self: Arc<Self>, base_url: &str, token: Option<String>, interval_duration: Duration) {
        let mut interval = interval(interval_duration);
        loop {
            interval.tick().await;
            self.do_periodic_cleanup(base_url,token.clone()).await;
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
                    log_info!("Source IP {} is secondary, using primary IP {} on {}", source_ip, primary, self.main_interface);
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

    /// 执行 IP jump，包含：备份、删除 source ip、添加 target ip、记录 secondary、设置网关
    pub async fn do_ip_jump_async(&self, mut config: IpJumpConfig, info: &mut PutIpJumpInfo) -> Result<(), String> {
        log_info!("Starting IP jump: {} -> {} (gw={})", config.source_ip, config.target_ip, config.gateway);

        // 1. 检查 source_ip 是否是次要 IP 或不存在，如果是，则替换为主 IP
        let (source_ip, _interface) = self.get_primary_ip(&config.source_ip).await?;
        if source_ip != config.source_ip {
            log_info!("Adjusted source_ip from {} to primary IP {}", config.source_ip, source_ip);
            config.source_ip = source_ip.clone();
        }

        // 在变更前清理旧 secondary
        self.cleanup_old_secondary(&config.source_ip).await;

        // 2. 备份 interface info for source_ip
        log_info!("Backing up interface for IP: {}", config.source_ip);
        let backup = self.backup_interface(&config.source_ip).await.map_err(|e| {
            log_error!("backup_interface failed: {}", e);
            e
        })?;
        log_info!("Backup created: {:?}", backup);

        // 3. parse prefixes
        let src_prefix = netmask_to_prefix(&backup.netmask).map_err(|e| e.to_string())?;
        let (target_ip, target_prefix) = parse_cidr(&config.target_ip).map_err(|e| e.to_string())?;
        log_info!("Source prefix: {}, Target IP: {}, Target prefix: {}", src_prefix, target_ip, target_prefix);

        // 4. remove source ip from device
        log_info!("Removing source IP: {}/{} from {}", config.source_ip, src_prefix, backup.interface);
        if let Err(e) = self.run_ip_cmd(&["addr", "del", &format!("{}/{}", config.source_ip, src_prefix), "dev", &backup.interface]).await {
            log_error!("addr del failed: {}, attempt restore", e);
            log_info!("addr del failed: {}, attempt restore", e);
            let _ = self.restore_backup(&backup).await;
            return Err(format!("addr del failed: {}", e));
        }

        // 5. add target ip
        log_info!("Adding target IP: {}/{} to {}", target_ip, target_prefix, backup.interface);
        if let Err(e) = self.run_ip_cmd(&["addr", "add", &format!("{}/{}", target_ip, target_prefix), "dev", &backup.interface]).await {
            log_error!("addr add failed: {}, restoring", e);
            let _ = self.restore_backup(&backup).await;
            return Err(format!("addr add failed: {}", e));
        }

        // 6. add secondary ip record for original source ip
        let tick = self.increment_tick().await;
        log_info!("Adding secondary IP: {} on {}", config.source_ip, backup.interface);
        if let Err(e) = self.add_secondary_ip(&backup.interface, &config.source_ip, &backup.netmask, src_prefix, tick).await {
            log_error!("add_secondary_ip warning: {}", e);
        }

        // 7. set gateway if provided
        if !config.gateway.trim().is_empty() {
            log_info!("Setting gateway: {} on {}", config.gateway, backup.interface);
            if let Err(e) = self.set_gateway(&config.gateway, &backup.interface).await {
                log_error!("set_gateway failed: {}, restoring", e);
                let _ = self.restore_backup(&backup).await;
                return Err(format!("set gateway failed: {}", e));
            }
        }

        // fill info
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

    /// 根据某个 IP 找到绑定该 IP 的 interface、netmask 并返回备份信息
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

    /// 获取默认网关 ip
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

    /// 通用 ip 子命令封装
    pub async fn run_ip_cmd(&self, args: &[&str]) -> Result<(), String> {
        run_cmd_status("ip", args).await.map_err(|e| e)
    }

    /// 指定网关 + dev
    pub async fn set_gateway(&self, gateway: &str, iface: &str) -> Result<(), String> {
        let _ = run_cmd_status("ip", &["route", "del", "default", "dev", iface]).await;
        run_cmd_status("ip", &["route", "add", "default", "via", gateway, "dev", iface]).await
            .map_err(|e| format!("set_gateway failed: {}", e))
    }

    /// 恢复备份
    pub async fn restore_backup(&self, backup: &NetworkBackup) -> Result<(), String> {
        let prefix = netmask_to_prefix(&backup.netmask).map_err(|e| e.to_string())?;
        let _ = self.run_ip_cmd(&["addr", "add", &format!("{}/{}", backup.ip, prefix), "dev", &backup.interface]).await;
        if let Some(gw) = &backup.gateway {
            let _ = self.set_gateway(gw, &backup.interface).await;
        }
        Ok(())
    }

    pub async fn add_secondary_ip(&self, iface: &str, ip: &str, netmask: &str, prefix: u8, tick: u64) -> Result<(), String> {
        log_info!("Attempting to add secondary IP: {} on {}, tick: {}", ip, iface, tick);
        let mut list = self.secondary_ips.write().await;

        // 检查是否已存在相同的 IP 和接口
        if let Some(e) = list.iter_mut().find(|x| x.interface == iface && x.ip == ip) {
            e.added_tick = tick; // 更新 tick
            log_info!("Updated existing secondary IP: {} on {}", ip, iface);
            return Ok(());
        }

        // 添加新的 secondary IP 记录
        list.push(SecondaryIPInfo {
            interface: iface.to_string(),
            ip: ip.to_string(),
            netmask: netmask.to_string(),
            prefix_len: prefix,
            added_tick: tick,
        });

        // 如果系统上没有这个 IP，则添加到接口
        if !ip_exists_on_iface(iface, ip).await {
            self.run_ip_cmd(&["addr", "add", &format!("{}/{}", ip, prefix), "dev", iface])
                .await
                .map_err(|e| format!("failed to add secondary ip to system: {}", e))?;
            log_info!("Added IP to system: {} on {}", ip, iface);
        }

        log_info!("Added secondary IP: {} on {}, list len: {}", ip, iface, list.len());
        Ok(())
    }
    /// 查找与 gateway 同网段的接口名
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
        let tick = self.increment_tick().await;
        let mut expired: Vec<(String, String, u8)> = Vec::new();
        {
            let list = self.secondary_ips.read().await;
            for info in list.iter() {
                if tick.saturating_sub(info.added_tick) >= AGING_TICKS {
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

        // 判断是否进入上传逻辑
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
                        *failed = false; // 清空失败标记
                    }
                    Err(e) => {
                        log_error!("Failed to upload periodic IP jump result: {}, will retry next time", e);
                        let mut failed = self.last_upload_failed.write().await;
                        *failed = true; // 标记失败，下次重试
                    }
                }

                // nmcli 持久化 primary IP
                if self.has_nmcli().await {
                    if let Ok(primary_ip) = self.get_primary_ip_of_main_interface().await {
                        if let Err(e) = self.nmcli_update_primary_ip(&self.main_interface, &primary_ip).await {
                            log_error!("Failed to persist primary IP using nmcli: {}", e);
                        }
                    }
                }
            } else {
                log_error!("Cannot get local agent IP for periodic upload");
            }
        }
    }
    async fn try_remove_ip_from_system(&self, iface: &str, ip: &str, prefix: u8) -> Result<(), String> {
        let with_prefix = format!("{}/{}", ip, prefix);
        log_info!("try_remove_ip_from_system: running: ip addr del {} dev {}", with_prefix, iface);
        match run_cmd_capture("ip", &["addr", "del", &with_prefix, "dev", iface]).await {
            Ok(out) => {
                log_info!("ip addr del (with prefix) stdout: {}", out);
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
    pub async fn remove_secondary_ip(&self, iface: &str, ip: &str) -> Result<(), String> {
        let prefix_opt = {
            let list = self.secondary_ips.read().await;
            list.iter().find(|x| x.interface == iface && x.ip == ip).map(|x| x.prefix_len)
        };

        if let Some(p) = prefix_opt {
            log_info!("remove_secondary_ip: found prefix {} for {} on {}", p, ip, iface);
            match self.try_remove_ip_from_system(iface, ip, p).await {
                Ok(()) => {
                    // 成功则从内存中删除记录
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
        let json_data = build_upload_agent_ip_json(agent_ip);
        log_info!("Reporting putIpJump: {} => {}", url, json_data);

        // 创建客户端，如果失败直接返回 Err
        let net_client = NetClient::new(Some(base_url.to_string()), true)
            .map_err(|e| format!("创建 NetClient 失败: {}", e))?;

        // 发送请求，如果失败直接返回 Err
        let response = net_client
            .post_data_async(&url, &json_data, Duration::from_secs(10), token_str)
            .await
            .map_err(|err| {
                log_info!("发送指标失败: {}", err);
                eprintln!("发送指标失败: {}", err);
                format!("发送指标失败: {}", err)
            })?;

        log_info!("服务器响应: {}", response);
        Ok(())
    }

    pub async fn nmcli_update_primary_ip(&self, iface: &str, ip: &str) -> Result<(), String> {
        // 1. 获取当前 IP 的 prefix
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

        // 2. 获取当前 nmcli connection
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

        // 3. 修改 ipv4.addresses
        let addr = format!("{}/{}", ip, prefix);
        let status = run_cmd_status("nmcli", &["connection", "modify", &conn_name, "ipv4.addresses", &addr]).await;
        status.map_err(|e| format!("nmcli modify ipv4.addresses failed: {}", e))?;

        // 4. 确保 ipv4.method 是 manual
        let status = run_cmd_status("nmcli", &["connection", "modify", &conn_name, "ipv4.method", "manual"]).await;
        status.map_err(|e| format!("nmcli modify ipv4.method failed: {}", e))?;

        // 5. 重启连接应用配置
        let status = run_cmd_status("nmcli", &["connection", "up", &conn_name]).await;
        status.map_err(|e| format!("nmcli connection up failed: {}", e))?;

        log_info!("Primary IP {} on {} persisted via nmcli (connection: {})", ip, iface, conn_name);
        Ok(())
    }
    pub async fn has_nmcli(&self) -> bool {
        run_cmd_status("which", &["nmcli"]).await.is_ok()
    }
    pub async fn get_primary_ip_of_main_interface(&self) -> Result<String, String> {
        let out = run_cmd_capture("ip", &["-o", "-4", "addr", "show", "dev", &self.main_interface]).await
            .map_err(|e| format!("ip addr show failed: {}", e))?;

        let re = regex::Regex::new(r"^\d+:\s+[^:\s]+\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)").unwrap();

        for line in out.lines() {
            if let Some(cap) = re.captures(line) {
                let addr = cap.get(1).unwrap().as_str();
                if !line.contains("secondary") {
                    // 找到 primary IP
                    return Ok(addr.to_string());
                }
            }
        }

        Err(format!("No primary IP found on interface {}", self.main_interface))
    }
}

pub fn build_upload_agent_ip_json(agent_ip: &str) -> String {
    let json_data = json!({
        "ip": agent_ip,
    });
    json_data.to_string()
}

