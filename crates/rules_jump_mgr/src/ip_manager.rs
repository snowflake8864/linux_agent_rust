//src/ip_manager.rs
use crate::{IpJumpConfig, PutIpJumpInfo, SecondaryIPInfo};
use ipnet::Ipv4Net;
use crate::utils::*;
use tokio::sync::RwLock;
use std::sync::Arc;
use logging::{log_info, log_error};
use tokio::time::{interval, Duration};

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
}

impl IpJumpManager {
    /// 创建新的 IpJumpManager 实例，基于 server_ip 确定主接口，并返回 Arc 包装的共享实例
    pub fn new(main_interface: &str) -> Arc<Self> {
        Arc::new(IpJumpManager {
            secondary_ips: Arc::new(RwLock::new(Vec::new())),
            tick_counter: Arc::new(RwLock::new(0)),
            main_interface:main_interface.to_string(),
        })
    }

    /// 增加 tick 计数器
    async fn increment_tick(&self) -> u64 {
        let mut tick = self.tick_counter.write().await;
        *tick = tick.wrapping_add(1);
        //log_info!("TICK_COUNTER incremented to: {}", *tick);
        *tick
    }

    /// 启动定时清理任务
    pub async fn start_periodic_cleanup(self: Arc<Self>, interval_duration: Duration) {
        let mut interval = interval(interval_duration);
        loop {
            interval.tick().await;
            //log_info!("正在执行定期清理...");
            self.do_periodic_cleanup().await;
        }
    }

    /// 获取主接口的主 IP
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

    /// 添加 secondary ip 记录并在系统中添加地址（如果不存在）
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

    /// 检查是否存在 ESTABLISHED 到 target_ip 的连接
    pub fn has_established_connection(&self, target_ip: &str) -> bool {
        crate::utils::has_established_connection(target_ip)
    }

//===

    pub async fn do_periodic_cleanup(&self) {
        // tick 由定时任务增加一次
        let tick = self.increment_tick().await;

        // 收集过期项 (interface, ip, prefix_len) 到一个临时列表
        let mut expired: Vec<(String, String, u8)> = Vec::new();
        {
            let list = self.secondary_ips.read().await;
            for info in list.iter() {
                if tick.saturating_sub(info.added_tick) >= AGING_TICKS {
                    expired.push((info.interface.clone(), info.ip.clone(), info.prefix_len));
                }
            }
        }

        // 尝试删除系统上的 IP，每次删除成功才从内存中移除记录
        for (iface, ip, prefix) in expired.iter() {
            log_info!("Periodic cleanup: attempting to remove aged secondary IP {} on {} (prefix {})", ip, iface, prefix);
            match self.try_remove_ip_from_system(iface, ip, *prefix).await {
                Ok(()) => {
                    // 如果系统删除成功，从 secondary_ips 中移除
                    let mut list = self.secondary_ips.write().await;
                    let before = list.len();
                    list.retain(|x| !(x.interface == *iface && x.ip == *ip));
                    let after = list.len();
                    log_info!("Removed aged IP {} on {} from system and list (before {}, after {})", ip, iface, before, after);
                }
                Err(e) => {
                    log_error!("Failed to remove aged IP {} on {}: {}", ip, iface, e);
                    // 不从内存删除记录，留给下次重试
                }
            }
        }

        let list = self.secondary_ips.read().await;
        //log_info!("Periodic cleanup completed, remaining secondary IPs: {:?}", *list);
    }

    /// 尝试删除系统上的 IP：优先用 prefix 删除，失败会尝试不带 prefix 的删除；返回 Ok 表示系统确实没有该地址（或删除成功）
    async fn try_remove_ip_from_system(&self, iface: &str, ip: &str, prefix: u8) -> Result<(), String> {
        // 1) 尝试精确带前缀删除
        let with_prefix = format!("{}/{}", ip, prefix);
        log_info!("try_remove_ip_from_system: running: ip addr del {} dev {}", with_prefix, iface);
        match run_cmd_capture("ip", &["addr", "del", &with_prefix, "dev", iface]).await {
            Ok(out) => {
                // 即使 ip 命令有输出，也要再确认这个 IP 是否仍然在接口上
                log_info!("ip addr del (with prefix) stdout: {}", out);
                // 检查是否仍然存在
                if !ip_exists_on_iface(iface, ip).await {
                    return Ok(());
                } else {
                    log_error!("After deleting {} (with prefix), ip still exists on {}", with_prefix, iface);
                }
            }
            Err(err) => {
                log_error!("ip addr del (with prefix) failed: {} (cmd stderr/stdout)", err);
                // 继续尝试不带前缀
            }
        }

        // 2) 兜底：尝试不带前缀删除（有时前缀不一致导致前一步无效）
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

    /// 删除 secondary ip（从系统和列表） - 这个函数保留，但改为调用 try_remove_ip_from_system，
    /// 如果成功则从列表中移除；如果失败则返回错误（不盲目移除列表）
    pub async fn remove_secondary_ip(&self, iface: &str, ip: &str) -> Result<(), String> {
        // 查找 prefix（尽量从内存里找到）
        let prefix_opt = {
            let list = self.secondary_ips.read().await;
            list.iter().find(|x| x.interface == iface && x.ip == ip).map(|x| x.prefix_len)
        };

        if let Some(p) = prefix_opt {
            log_info!("remove_secondary_ip: found prefix {} for {} on {}", p, ip, iface);
            // 使用 try_remove_ip_from_system 尝试删除系统上地址
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
            // 没有 prefix 信息，尝试不带 prefix 的删除
            log_info!("remove_secondary_ip: prefix not found for {} on {}, trying without prefix", ip, iface);
            match self.try_remove_ip_from_system(iface, ip, 0).await {
                Ok(()) => {
                    // 仍然尝试从内存移除所有匹配 ip/interface 的记录
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

}
