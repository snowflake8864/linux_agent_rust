//! 策略快照模块
//!
//! 提供 `dump_all_policies()`，将所有当前生效的策略以 JSON 形式汇总，
//! 供 gRPC 策略查询接口使用。策略仅从内存态（NETINFO_CONFIG、gRPC 缓存、
//! POLICY_MANAGER 等）读取，不写盘，也不从任何本地文件加载。

use logging::log_warn;

/// 获取所有当前策略的完整 JSON 对象（供 gRPC 等外部调用）
pub fn dump_all_policies() -> serde_json::Value {
    let (whitelist, blacklist) = read_process_policy();
    serde_json::json!({
        "config": read_current_config(),
        "process_policy": {
            "description": "进程管控策略 — 白名单/黑名单 hash 列表",
            "whitelist": whitelist,
            "blacklist": blacklist,
        },
        "dir_policy": read_dir_policy(),
        "extort_policy": read_extort_policy(),
        "ip_block_policy": read_ip_block_policy(),
        "ip_black_policy": read_ip_black_policy(),
        "virtual_port": read_virtual_port_policy(),
        "peripheral_policy": read_peripheral_policy(),
        "outreach_rules": read_outreach_rules(),
        "trust_dir": read_trust_dir(),
        "backend_mode": read_backend_info(),
    })
}

// ── 各策略读取函数 ──

/// 读取当前配置（开关/保护项）
fn read_current_config() -> serde_json::Value {
    let cfg = config::net_info::NETINFO_CONFIG.lock().unwrap();
    serde_json::json!({
        "description": "Agent 运行时配置 — 各项开关与保护模式",
        "switches": {
            "file_switch": cfg.file_switch,
            "file_protect": cfg.file_protect,
            "proc_switch": cfg.proc_switch,
            "proc_protect": cfg.proc_protect,
        },
        "extortion": {
            "extortion_switch": cfg.extortion_switch,
            "extortion_protect": cfg.extortion_protect,
        },
        "network": {
            "open_port_switch": cfg.open_port_switch,
            "dynamic_switch": cfg.dynamic_switch,
            "internet_switch": cfg.internet_switch,
        },
        "logging": {
            "syslog_inner_switch": cfg.syslog_inner_switch,
            "syslog_outer_switch": cfg.syslog_outer_switch,
            "syslog_dns_switch": cfg.syslog_dns_switch,
            "syslog_process_switch": cfg.syslog_process_switch,
            "syslog_login_switch": cfg.syslog_login_switch,
            "log_proto": cfg.log_proto,
            "log_sent": cfg.log_sent,
        },
        "peripheral": {
            "usb_switch": cfg.usb_switch,
            "usb_protect": cfg.usb_protect,
        },
        "self_protect": cfg.self_protect_switch,
        "outreach": {
            "outreach_switch": cfg.outreach_switch,
            "outreach_time": cfg.outreach_time,
        },
        "baseline": {
            "baseline_switch": cfg.baseline_switch,
            "baseline_time": cfg.baseline_time,
        },
        "hardware": {
            "hardware_switch": cfg.hardware_switch,
            "hardware_time": cfg.hardware_time,
        },
        "scheduling": {
            "cron_time": cfg.cron_time,
            "module_switch": cfg.module_switch,
        },
        "log_ip_port": cfg.log_ip_port,
        "backend_mode": cfg.backend_mode,
        "ifcfg": cfg.ifcfg,
    })
}

/// 读取进程黑白名单策略
fn read_process_policy() -> (Vec<String>, Vec<String>) {
    let mgr = process_mgr::POLICY_MANAGER.lock().unwrap();
    (mgr.get_white_list(), mgr.get_black_list())
}

/// 读取目录保护策略（从 gRPC 缓存读取）
fn read_dir_policy() -> serde_json::Value {
    let cache = grpc_gateway::notify::DIR_POLICY_CACHE.lock().unwrap();
    let rules: Vec<serde_json::Value> = cache
        .iter()
        .map(|r| {
            serde_json::json!({
                "dir": r.dir,
                "type": r.typ,
                "pid": r.pid,
            })
        })
        .collect();
    serde_json::json!({
        "description": "目录保护策略 — 受监控/保护的目录列表",
        "count": rules.len(),
        "rules": rules,
    })
}

/// 读取勒索防护策略（文件后缀保护）
fn read_extort_policy() -> serde_json::Value {
    let cache = grpc_gateway::notify::EXTORT_POLICY_CACHE.lock().unwrap();
    let rules: Vec<serde_json::Value> = cache
        .iter()
        .map(|r| {
            serde_json::json!({
                "file_suffix": r.file_type,
                "type": r.typ,
                "trusted_processes": r.map_comm,
            })
        })
        .collect();
    serde_json::json!({
        "description": "勒索软件防护策略 — 受保护的文件后缀及可信进程",
        "count": rules.len(),
        "rules": rules,
    })
}

/// 读取 IP 阻断策略
fn read_ip_block_policy() -> serde_json::Value {
    // IP_POLICIES 存储所有 IP 策略（netblock和black_ip共用同一个 HashMap）
    // 通过 direction 区分：direction != 0 为 netblock 策略
    let guard = match netblock::ip_policy::IP_POLICIES.try_read() {
        Ok(g) => g,
        Err(e) => {
            log_warn!("[policy_writer] IP_POLICIES 读锁获取失败: {}", e);
            return serde_json::json!({
                "description": "IP 阻断策略",
                "error": "无法读取（锁被占用）",
                "rules": []
            });
        }
    };
    let policies: Vec<serde_json::Value> = guard
        .iter()
        .filter(|(_, p)| p.direction != 0) // direction=0 的是 black_ip
        .map(|(ip, p)| {
            serde_json::json!({
                "ip": ip,
                "direction": p.direction,
                "duration_secs": p.duration,
                "is_ipv6": p.is_ipv6,
            })
        })
        .collect();
    serde_json::json!({
        "description": "IP 阻断策略 — 动态阻断的 IP 列表（含过期时间）",
        "count": policies.len(),
        "rules": policies,
    })
}

/// 读取 IP 黑名单策略
fn read_ip_black_policy() -> serde_json::Value {
    let guard = match netblock::ip_policy::IP_POLICIES.try_read() {
        Ok(g) => g,
        Err(e) => {
            log_warn!("[policy_writer] IP_POLICIES 读锁获取失败: {}", e);
            return serde_json::json!({
                "description": "IP 黑名单策略",
                "error": "无法读取（锁被占用）",
                "rules": []
            });
        }
    };
    let policies: Vec<serde_json::Value> = guard
        .iter()
        .filter(|(_, p)| p.direction == 0) // direction=0 是 black_ip
        .map(|(ip, p)| {
            serde_json::json!({
                "ip": ip,
                "direction": p.direction,
                "is_ipv6": p.is_ipv6,
            })
        })
        .collect();
    serde_json::json!({
        "description": "IP 黑名单策略 — 永久黑名单 IP 列表",
        "count": policies.len(),
        "rules": policies,
    })
}

/// 读取虚拟端口策略
fn read_virtual_port_policy() -> serde_json::Value {
    let cache = grpc_gateway::notify::VIRTUAL_PORT_CACHE.lock().unwrap();
    let rules: Vec<serde_json::Value> = cache
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "source_ip": r.source_ip,
                "source_port_start": r.source_port_start,
                "source_port_end": r.source_port_end,
                "dest_ip": r.dest_ip,
                "dest_port": r.dest_port,
                "dest_port_type": r.dest_port_type,
                "protocol": r.protocol,
                "type": r.r#type,
                "alarm_level": r.alarm_level,
            })
        })
        .collect();
    serde_json::json!({
        "description": "虚拟端口规则 — 端口映射/重定向规则",
        "count": rules.len(),
        "rules": rules,
    })
}

/// 读取外设管控策略
fn read_peripheral_policy() -> serde_json::Value {
    let guard = udisk::list::SHARED_USB_LIST.lock().unwrap();
    let whitelist: Vec<serde_json::Value> = guard
        .get_whitelist()
        .iter()
        .map(|d| {
            serde_json::json!({
                "eid": d.perpheral_eid,
                "name": d.perpheral_name,
                "type": d.type_,
                "intro": d.intro,
            })
        })
        .collect();
    let blacklist: Vec<serde_json::Value> = guard
        .get_blacklist()
        .iter()
        .map(|d| {
            serde_json::json!({
                "eid": d.perpheral_eid,
                "name": d.perpheral_name,
                "type": d.type_,
                "intro": d.intro,
            })
        })
        .collect();
    serde_json::json!({
        "description": "外设管控策略 — USB 设备白名单/黑名单",
        "whitelist_count": whitelist.len(),
        "blacklist_count": blacklist.len(),
        "whitelist": whitelist,
        "blacklist": blacklist,
    })
}

/// 读取外联探测规则
fn read_outreach_rules() -> serde_json::Value {
    let rules: Vec<serde_json::Value> = task::net_reach_rule::get_global_outreach_rules()
        .iter()
        .map(|r| {
            serde_json::json!({
                "addr": r.addr,
                "method": r.method,
                "type": r.r#type,
            })
        })
        .collect();
    serde_json::json!({
        "description": "外联探测规则 — 网络可达性探测目标",
        "count": rules.len(),
        "rules": rules,
    })
}

/// 读取信任目录
fn read_trust_dir() -> serde_json::Value {
    let cache = grpc_gateway::notify::TRUST_DIR_CACHE.lock().unwrap();
    let dirs: Vec<serde_json::Value> = cache
        .iter()
        .map(|d| {
            serde_json::json!({
                "dir": d.dir,
                "type": d.r#type,
                "is_extend": d.is_extend,
            })
        })
        .collect();
    serde_json::json!({
        "description": "信任目录 — 全局信任目录（白名单目录）",
        "count": dirs.len(),
        "dirs": dirs,
    })
}

/// 读取后端模式信息
fn read_backend_info() -> serde_json::Value {
    let (configured, effective, interface) = {
        let hub = crate::AgentDataHub::new();
        hub.get_backend_mode()
    };
    serde_json::json!({
        "description": "后端模式信息",
        "configured": configured,
        "effective": effective,
        "interface": interface,
    })
}
