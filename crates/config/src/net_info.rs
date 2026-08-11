//crates/config/src/net_info.rs
use configparser::ini::Ini;
use hostinfo::system_info::SystemInfo;
use hostinfo::{agent_uid, ip_mac};
use logging::{log_error, log_info};
use std::fs;
use std::fs::File;
use std::io::{self, Write};
use std::process::Command;

#[derive(Debug, Default, Clone)]
pub struct NetInfoConfig {
    pub app_path: String,
    pub mid: String,
    pub ver: String,
    pub com_time: u32,
    pub cron_time: u32,
    pub extortion_protect: bool,
    pub extortion_switch: bool,
    pub self_protect_switch: bool,
    pub fast_time: u32,
    pub file_protect: bool,
    pub file_switch: bool,
    pub dynamic_switch: bool,
    pub log_ip_port: Option<String>,
    pub log_proto: u32,
    pub log_sent: u32,
    pub cli_port: u32,
    pub module_switch: u32,
    pub open_port_switch: bool,
    pub proc_protect: bool,
    pub proc_switch: bool,
    pub scan_file_time: u32,
    pub scan_proc_time: u32,
    pub server_ip_port: String,
    pub server_ip: String,
    pub server_port: u32,
    pub usb_protect: bool,
    pub usb_switch: bool,
    pub syslog_dns_switch: bool,
    pub syslog_outer_switch: bool,
    pub syslog_inner_switch: bool,
    pub syslog_process_switch: bool,
    pub syslog_login_switch: bool,
    pub internet_switch: bool,
        pub admission_switch: bool,
    pub baseline_switch: bool,
    pub baseline_time: u32,
    pub outreach_switch: bool,
    pub outreach_time: u32,
    pub hardware_switch: bool,
    pub hardware_time: u32,
    pub user_id: String,
    //=====host info
    pub dev_uid: String,
    pub macid: String,
    pub ips: String,
    pub ifcfg: String,
    pub os: String,
    pub memsize: String,
    pub cpu: String,
    pub hdsize: String,
    pub auth: String,
    pub host_name: String,
    pub mod_ver: String,
    pub arch_type: u8,
    pub is_offline_mode: bool,
    pub grpc_enabled: bool,
    pub grpc_dev_mode: bool,
    pub grpc_addr: String,
    pub grpc_dev_addr: String,
    pub grpc_batch_size: usize,
    pub grpc_allow_config_write_online: bool,
    pub grpc_alert_push: bool,
    pub vigilixav_enabled: bool,
    pub vigilixav_host: String,
    pub vigilixav_port: u16,
    pub vigilixav_timeout_secs: u64,
    pub vigilixav_pool_size: usize,
    pub vigilixav_connection_type: String,
    pub vigilixav_socket_path: String,
    pub install_time: i64,
    // 准入功能配置
    pub admission: AdmissionConfig,
    // SQLite 数据库配置
    pub sqlite_db: SqliteDbConfig,
    pub db_policy: DbPolicyConfig,
    // 跳变配置
    pub jump: JumpConfig,
    // gRPC 子服务开关
    pub grpc_svc: GrpcServices,
    // 系统组件开关
    pub system: SystemConfig,
    // 后端模式: "driver" | "ebpf"
    pub backend_mode: String,
    // eBPF 模块开关: 控制加载哪些 .bpf.o（[EBPF] 段）
    pub ebpf_file_agent: bool,
    pub ebpf_proc_agent: bool,
    pub ebpf_net_agent: bool,
}

/// 准入功能配置，对应 ini 中的 [ADMISSION] 段
/// 如果 ini 中没有 [ADMISSION] 段，所有字段取默认值（ENABLED=0，即不启用）
#[derive(Debug, Clone)]
pub struct AdmissionConfig {
    pub enabled: bool,           // 是否启用准入功能
    pub mode: u8,                // 0=关准入, 1=开准入, 2=自动检测
    pub retry_interval: u64,     // 自动检测网络异常时重试间隔（秒）
    pub max_retries: u32,        // 每轮最多重试次数
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        AdmissionConfig {
            enabled: false,       // 默认不启用
            mode: 0,              // 默认关闭准入
            retry_interval: 60,   // 默认60秒重试
            max_retries: 3,       // 默认3次
        }
    }
}

/// SQLite 基础设施配置，对应 ini 中的 [SQLITE_DB] 段
/// ENABLED=1 时创建 /opt/osec/db 目录并初始化 WAL 模式连接
/// ENABLED=0 时所有上层 DB 功能不可用（dsqlite_db crate 不初始化）
#[derive(Debug, Clone)]
pub struct SqliteDbConfig {
    pub enabled: bool,
}

impl Default for SqliteDbConfig {
    fn default() -> Self {
        SqliteDbConfig { enabled: false }
    }
}

/// DB 业务策略配置，对应 ini 中的 [DB_POLICY] 段
/// 仅当 [SQLITE_DB] ENABLED=1 时生效
/// 每个字段独立控制对应模块是否启用 SQLite 持久化
#[derive(Debug, Clone)]
pub struct DbPolicyConfig {
    pub alert_log: bool,            // ALERT_LOG — 告警日志持久化
    pub process_policy: bool,       // PROCESS_POLICY — 进程黑白名单双表
    pub known_executables: bool,    // KNOWN_EXECUTABLES — 非标准目录可执行文件记录
    pub jump_status: bool,          // JUMP_STATUS — IP跳变状态
    pub peripheral_policy: bool,    // PERIPHERAL_POLICY — USB外设黑白名单双表
    pub quarantine: bool,           // QUARANTINE — 病毒隔离/还原元数据（替代.meta文件）
    pub alert_max_rows: u32,        // ALERT_MAX_ROWS — 告警保留条数，0=不限制
}

impl Default for DbPolicyConfig {
    fn default() -> Self {
        DbPolicyConfig {
            alert_log: false,
            process_policy: false,
            known_executables: false,
            jump_status: false,
            peripheral_policy: false,
            quarantine: false,
            alert_max_rows: 0,
        }
    }
}

/// 跳变配置，对应 ini 中的 [JUMP] 段
/// ENABLED=0 时所有跳变功能不可用（gRPC JumpService 也不注册）
#[derive(Debug, Clone)]
pub struct JumpConfig {
    pub enabled: bool,      // ENABLED — 跳变总闸
    pub ip_jump: bool,      // IP_JUMP — IP 跳变
    pub pw_jump: bool,      // PW_JUMP — 口令跳变
}

impl Default for JumpConfig {
    fn default() -> Self {
        JumpConfig { enabled: false, ip_jump: true, pw_jump: true }
    }
}

/// gRPC 子服务开关，对应 ini 中 [GRPC] 段的子服务配置
/// 仅当 [GRPC] ENABLED=1 时生效
#[derive(Debug, Clone)]
pub struct GrpcServices {
    pub virus_scan: bool,    // VIRUS_SCAN — 病毒扫描服务（还要 VIGILIXAV）
    pub vuln_scan: bool,     // VULN_SCAN — 漏洞扫描服务
    pub jump: bool,          // JUMP — 跳变服务（还要 [JUMP] ENABLED）
    pub config: bool,        // CONFIG — 配置读写服务
    pub policy: bool,        // POLICY — 策略管理服务
    pub data_query: bool,    // DATA_QUERY — 数据查询服务
    pub backup: bool,        // BACKUP — 备份还原服务
    pub task: bool,          // TASK — 本地任务服务
    pub agent_status: bool,  // AGENT_STATUS — 状态上报服务
}

impl Default for GrpcServices {
    fn default() -> Self {
        GrpcServices {
            virus_scan:   true,
            vuln_scan:    false,
            jump:         false,
            config:       true,
            policy:       true,
            data_query:   true,
            backup:       true,
            task:         true,
            agent_status: true,
        }
    }
}

/// 系统组件开关，对应 ini 中的 [SYSTEM] 段
/// 控制非核心系统组件的启动
#[derive(Debug, Clone)]
pub struct SystemConfig {
    pub docker_monitor: bool,      // DOCKER_MONITOR — Docker 容器监控
    pub usb_hotplug: bool,         // USB_HOTPLUG — USB 热插拔监听
    pub connectivity_probe: bool,  // CONNECTIVITY_PROBE — 周期连通性探测
    pub ntp_sync: bool,            // NTP_SYNC — NTP 时间同步
}

impl Default for SystemConfig {
    fn default() -> Self {
        SystemConfig {
            docker_monitor: true,       // 默认开，兼容旧版
            usb_hotplug: true,          // 默认开，兼容旧版
            connectivity_probe: true,   // 核心功能，默认开
            ntp_sync: true,             // 默认开，兼容旧版
        }
    }
}

enum NetRule<'a> {
    ServerIpV4(&'a str),
    ServerPort(u32),
    LogIpPort(&'a str),
    VirtualOpenPort(bool),
}

fn ip_str_to_u32(ip: &str) -> Result<u32, String> {
    let parsed = ip
        .parse::<std::net::Ipv4Addr>()
        .map_err(|e| e.to_string())?;
    Ok(u32::from_be_bytes(parsed.octets()))
}

fn run_cmd_capture(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to execute {}: {}", cmd, e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "Command {} failed with status {}: {}",
            cmd, output.status, stderr
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.trim().to_string())
}

impl NetInfoConfig {
    /// 获取主接口（基于 server_ip）
    fn get_main_interface(server_ip: &str) -> Result<String, String> {
        let out = run_cmd_capture("ip", &["route", "get", server_ip])
            .map_err(|e| format!("ip route get {} failed: {}", server_ip, e))?;
        let re = regex::Regex::new(r"dev\s+(\S+)").map_err(|e| format!("Regex error: {}", e))?;
        for line in out.lines() {
            if let Some(cap) = re.captures(line) {
                let iface = cap.get(1).unwrap().as_str();
                if iface != "lo" {
                    return Ok(iface.to_string());
                }
            }
        }
        Err(format!(
            "No valid interface found for server_ip {}",
            server_ip
        ))
    }

    fn write_net_rule(&self, rule: NetRule) -> Result<(), String> {
        match rule {
            NetRule::ServerIpV4(ip) => {
                let ip_u32 = match ip_str_to_u32(ip) {
                    Ok(ip) => ip,
                    Err(e) => return Err(e),
                };
                self.write_raw("server_ipv4 ", &ip_u32.to_string())
            }
            NetRule::ServerPort(port) => self.write_raw("server_port ", &port.to_string()),
            NetRule::LogIpPort(log_ip_port) => self.write_raw("log_ip_port ", log_ip_port),
            NetRule::VirtualOpenPort(open_port_state) => self.write_raw(
                "vir_open_port_switch ",
                if open_port_state { "1" } else { "0" },
            ),
        }
    }

    fn write_raw(&self, rule_type: &str, value: &str) -> Result<(), String> {
        let content = format!("{} {}\n", rule_type, value);
        fs::write("/proc/osec/net_rules", content)
            .map_err(|e| format!("Failed to write to /proc/osec/net_rules: {}", e))
    }

    pub fn from_ini(ini: &Ini) -> Self {
        let mut config = NetInfoConfig::default();

        if let Some(mid) = ini.get("CLIENTINFO", "MID") {
            config.mid = mid;
        }

        config.ver = ini
            .get("SERVERINFO", "VERSION")
            .unwrap_or_else(|| "3.0.1_T9".to_string());

        if let Some(user_id) = ini.get("SERVERINFO", "USER_ID") {
            config.user_id = user_id;
        }

        if let Some(value) = ini.get("SERVERINFO", "COMTIME") {
            config.com_time = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "CRONTIME") {
            config.cron_time = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "EXTORTION_PROTECT") {
            config.extortion_protect = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "EXTORTION_SWITCH") {
            config.extortion_switch = matches!(value.trim(), "1");
            log_info!("===extortion_switch: {}", config.extortion_switch);
        }
        if let Some(value) = ini.get("SERVERINFO", "SELF_PROTECT_SWITCH") {
            config.self_protect_switch = matches!(value.trim(), "1");
            log_info!("===self_protect_switch: {}", config.self_protect_switch);
        }
        if let Some(value) = ini.get("SERVERINFO", "FASTTIME") {
            config.fast_time = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "FILE_PROTECT") {
            config.file_protect = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "FILE_SWITCH") {
            config.file_switch = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "DYNAMIC_SWITCH") {
            config.dynamic_switch = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "LOGIPPORT") {
            config.log_ip_port = Some(value);
        }
        if let Some(value) = ini.get("SERVERINFO", "LOGPROTO") {
            config.log_proto = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "LOGSENT") {
            config.log_sent = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "CLI_SERVER_PORT") {
            config.cli_port = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "MODULE_SWITCH") {
            config.module_switch = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "OPEN_PORT_SWITCH") {
            config.open_port_switch = matches!(value.trim(), "1");
            let _ = config.write_net_rule(NetRule::VirtualOpenPort(config.open_port_switch));
        }
        if let Some(value) = ini.get("SERVERINFO", "PROC_PROTECT") {
            config.proc_protect = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "PROC_SWITCH") {
            config.proc_switch = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "SCANFILETIME") {
            config.scan_file_time = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "SCANPROCTIME") {
            config.scan_proc_time = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "SERVERIPPORT") {
            config.server_ip_port = value;
        }

        if let Some(value) = ini.get("SERVERINFO", "SERVER_IP") {
            config.server_ip = value;

            if !config.server_ip.is_empty() {
                let ip_for_route = match Self::extract_ip(&config.server_ip) {
                    Some(ip) => ip,
                    None => {
                        log_error!(
                            "Failed to extract IP from server_ip: '{}', using raw value (may fail)",
                            config.server_ip
                        );
                        config.server_ip.clone()
                    }
                };

                config.ifcfg = Self::get_main_interface(&ip_for_route).unwrap_or_else(|e| {
                    log_error!(
                        "Failed to get main interface for IP '{}': {}, using default 'eth0'",
                        ip_for_route,
                        e
                    );
                    "eth0".to_string()
                });

                log_info!("Main interface set to: {}", config.ifcfg);
            }
        }

        if let Some(value) = ini.get("SERVERINFO", "SERVER_PORT") {
            config.server_port = value.parse().unwrap_or_default();
        }
        if let Some(value) = ini.get("SERVERINFO", "USB_PROTECT") {
            config.usb_protect = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "USB_SWITCH") {
            config.usb_switch = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "DNS_SWITCH") {
            config.syslog_dns_switch = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "INTERNAL_COMMUNICATION_SWITCH") {
            config.syslog_inner_switch = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "EXTERNAL_COMMUNICATION_SWITCH") {
            config.syslog_outer_switch = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "INTERNET_SWITCH") {
            config.internet_switch = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "ADMISSION_SWITCH") {
            config.admission_switch = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "OFFLINE_MODE") {
            config.is_offline_mode = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "SYSLOG_PROCESS_SWITCH") {
            config.syslog_process_switch = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SERVERINFO", "SYSLOG_LOGIN_SWITCH") {
            config.syslog_login_switch = matches!(value.trim(), "1");
        }

        if let Some(value) = ini.get("SERVERINFO", "HARDWARE_SWITCH") {
            config.hardware_switch = matches!(value.trim(), "1");
        }

        if let Some(value) = ini.get("SERVERINFO", "HARDWARE_TIME") {
            config.hardware_time = value.parse().unwrap_or_default();
        }

        if let Some(value) = ini.get("SERVERINFO", "BASELINE_SWITCH") {
            config.baseline_switch = matches!(value.trim(), "1");
        }

        if let Some(value) = ini.get("SERVERINFO", "BASELINE_TIME") {
            config.baseline_time = value.parse().unwrap_or_default();
        }

        if let Some(value) = ini.get("SERVERINFO", "OUTREACH_SWITCH") {
            config.outreach_switch = matches!(value.trim(), "1");
        }

        if let Some(value) = ini.get("SERVERINFO", "OUTREACH_TIME") {
            config.outreach_time = value.parse().unwrap_or_default();
        }

        if let Some(value) = ini.get("SERVERINFO", "INSTALL_TIME") {
            config.install_time = value.parse().unwrap_or_default();
        }

        if let Some(value) = ini.get("HOSTINFO", "DEV_UID") {
            config.dev_uid = value;
        }
        if let Some(value) = ini.get("HOSTINFO", "MACID") {
            config.macid = value;
        }
        if let Some(value) = ini.get("HOSTINFO", "IPS") {
            config.ips = value;
        }
        if let Some(value) = ini.get("HOSTINFO", "OS") {
            config.os = value;
        }
        if let Some(value) = ini.get("HOSTINFO", "MEMSIZE") {
            config.memsize = value;
        }
        if let Some(value) = ini.get("HOSTINFO", "CPU") {
            config.cpu = value;
        }
        if let Some(value) = ini.get("HOSTINFO", "HDSIZE") {
            config.hdsize = value;
        }
        if let Some(value) = ini.get("HOSTINFO", "AUTH") {
            config.auth = value;
        }
        if let Some(value) = ini.get("HOSTINFO", "HOSTNAME") {
            config.host_name = value;
        }

        // [GRPC] — gRPC 服务通用配置
        if let Some(value) = ini.get("GRPC", "ENABLED") {
            config.grpc_enabled = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("GRPC", "DEV_MODE") {
            config.grpc_dev_mode = matches!(value.trim(), "1");
        }
        config.grpc_addr = ini
            .get("GRPC", "GRPC_ADDR")
            .unwrap_or_else(|| "127.0.0.1:50051".to_string());
        config.grpc_dev_addr = ini
            .get("GRPC", "DEV_GRPC_ADDR")
            .unwrap_or_else(|| "0.0.0.0:50051".to_string());
        if let Some(value) = ini.get("GRPC", "BATCH_SIZE") {
            config.grpc_batch_size = value.parse().unwrap_or(100);
        } else {
            config.grpc_batch_size = 100;
        }
        if let Some(value) = ini.get("GRPC", "ALLOW_CONFIG_WRITE_ONLINE") {
            config.grpc_allow_config_write_online = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("GRPC", "ALERT_PUSH") {
            config.grpc_alert_push = matches!(value.trim(), "1");
        } else {
            config.grpc_alert_push = false; // 默认关闭
        }
        // [GRPC] 子服务开关
        if let Some(value) = ini.get("GRPC", "VIRUS_SCAN") {
            config.grpc_svc.virus_scan = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("GRPC", "VULN_SCAN") {
            config.grpc_svc.vuln_scan = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("GRPC", "JUMP") {
            config.grpc_svc.jump = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("GRPC", "CONFIG") {
            config.grpc_svc.config = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("GRPC", "POLICY") {
            config.grpc_svc.policy = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("GRPC", "DATA_QUERY") {
            config.grpc_svc.data_query = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("GRPC", "BACKUP") {
            config.grpc_svc.backup = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("GRPC", "TASK") {
            config.grpc_svc.task = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("GRPC", "AGENT_STATUS") {
            config.grpc_svc.agent_status = matches!(value.trim(), "1");
        }

        // [VIGILIXAV] — VigilixAV 病毒扫描配置
        if let Some(value) = ini.get("VIGILIXAV", "ENABLED") {
            config.vigilixav_enabled = matches!(value.trim(), "1");
        }
        config.vigilixav_host = ini
            .get("VIGILIXAV", "HOST")
            .unwrap_or_else(|| "127.0.0.1".to_string());
        if let Some(value) = ini.get("VIGILIXAV", "PORT") {
            config.vigilixav_port = value.parse().unwrap_or(3310);
        } else {
            config.vigilixav_port = 3310;
        }
        if let Some(value) = ini.get("VIGILIXAV", "TIMEOUT") {
            config.vigilixav_timeout_secs = value.parse().unwrap_or(60);
        } else {
            config.vigilixav_timeout_secs = 60;
        }
        if let Some(value) = ini.get("VIGILIXAV", "POOL_SIZE") {
            config.vigilixav_pool_size = value.parse().unwrap_or(10);
        } else {
            config.vigilixav_pool_size = 10;
        }

        config.vigilixav_connection_type = ini
            .get("VIGILIXAV", "CONNECTION_TYPE")
            .unwrap_or_else(|| "tcp".to_string());
        config.vigilixav_socket_path = ini
            .get("VIGILIXAV", "SOCKET_PATH")
            .unwrap_or_else(|| "/opt/clamav/var/run/clamd.sock".to_string());

        // [ADMISSION] 段 — 没有此段则全部默认（enabled=false）
        if let Some(value) = ini.get("ADMISSION", "ENABLED") {
            config.admission.enabled = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("ADMISSION", "MODE") {
            config.admission.mode = value.trim().parse().unwrap_or(0);
        }
        if let Some(value) = ini.get("ADMISSION", "RETRY_INTERVAL") {
            config.admission.retry_interval = value.trim().parse().unwrap_or(60);
        }
        if let Some(value) = ini.get("ADMISSION", "MAX_RETRIES") {
            config.admission.max_retries = value.trim().parse().unwrap_or(3);
        }

        // [BACKEND]
        config.backend_mode = ini
            .get("BACKEND", "MODE")
            .unwrap_or_else(|| "driver".to_string());

        // [EBPF] — 控制 eBPF 模式下加载哪些模块（.bpf.o）
        if let Some(value) = ini.get("EBPF", "FILE_AGENT") {
            config.ebpf_file_agent = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("EBPF", "PROC_AGENT") {
            config.ebpf_proc_agent = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("EBPF", "NET_AGENT") {
            config.ebpf_net_agent = matches!(value.trim(), "1");
        }

        // [SQLITE_DB] — SQLite 基础设施开关，默认关闭
        if let Some(value) = ini.get("SQLITE_DB", "ENABLED") {
            config.sqlite_db.enabled = matches!(value.trim(), "1");
        }

        // [DB_POLICY] — DB 业务特性开关，每个功能独立控制
        if let Some(value) = ini.get("DB_POLICY", "ALERT_LOG") {
            config.db_policy.alert_log = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("DB_POLICY", "PROCESS_POLICY") {
            config.db_policy.process_policy = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("DB_POLICY", "KNOWN_EXECUTABLES") {
            config.db_policy.known_executables = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("DB_POLICY", "JUMP_STATUS") {
            config.db_policy.jump_status = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("DB_POLICY", "PERIPHERAL_POLICY") {
            config.db_policy.peripheral_policy = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("DB_POLICY", "QUARANTINE") {
            config.db_policy.quarantine = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("DB_POLICY", "ALERT_MAX_ROWS") {
            config.db_policy.alert_max_rows = value.trim().parse().unwrap_or(0);
        }

        // [JUMP] — 跳变功能，默认关闭
        if let Some(value) = ini.get("JUMP", "ENABLED") {
            config.jump.enabled = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("JUMP", "IP_JUMP") {
            config.jump.ip_jump = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("JUMP", "PW_JUMP") {
            config.jump.pw_jump = matches!(value.trim(), "1");
        }

        // [SYSTEM] — 系统组件开关
        if let Some(value) = ini.get("SYSTEM", "DOCKER_MONITOR") {
            config.system.docker_monitor = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SYSTEM", "USB_HOTPLUG") {
            config.system.usb_hotplug = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SYSTEM", "CONNECTIVITY_PROBE") {
            config.system.connectivity_probe = matches!(value.trim(), "1");
        }
        if let Some(value) = ini.get("SYSTEM", "NTP_SYNC") {
            config.system.ntp_sync = matches!(value.trim(), "1");
        }

        config
    }

    pub fn to_ini(&self, file_name: &str) -> Result<(), io::Error> {
        let mut file = File::create(file_name)?;
        writeln!(file, "[CLIENTINFO]")?;
        writeln!(file, "MID={}", self.mid)?;
        writeln!(file, "[SERVERINFO]")?;
        writeln!(file, "USER_ID={}", self.user_id)?;
        writeln!(file, "COMTIME={}", self.com_time)?;
        writeln!(file, "CRONTIME={}", self.cron_time)?;
        writeln!(file, "EXTORTION_PROTECT={}", self.extortion_protect as u8)?;
        writeln!(file, "EXTORTION_SWITCH={}", self.extortion_switch as u8)?;
        writeln!(
            file,
            "SELF_PROTECT_SWITCH={}",
            self.self_protect_switch as u8
        )?;
        writeln!(file, "FASTTIME={}", self.fast_time)?;
        writeln!(file, "FILE_PROTECT={}", self.file_protect as u8)?;
        writeln!(file, "FILE_SWITCH={}", self.file_switch as u8)?;
        writeln!(
            file,
            "LOGIPPORT={}",
            self.log_ip_port.clone().unwrap_or_default()
        )?;
        writeln!(file, "LOGPROTO={}", self.log_proto)?;
        writeln!(file, "LOGSENT={}", self.log_sent)?;
        writeln!(file, "CLI_SERVER_PORT={}", self.cli_port)?;
        writeln!(file, "MODULE_SWITCH={}", self.module_switch)?;
        writeln!(file, "OPEN_PORT_SWITCH={}", self.open_port_switch as u8)?;
        writeln!(file, "PROC_PROTECT={}", self.proc_protect as u8)?;
        writeln!(file, "PROC_SWITCH={}", self.proc_switch as u8)?;
        writeln!(file, "DYNAMIC_SWITCH={}", self.dynamic_switch as u8)?;
        writeln!(file, "SCANFILETIME={}", self.scan_file_time)?;
        writeln!(file, "SCANPROCTIME={}", self.scan_proc_time)?;
        writeln!(file, "SERVERIPPORT={}", self.server_ip_port)?;
        writeln!(file, "SERVER_IP={}", self.server_ip)?;
        writeln!(file, "SERVER_PORT={}", self.server_port)?;
        writeln!(file, "USB_PROTECT={}", self.usb_protect as u8)?;
        writeln!(file, "USB_SWITCH={}", self.usb_switch as u8)?;
        writeln!(file, "DNS_SWITCH={}", self.syslog_dns_switch as u8)?;
        writeln!(
            file,
            "INTERNAL_COMMUNICATION_SWITCH={}",
            self.syslog_inner_switch as u8
        )?;
        writeln!(
            file,
            "EXTERNAL_COMMUNICATION_SWITCH={}",
            self.syslog_outer_switch as u8
        )?;
        writeln!(
            file,
            "SYSLOG_PROCESS_SWITCH={}",
            self.syslog_process_switch as u8
        )?;
        writeln!(
            file,
            "SYSLOG_LOGIN_SWITCH={}",
            self.syslog_login_switch as u8
        )?;
        writeln!(file, "INTERNET_SWITCH={}", self.internet_switch as u8)?;
                writeln!(file, "ADMISSION_SWITCH={}", self.admission_switch as u8)?;
        writeln!(file, "OFFLINE_MODE={}", self.is_offline_mode as u8)?;
        writeln!(file, "BASELINE_SWITCH={}", self.baseline_switch as u8)?;
        writeln!(file, "BASELINE_TIME={}", self.baseline_time)?;
        writeln!(file, "HARDWARE_SWITCH={}", self.hardware_switch as u8)?;
        writeln!(file, "HARDWARE_TIME={}", self.hardware_time)?;
        writeln!(file, "OUTREACH_SWITCH={}", self.outreach_switch as u8)?;
        writeln!(file, "OUTREACH_TIME={}", self.outreach_time)?;
        writeln!(file, "INSTALL_TIME={}", self.install_time)?;
        writeln!(file, "VERSION={}", self.ver)?;
        writeln!(file, "[HOSTINFO]")?;
        writeln!(file, "DEV_UID={}", self.dev_uid)?;
        writeln!(file, "MACID={}", self.macid)?;
        //writeln!(file, "IPS={}", self.ips)?;
        //writeln!(file, "IFCFG={}", self.ifcfg)?;
        //writeln!(file, "OS={}", self.os)?;
        //writeln!(file, "MEMSIZE={}", self.memsize)?;
        writeln!(file, "CPU={}", self.cpu)?;
        //writeln!(file, "HDSIZE={}", self.hdsize)?;
        writeln!(file, "AUTH={}", self.auth)?;
        writeln!(file, "HOSTNAME={}", self.host_name)?;
        writeln!(file, "[GRPC]")?;
        writeln!(file, "ENABLED={}", self.grpc_enabled as u8)?;
        writeln!(file, "DEV_MODE={}", self.grpc_dev_mode as u8)?;
        writeln!(file, "GRPC_ADDR={}", self.grpc_addr)?;
        writeln!(file, "DEV_GRPC_ADDR={}", self.grpc_dev_addr)?;
        writeln!(file, "BATCH_SIZE={}", self.grpc_batch_size)?;
        writeln!(file, "ALLOW_CONFIG_WRITE_ONLINE={}", self.grpc_allow_config_write_online as u8)?;
        writeln!(file, "ALERT_PUSH={}", self.grpc_alert_push as u8)?;
        writeln!(file, "VIRUS_SCAN={}", self.grpc_svc.virus_scan as u8)?;
        writeln!(file, "VULN_SCAN={}", self.grpc_svc.vuln_scan as u8)?;
        writeln!(file, "JUMP={}", self.grpc_svc.jump as u8)?;
        writeln!(file, "CONFIG={}", self.grpc_svc.config as u8)?;
        writeln!(file, "POLICY={}", self.grpc_svc.policy as u8)?;
        writeln!(file, "DATA_QUERY={}", self.grpc_svc.data_query as u8)?;
        writeln!(file, "BACKUP={}", self.grpc_svc.backup as u8)?;
        writeln!(file, "TASK={}", self.grpc_svc.task as u8)?;
        writeln!(file, "AGENT_STATUS={}", self.grpc_svc.agent_status as u8)?;
        writeln!(file, "[VIGILIXAV]")?;
        writeln!(file, "ENABLED={}", self.vigilixav_enabled as u8)?;
        writeln!(file, "HOST={}", self.vigilixav_host)?;
        writeln!(file, "PORT={}", self.vigilixav_port)?;
        writeln!(file, "TIMEOUT={}", self.vigilixav_timeout_secs)?;
        writeln!(file, "POOL_SIZE={}", self.vigilixav_pool_size)?;
        writeln!(
            file,
            "CONNECTION_TYPE={}",
            self.vigilixav_connection_type
        )?;
        writeln!(file, "SOCKET_PATH={}", self.vigilixav_socket_path)?;
        if self.vigilixav_socket_path.is_empty() {
            writeln!(file, "SOCKET_PATH=/opt/clamav/var/run/clamd.sock")?;
        }

        // [ADMISSION] 段
        writeln!(file, "[ADMISSION]")?;
        writeln!(file, "ENABLED={}", self.admission.enabled as u8)?;
        writeln!(file, "MODE={}", self.admission.mode)?;
        writeln!(file, "RETRY_INTERVAL={}", self.admission.retry_interval)?;
        writeln!(file, "MAX_RETRIES={}", self.admission.max_retries)?;

        // [BACKEND] 段
        writeln!(file, "[BACKEND]")?;
        writeln!(file, "MODE={}", self.backend_mode)?;

        // [EBPF] 段 — eBPF 模块开关
        writeln!(file, "[EBPF]")?;
        writeln!(file, "FILE_AGENT={}", self.ebpf_file_agent as u8)?;
        writeln!(file, "PROC_AGENT={}", self.ebpf_proc_agent as u8)?;
        writeln!(file, "NET_AGENT={}", self.ebpf_net_agent as u8)?;

        // [SQLITE_DB] 段 — SQLite 基础设施开关
        writeln!(file, "[SQLITE_DB]")?;
        writeln!(file, "ENABLED={}", self.sqlite_db.enabled as u8)?;

        // [DB_POLICY] 段 — DB 业务特性开关
        writeln!(file, "[DB_POLICY]")?;
        writeln!(file, "ALERT_LOG={}", self.db_policy.alert_log as u8)?;
        writeln!(file, "PROCESS_POLICY={}", self.db_policy.process_policy as u8)?;
        writeln!(file, "KNOWN_EXECUTABLES={}", self.db_policy.known_executables as u8)?;
        writeln!(file, "JUMP_STATUS={}", self.db_policy.jump_status as u8)?;
        writeln!(file, "PERIPHERAL_POLICY={}", self.db_policy.peripheral_policy as u8)?;
        writeln!(file, "QUARANTINE={}", self.db_policy.quarantine as u8)?;
        writeln!(file, "ALERT_MAX_ROWS={}", self.db_policy.alert_max_rows)?;

        // [JUMP] 段 — 跳变功能开关
        writeln!(file, "[JUMP]")?;
        writeln!(file, "ENABLED={}", self.jump.enabled as u8)?;
        writeln!(file, "IP_JUMP={}", self.jump.ip_jump as u8)?;
        writeln!(file, "PW_JUMP={}", self.jump.pw_jump as u8)?;

        // [SYSTEM] 段 — 系统组件开关
        writeln!(file, "[SYSTEM]")?;
        writeln!(file, "DOCKER_MONITOR={}", self.system.docker_monitor as u8)?;
        writeln!(file, "USB_HOTPLUG={}", self.system.usb_hotplug as u8)?;
        writeln!(file, "CONNECTIVITY_PROBE={}", self.system.connectivity_probe as u8)?;
        writeln!(file, "NTP_SYNC={}", self.system.ntp_sync as u8)?;

        Ok(())
    }

    pub fn acquire_host_info(&mut self) -> io::Result<()> {
        log_info!("========dev_id:{}", self.dev_uid);
        //if self.dev_uid.is_empty()
        {
            self.dev_uid = agent_uid::ensure_and_get_mgs_guid(&("/etc/.vedasystem"))
                .unwrap_or_else(|_| "unknown".to_string());
        }
        // 同步 uid 到 app.conf（供 EndpointSecurityApp GUI 读取）
        self.sync_uid_to_app_conf();
        log_info!("=====dev_id:{}", self.dev_uid);
        // MAC 地址必须始终从系统获取，不能信任 ini 缓存值
        // （ini 可能缓存了虚拟网卡/网关的 MAC）
        {
            let mac = ip_mac::get_mac().unwrap_or("unknown".to_string());
            log_info!("acquire_host_info: macid from system = {}", mac);
            self.macid = mac;
        }
        //if self.host_name.is_empty() 
        {
            self.host_name =
                SystemInfo::get_computer_name().unwrap_or_else(|_| "Unknown".to_string());
        }
        if self.auth.is_empty() {
            self.auth = "123123".to_string();
        }
        if self.os.is_empty() {
            self.os = SystemInfo::get_computer_version().unwrap_or_else(|_| "Unknown".to_string());
        }
        if self.cpu.is_empty() {
            self.cpu = SystemInfo::get_cpu_cores().unwrap_or_else(|_| "Unknown".to_string());
        }
        if self.memsize.is_empty() {
            self.memsize = SystemInfo::get_memory_size().unwrap_or_else(|_| "Unknown".to_string());
        }
        if self.hdsize.is_empty() {
            self.hdsize = SystemInfo::get_disk_size().unwrap_or_else(|_| "Unknown".to_string());
        }
        if self.ips.is_empty() {
            self.ips = ip_mac::get_ip().unwrap_or("unknown".to_string());
        }
        Ok(())
    }

    /// 将 uid 同步到 /opt/EndpointSecurityApp/app.conf
    /// 供 EndpointSecurityApp GUI 读取，格式: uid=<dev_uid>
    fn sync_uid_to_app_conf(&self) {
        let app_conf = "/opt/EndpointSecurityApp/app.conf";
        let uid_line = format!("uid={}", self.dev_uid);
        match std::fs::read_to_string(app_conf) {
            Ok(content) => {
                let mut updated = false;
                let lines: Vec<String> = content
                    .lines()
                    .map(|l| {
                        if l.trim_start().starts_with("uid=") {
                            updated = true;
                            uid_line.clone()
                        } else {
                            l.to_string()
                        }
                    })
                    .collect();
                let mut new_content = if updated {
                    lines.join("\n")
                } else {
                    // 没有 uid= 行，追加到末尾
                    format!("{}\n{}", content.trim_end(), uid_line)
                };
                new_content.push('\n');
                if let Err(e) = std::fs::write(app_conf, &new_content) {
                    log_error!("写入 app.conf uid 失败: {}", e);
                } else {
                    log_info!("已同步 uid={} 到 app.conf", self.dev_uid);
                }
            }
            Err(_) => {
                // 文件不存在，创建
                if let Err(e) = std::fs::write(app_conf, format!("{}\n", uid_line)) {
                    log_error!("创建 app.conf 失败: {}", e);
                } else {
                    log_info!("已创建 app.conf uid={}", self.dev_uid);
                }
            }
        }
    }

    fn extract_ip(input: &str) -> Option<String> {
        use std::net::IpAddr;

        // 1. 去掉协议头
        let without_scheme = input
            .strip_prefix("http://")
            .or_else(|| input.strip_prefix("https://"))
            .unwrap_or(input);

        let host_part = if without_scheme.starts_with('[') {
            // 找到第一个 ']'
            if let Some(idx) = without_scheme.find(']') {
                &without_scheme[1..idx] // 提取 ::1
            } else {
                without_scheme // 格式错误，但继续尝试
            }
        } else {
            without_scheme.split(':').next().unwrap_or(without_scheme)
        };

        if host_part.parse::<IpAddr>().is_ok() {
            Some(host_part.to_string())
        } else {
            None
        }
    }
}

use once_cell::sync::Lazy;
use std::path::Path;
use std::sync::Mutex;

pub static NETINFO_CONFIG: Lazy<Mutex<NetInfoConfig>> = Lazy::new(|| {
    let base_path = std::env::var("CONFIG_PATH")
        .ok()
        .unwrap_or_else(|| "/opt/osec".to_string());
    let path = format!("{}/net_info.ini", base_path);
    let mut ini = Ini::new();
    if Path::new(&path).exists() {
        ini.load(&path).unwrap_or_else(|err| {
            eprintln!("Failed to load configuration file from '{}': {}", path, err);
            std::process::exit(1);
        });
    } else {
        eprintln!("Configuration file '{}' does not exist", path);
        std::process::exit(1);
    }
    Mutex::new(NetInfoConfig::from_ini(&ini))
});
