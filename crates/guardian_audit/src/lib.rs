// crates/guardian_audit/src/lib.rs
//
// 终端守护安全评估模块 — 完全独立，不依赖 BootManager
//
// 功能：
//   1. POST /v1/device/auth        设备认证，获取 token（启动时执行）
//   2. POST /v1/device/heartbeat   心跳（频率可配置，401时重新认证）
//   3. POST /v1/device/controlList 控制列表（频率可配置，401时重新认证）
//   4. GET  /getSaPolicy           HTTP server，供专联设备查询安全策略
//
// 配置：统一读取 /opt/osec/guardian_audit.ini
//   [security_eval] - 服务器地址、用户ID、设备信息、模块配置

use std::pin::Pin;
use std::future::Future;
use std::sync::{Arc, RwLock};

use once_cell::sync::Lazy;
use axum::{routing::get, Router, Json};
use serde::{Deserialize, Serialize};
use tokio::time::{interval, Duration};

use net_client::core::client::NetClient;
use logging::{log_info, log_error, log_warn};
use chrono::Utc;
use md5::{Md5, Digest};
use uuid::Uuid;
use std::io::{Read, Write};
use std::path::Path;

// ═══════════════════════════════════════════════════════
// DEV_UID 生成（与 hostinfo::agent_uid::ensure_and_get_mgs_guid 一致）
// ═══════════════════════════════════════════════════════
fn get_dev_uid(file_path: &str) -> Result<String, std::io::Error> {
    if !Path::new(file_path).exists() {
        let message_uuid = Uuid::new_v4().to_string();
        let mut ofile = std::fs::OpenOptions::new().create(true).write(true).open(file_path)?;
        ofile.write_all(message_uuid.as_bytes())?;
        ofile.write_all(b"\n")?;
    }
    let mut file = std::fs::File::open(file_path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    let mut hasher = Md5::new();
    hasher.update(&contents);
    Ok(hex::encode(hasher.finalize()))
}

// ═══════════════════════════════════════════════════════
// IP 地址自动检测（与 hostinfo::ip_mac::get_ip 等价）
// ═══════════════════════════════════════════════════════
fn get_ip() -> Option<String> {
    use std::process::Command;
    let output = Command::new("ip")
        .args(["addr", "show"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ips = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("inet ") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let ip_with_prefix = parts[1];
            if ip_with_prefix.starts_with("127.") {
                continue;
            }
            if let Some((ip_addr, _)) = ip_with_prefix.split_once('/') {
                if !ip_addr.is_empty() {
                    ips.push(ip_addr.to_string());
                }
            }
        }
    }
    if ips.is_empty() { None } else { Some(ips.join(",")) }
}

// ═══════════════════════════════════════════════════════
// MAC 地址自动检测（读取 /sys/class/net/，与 hostinfo::ip_mac::get_mac 等价）
// ═══════════════════════════════════════════════════════
fn get_mac() -> Option<String> {
    use std::fs;
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let iface = entry.file_name();
            let iface_name = iface.to_string_lossy();
            // 跳过 loopback 和虚拟接口
            if iface_name == "lo" || iface_name.starts_with("docker") || iface_name.starts_with("veth") {
                continue;
            }
            let addr_path = format!("/sys/class/net/{}/address", iface_name);
            if let Ok(mac) = fs::read_to_string(&addr_path) {
                let mac = mac.trim().to_string();
                // 跳过无效 MAC（全 0 或全 ff）
                if !mac.is_empty() && mac != "00:00:00:00:00:00" && mac != "ff:ff:ff:ff:ff:ff" {
                    return Some(mac);
                }
            }
        }
    }
    None
}

// ═══════════════════════════════════════════════════════
// 将自动生成的 dev_uid / macid 回写到配置文件
// ═══════════════════════════════════════════════════════
impl BaseOnline {
    fn persist_config(config_path: &str, dev_uid: &str, macid: &str, ips: &str) {
        use std::fs;
        use std::io::{BufRead, BufReader};

        // 文件不存在就不写
        if !Path::new(config_path).exists() {
            return;
        }

        let file = match fs::File::open(config_path) {
            Ok(f) => f,
            Err(e) => {
                log_error!("guardian_audit: 回写配置失败（打开）: {}", e);
                return;
            }
        };
        let reader = BufReader::new(file);
        let mut lines: Vec<String> = Vec::new();
        let mut changed = false;

        for line in reader.lines().flatten() {
            let trimmed = line.trim();
            if trimmed.starts_with("dev_uid") && !dev_uid.is_empty() {
                let current = trimmed.splitn(2, '=').nth(1).unwrap_or("").trim();
                if current.is_empty() {
                    lines.push(format!("dev_uid = {}", dev_uid));
                    changed = true;
                    continue;
                }
            }
            if trimmed.starts_with("macid") && !macid.is_empty() {
                let current = trimmed.splitn(2, '=').nth(1).unwrap_or("").trim();
                if current.is_empty() {
                    lines.push(format!("macid = {}", macid));
                    changed = true;
                    continue;
                }
            }
            if trimmed.starts_with("ips") && !ips.is_empty() {
                let current = trimmed.splitn(2, '=').nth(1).unwrap_or("").trim();
                if current.is_empty() || current == "127.0.0.1" {
                    lines.push(format!("ips = {}", ips));
                    changed = true;
                    continue;
                }
            }
            lines.push(line);
        }

        // 有变化才写回
        if changed {
            let content = lines.join("\n");
            if let Err(e) = fs::write(config_path, format!("{}\n", content)) {
                log_error!("guardian_audit: 回写配置失败（写入）: {}", e);
            } else {
                log_info!("guardian_audit: 已将 dev_uid、macid、ips 回写到 {}", config_path);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════
// 认证数据结构（参考 crates/online/src/lib.rs）
// ═══════════════════════════════════════════════════════

#[derive(Serialize, Deserialize, Debug)]
pub struct BaseOnline {
    pub uid: String,
    pub macid: String,
    pub ip: String,
    pub ver: String,
    pub os: String,
    pub asstarttime: String,
    pub auth: String,
    pub userid: String,
    pub arch_type: u8,
}

impl BaseOnline {
    pub fn new(user_id: String) -> Self {
        // 从 /opt/osec/guardian_audit.ini 读取设备信息
        let mut ini = configparser::ini::Ini::new();
        let config_path = "/opt/osec/guardian_audit.ini";

        let (mut uid, mut macid, mut ips, ver, os) = if ini.load(config_path).is_ok() {
            (
                ini.get("security_eval", "dev_uid").unwrap_or_default(),
                ini.get("security_eval", "macid").unwrap_or_default(),
                ini.get("security_eval", "ips").unwrap_or_default(),
                ini.get("security_eval", "VERSION").unwrap_or_else(|| "3.0.1".to_string()),
                ini.get("security_eval", "os").unwrap_or_else(|| "Linux".to_string()),
            )
        } else {
            log_warn!("guardian_audit: 无法加载 {}，使用默认值", config_path);
            (String::new(), String::new(), String::new(), "3.0.1".to_string(), "Linux".to_string())
        };

        // dev_uid 为空时自动生成（与 agent_manager 的 ensure_and_get_mgs_guid 一致）
        if uid.is_empty() {
            match get_dev_uid("/etc/.vedasystem") {
                Ok(g) => uid = g,
                Err(e) => log_error!("guardian_audit: 获取 DEV_UID 失败: {}", e),
            }
        }

        // macid 为空时自动检测（读取 /sys/class/net/ 第一个非 loopback 接口）
        if macid.is_empty() {
            if let Some(m) = get_mac() {
                log_info!("guardian_audit: 自动检测到 MAC 地址: {}", m);
                macid = m;
            } else {
                log_warn!("guardian_audit: 无法自动检测 MAC 地址");
            }
        }

        // ips 为空或只有 127.0.0.1 时自动检测（`ip addr show`，跳过 loopback）
        if ips.is_empty() || ips == "127.0.0.1" {
            if let Some(detected_ips) = get_ip() {
                log_info!("guardian_audit: 自动检测到 IP 地址: {}", detected_ips);
                ips = detected_ips;
            } else {
                log_warn!("guardian_audit: 无法自动检测 IP 地址");
            }
        }

        // 将自动生成的值回写到配置文件，下次启动时直接使用
        Self::persist_config(config_path, &uid, &macid, &ips);

        let asstarttime = Utc::now().timestamp().to_string();
        let arch_type = match std::env::consts::ARCH {
            "x86_64" => 1,
            "aarch64" => 2,
            "mips64" => 3,
            _ => 0,
        };
        
        BaseOnline {
            uid,
            macid,
            ip: ips,
            ver,
            os,
            asstarttime,
            auth: String::new(),
            userid: user_id,
            arch_type,
        }
    }
}

// ═══════════════════════════════════════════════════════
// 配置管理（从 /opt/osec/guardian_audit.ini 统一读取）
// ═══════════════════════════════════════════════════════

pub struct GuardianConfig {
    pub server_url: String,
    pub listen_addr: String,
    pub enabled: bool,
    pub heartbeat_interval: u64,
    pub control_list_interval: u64,
    pub client_download_url: String,
    pub user_id: String,  // 从 guardian_audit.ini USER_ID
}

impl GuardianConfig {
    pub fn load() -> Self {
        let mut ini = configparser::ini::Ini::new();
        let module_config_path = "/opt/osec/guardian_audit.ini";

        if ini.load(module_config_path).is_err() {
            log_warn!("guardian_audit: 无法加载 {}，使用默认值", module_config_path);
            return Self::default();
        }

        // 1. 优先从 SERVERIPPORT 读取（格式: IP:PORT，如 192.168.19.92:10443）
        let server_url = ini.get("security_eval", "SERVERIPPORT")
            .and_then(|v| {
                let v = v.trim();
                if v.is_empty() {
                    None
                } else {
                    Some(format!("https://{}", v))
                }
            })
            // 2. 回退：从旧 key server_url 读取（完整 URL）
            .or_else(|| {
                ini.get("security_eval", "server_url")
                    .filter(|v| !v.trim().is_empty())
            })
            // 3. 回退：从 /opt/config.ini 读取（兼容旧安装）
            .or_else(Self::load_config_ini)
            .unwrap_or_else(|| "https://127.0.0.1:443".to_string());

        // 4. 优先从 guardian_audit.ini 读 USER_ID，回退到 /opt/config.ini
        let user_id = ini.get("security_eval", "USER_ID")
            .filter(|v| !v.trim().is_empty())
            .or_else(|| Self::load_config_user_id())
            .unwrap_or_default();

        GuardianConfig {
            server_url,
            user_id,
            listen_addr: ini.get("security_eval", "listen_addr")
                .unwrap_or_else(|| "127.0.0.1:50050".to_string()),
            enabled: ini.get("security_eval", "enabled")
                .map(|v| !matches!(v.trim(), "0" | "false"))
                .unwrap_or(true),
            heartbeat_interval: ini.get("security_eval", "heartbeat_interval")
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(30),
            control_list_interval: ini.get("security_eval", "control_list_interval")
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(30),
            client_download_url: ini.get("security_eval", "client_download_url")
                .unwrap_or_default(),
        }
    }

    /// 从 /opt/config.ini 读取完整 server_url（兼容旧安装）
    fn load_config_ini() -> Option<String> {
        let mut ini = configparser::ini::Ini::new();
        let config_path = "/opt/config.ini";

        if ini.load(config_path).is_err() {
            return None;
        }

        let url = ini.get("SERVER", "URL")?;
        let port = ini.get("SERVER", "PORT")
            .unwrap_or_else(|| "443".to_string());

        let clean_url = url.trim().trim_start_matches("http://").trim_start_matches("https://");
        let scheme = "https";
        Some(format!("{}://{}:{}", scheme, clean_url, port))
    }

    /// 从 /opt/config.ini 读取 USER_ID（兼容旧安装）
    fn load_config_user_id() -> Option<String> {
        let mut ini = configparser::ini::Ini::new();
        let config_path = "/opt/config.ini";

        if ini.load(config_path).is_err() {
            return None;
        }

        ini.get("SERVER", "USER_ID")
    }
    
    pub fn default() -> Self {
        GuardianConfig {
            server_url: "https://127.0.0.1:443".to_string(),
            listen_addr: "127.0.0.1:50050".to_string(),
            enabled: true,
            heartbeat_interval: 30,
            control_list_interval: 30,
            client_download_url: String::new(),
            user_id: String::new(),
        }
    }
}

// ═══════════════════════════════════════════════════════
// 全局策略缓存（controlList 写入，getSaPolicy handler 读取）
// ═══════════════════════════════════════════════════════
#[derive(Debug, Clone, Default)]
pub struct SaPolicyState {
    pub enabled: bool,
    pub client_download_url: String,
    pub crontab_time: u32,
    /// 来自 controlList.list[].ip
    pub allowed_ips: Vec<String>,
    pub external_whitelist: Vec<String>,
    pub external_blacklist: Vec<String>,
    pub internal_whitelist: Vec<String>,
    pub internal_blacklist: Vec<String>,
}

pub static SA_POLICY: Lazy<Arc<RwLock<SaPolicyState>>> = Lazy::new(|| {
    let cfg = GuardianConfig::load();
    Arc::new(RwLock::new(SaPolicyState {
        enabled: cfg.enabled,
        client_download_url: cfg.client_download_url,
        crontab_time: 10,
        ..Default::default()
    }))
});

fn update_allowed_ips(ips: Vec<String>) {
    match SA_POLICY.write() {
        Ok(mut p) => {
            log_info!("guardian_audit: 更新准入白名单 {} 条", ips.len());
            p.allowed_ips = ips;
        }
        Err(e) => log_error!("guardian_audit: 写策略失败: {}", e),
    }
}

// ═══════════════════════════════════════════════════════
// 全局 Token 存储(跨任务共享)
// ═══════════════════════════════════════════════════════
pub static TOKEN_STORE: Lazy<Arc<RwLock<Option<String>>>> = Lazy::new(|| {
    Arc::new(RwLock::new(None))
});

pub fn update_token(new_token: String) {
    if let Ok(mut token) = TOKEN_STORE.write() {
        *token = Some(new_token);
        log_info!("guardian_audit: Token 已更新");
    }
}

pub fn get_token() -> Option<String> {
    TOKEN_STORE.read().ok().and_then(|t| t.clone())
}

/// 检查响应是否表示 Token 过期(401)
pub fn is_token_expired(response: &str) -> bool {
    response.contains("\"code\":\"401\"") 
        || response.contains("\"code\": \"401\"")
        || response.contains("Unauthorized")
        || response.contains("401")
}

/// 重新认证
pub async fn re_authenticate(client: &NetClient, base_url: &str) -> bool {
    log_warn!("guardian_audit: Token 已过期,开始重新认证...");
    let url = format!("{}/v1/device/auth", base_url);
    
    match client.post_data_async(&url, "{}", Duration::from_secs(10), None).await {
        Ok(resp) => {
            log_info!("guardian_audit: 重认证响应 <- {}", resp);
            if let Ok(r) = serde_json::from_str::<AuthResponse>(&resp) {
                if r.code == "000000" {
                    log_info!("guardian_audit: 重新认证成功");
                    update_token(r.data.token);
                    return true;
                } else {
                    log_error!("guardian_audit: 重新认证失败 code={} msg={}", r.code, r.msg);
                }
            }
        }
        Err(e) => log_error!("guardian_audit: 重新认证请求失败: {}", e),
    }
    false
}

// ═══════════════════════════════════════════════════════
// /v1/device/auth 响应结构
// ═══════════════════════════════════════════════════════
#[derive(Debug, Deserialize)]
struct AuthData {
    #[serde(default)]
    token: String,
}
#[derive(Debug, Deserialize)]
struct AuthResponse {
    code: String,
    data: AuthData,
    #[serde(default)]
    msg: String,
}

// ═══════════════════════════════════════════════════════
// /v1/device/heartbeat 响应结构
// ═══════════════════════════════════════════════════════
#[derive(Debug, Deserialize)]
struct HeartbeatData {
    #[serde(default)]
    remark: String,
    #[serde(default)]
    list: Vec<serde_json::Value>,
}
#[derive(Debug, Deserialize)]
struct HeartbeatResponse {
    code: String,
    data: HeartbeatData,
    #[serde(default)]
    msg: String,
}

// ═══════════════════════════════════════════════════════
// /v1/device/controlList 响应结构
// ═══════════════════════════════════════════════════════
#[derive(Debug, Deserialize)]
struct ControlItem {
    ip: String,
    #[serde(default)]
    uid: String,
}
#[derive(Debug, Deserialize)]
struct ControlListData {
    list: Vec<ControlItem>,
    #[serde(default)]
    remark: String,
}
#[derive(Debug, Deserialize)]
struct ControlListResponse {
    code: String,
    data: ControlListData,
    #[serde(default)]
    msg: String,
}

// ═══════════════════════════════════════════════════════
// GET /getSaPolicy 响应结构
// ═══════════════════════════════════════════════════════
#[derive(Serialize)]
struct SaPolicyResp {
    code: u32,
    msg: String,
    data: SaPolicyData,
}
#[derive(Serialize)]
struct SaPolicyData {
    enabled: bool,
    client_download_url: String,
    crontab_time: u32,
    policy: PolicyDetail,
}
#[derive(Serialize)]
struct PolicyDetail {
    external: IpList,
    internal: IpList,
    access_control: AccessControl,
}
#[derive(Serialize)]
struct IpList {
    whitelist: Vec<String>,
    blacklist: Vec<String>,
}
#[derive(Serialize)]
struct AccessControl {
    allowed_ips: Vec<String>,
}

async fn handle_get_sa_policy() -> Json<SaPolicyResp> {
    let state = SA_POLICY.read().unwrap();
    Json(SaPolicyResp {
        code: 200,
        msg: "请求成功".to_string(),
        data: SaPolicyData {
            enabled: state.enabled,
            client_download_url: state.client_download_url.clone(),
            crontab_time: state.crontab_time,
            policy: PolicyDetail {
                external: IpList {
                    whitelist: state.external_whitelist.clone(),
                    blacklist: state.external_blacklist.clone(),
                },
                internal: IpList {
                    whitelist: state.internal_whitelist.clone(),
                    blacklist: state.internal_blacklist.clone(),
                },
                access_control: AccessControl {
                    allowed_ips: state.allowed_ips.clone(),
                },
            },
        },
    })
}

// ═══════════════════════════════════════════════════════
// 启动服务（不再使用 BootManager）
// ═══════════════════════════════════════════════════════

pub fn start_guardian_audit_service() -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>> {
    let config = GuardianConfig::load();
    
    log_info!("guardian_audit: 配置加载完成");
    log_info!("guardian_audit: 服务器地址: {}", config.server_url);
    log_info!("guardian_audit: 监听地址: {}", config.listen_addr);
    log_info!("guardian_audit: 心跳间隔: {}s", config.heartbeat_interval);
    log_info!("guardian_audit: 控制列表间隔: {}s", config.control_list_interval);
    
    Box::pin(async move {
        // 创建 NetClient
        let client = match NetClient::new(Some(config.server_url.clone()), true) {
            Ok(c) => Arc::new(c),
            Err(e) => return Err(format!("guardian_audit: 创建 NetClient 失败: {}", e)),
        };

        // 1. 立即执行初始认证
        {
            let base_online = BaseOnline::new(config.user_id.clone());
            log_info!("guardian_audit: 认证请求数据: uid={}, macid={}, ip={}, ver={}, os={}, arch_type={}",
                      base_online.uid, base_online.macid, base_online.ip, base_online.ver, base_online.os, base_online.arch_type);

            let auth_body = match serde_json::to_string(&base_online) {
                Ok(json) => json,
                Err(e) => {
                    log_error!("guardian_audit: 序列化认证数据失败: {}", e);
                    "{}".to_string()
                }
            };

            let url = format!("{}/v1/device/auth", config.server_url);
            match client.post_data_async(&url, &auth_body, Duration::from_secs(10), None).await {
                Ok(resp) => {
                    log_info!("guardian_audit: 认证请求 -> POST {} | body={}", url, auth_body);
                    log_info!("guardian_audit: 认证响应 <- {}", resp);
                    if let Ok(r) = serde_json::from_str::<AuthResponse>(&resp) {
                        if r.code == "000000" {
                            log_info!("guardian_audit: 初始认证成功, token={}", &r.data.token[..r.data.token.len().min(16)]);
                            update_token(r.data.token);
                        } else {
                            log_error!("guardian_audit: 初始认证失败 code={} msg={}", r.code, r.msg);
                        }
                    }
                }
                Err(e) => log_error!("guardian_audit: 初始 auth 失败: {}", e),
            }
        }

        // 2. 心跳任务
        let heartbeat_interval = config.heartbeat_interval;
        tokio::spawn({
            let base = config.server_url.clone();
            let client = Arc::clone(&client);
            async move {
                let mut tick = interval(Duration::from_secs(heartbeat_interval));
                loop {
                    tick.tick().await;
                    let token = get_token();
                    let url = format!("{}/v1/device/heartbeat", base);
                    
                    match client.post_data_async(&url, "{}", Duration::from_secs(10), token.as_deref()).await {
                        Ok(resp) => {
                            if is_token_expired(&resp) {
                                if re_authenticate(&client, &base).await {
                                    log_info!("guardian_audit: Token 刷新成功,继续心跳");
                                }
                                continue;
                            }
                            
                            if let Ok(r) = serde_json::from_str::<HeartbeatResponse>(&resp) {
                                if r.code == "000000" {
                                    log_info!("guardian_audit: 心跳响应 <- {}", resp);
                                } else {
                                    log_error!("guardian_audit: 心跳异常 code={} resp={}", r.code, resp);
                                }
                            }
                        }
                        Err(e) => log_error!("guardian_audit: heartbeat 失败: {}", e),
                    }
                }
            }
        });

        // 3. controlList 任务
        let control_list_interval = config.control_list_interval;
        tokio::spawn({
            let base = config.server_url.clone();
            let client = Arc::clone(&client);
            async move {
                let mut tick = interval(Duration::from_secs(control_list_interval));
                loop {
                    tick.tick().await;
                    let token = get_token();
                    let url = format!("{}/v1/device/controlList", base);
                    
                    match client.post_data_async(&url, "{}", Duration::from_secs(10), token.as_deref()).await {
                        Ok(resp) => {
                            if is_token_expired(&resp) {
                                if re_authenticate(&client, &base).await {
                                    log_info!("guardian_audit: Token 刷新成功,继续拉取控制列表");
                                }
                                continue;
                            }
                            
                            if let Ok(r) = serde_json::from_str::<ControlListResponse>(&resp) {
                                if r.code == "000000" {
                                    log_info!("guardian_audit: controlList 响应 <- {}", resp);
                                    let ips: Vec<String> = r.data.list.iter()
                                        .map(|i| i.ip.clone()).collect();
                                    update_allowed_ips(ips);
                                } else {
                                    log_error!("guardian_audit: controlList 异常 code={} resp={}", r.code, resp);
                                }
                            }
                        }
                        Err(e) => log_error!("guardian_audit: controlList 失败: {}", e),
                    }
                }
            }
        });

        // 4. getSaPolicy HTTP server
        let app = Router::new().route("/getSaPolicy", get(handle_get_sa_policy));
        let listener = match tokio::net::TcpListener::bind(&config.listen_addr).await {
            Ok(l) => {
                log_info!("guardian_audit: HTTP server 已启动,监听 {}", config.listen_addr);
                l
            }
            Err(e) => return Err(format!("guardian_audit: 绑定 {} 失败: {}", config.listen_addr, e)),
        };

        // 启动 HTTP 服务器
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                log_error!("guardian_audit: HTTP server 异常: {}", e);
            }
        });

        Ok("guardian_audit 服务已启动".to_string())
    })
}
