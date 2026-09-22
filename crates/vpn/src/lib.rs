//! VPN 拨号 supervisor：移植自 rust_vpn_demo 的拨号流程。
//!
//! 用途：特定网络环境下必须先拨通 VPN（建立 tun）才能连上管理服务器。
//! 开关：/opt/osec/net_info.ini `[VPN] ENABLED=1`。
//!
//! 架构说明：
//! - agent 本体（常为静态 musl，不支持 dlopen，且不能因缺厂商 .so 而无法启动）
//!   不直连 VPN SDK，而是拉起拨号子进程 `vpn-helper` 并保活；
//! - `vpn-helper`（本 crate `src/bin/vpn_helper.rs`，需 `--features helper` 单独编译）
//!   直连 /opt/osec/vpn/lib 下的厂商 .so，KeepAlive5 内部阻塞+自动重连；
//! - 子进程退出即视为隧道中断，supervisor 按退避间隔重新拉起。

use logging::{log_error, log_info};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// vpn.conf 默认全路径
pub const DEFAULT_VPN_CONF: &str = "/opt/osec/vpn/vpn.conf";
/// SDK client.conf 默认全路径（传给 helper → FM_vpnclientInit）
pub const DEFAULT_CLIENT_CONF: &str = "/opt/osec/vpn/client.conf";
/// 拨号子进程默认全路径
pub const DEFAULT_HELPER: &str = "/opt/osec/vpn/vpn-helper";
/// vpn.conf 内相对路径的基准目录
pub const VPN_BASE_DIR: &str = "/opt/osec/vpn";
/// 子进程异常退出后的重拉间隔
pub const RESTART_BACKOFF: Duration = Duration::from_secs(10);

static VPN_RUNNING: AtomicBool = AtomicBool::new(false);
static VPN_STOP: AtomicBool = AtomicBool::new(false);
static VPN_CHILD: Mutex<Option<Child>> = Mutex::new(None);

#[derive(Debug, Deserialize, Clone)]
pub struct VpnConf {
    pub vpn: VpnSection,
    #[serde(rename = "copsign")]
    pub copysign: CoopSignSection,
    pub auth: AuthSection,
    pub log: LogSection,
    pub sdk: SdkSection,
}

#[derive(Debug, Deserialize, Clone)]
pub struct VpnSection {
    pub serv_ip: String,
    pub serv_port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CoopSignSection {
    pub serv_ip: String,
    pub serv_port: u16,
    pub ssl_config: String,
    pub ca_path: String,
    pub local_ws_port: u16,
    pub sign_cert_path: String,
    pub uuid: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthSection {
    pub username: String,
    pub password: String,
    pub authtype: u8,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LogSection {
    pub filename: String,
    pub level: u8,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SdkSection {
    pub timeout: u8,
    pub ipv6: u8,
    pub cert_save_path: String,
}

/// 把 vpn.conf 里的相对路径按 /opt/osec/vpn 补成全路径；已经是绝对路径则原样返回。
pub fn resolve_vpn_path(p: &str) -> String {
    if p.is_empty() || Path::new(p).is_absolute() {
        return p.to_string();
    }
    PathBuf::from(VPN_BASE_DIR).join(p).to_string_lossy().into_owned()
}

/// 解析 vpn.conf（TOML），并把其中的文件引用统一为全路径。
/// 仅做启动前自检（打日志），不阻断拉起。
pub fn load_conf(conf_path: &str) -> Result<VpnConf, String> {
    let conf_str = fs::read_to_string(conf_path)
        .map_err(|e| format!("读取 vpn.conf 失败({}): {}", conf_path, e))?;
    let mut conf: VpnConf =
        toml::from_str(&conf_str).map_err(|e| format!("解析 vpn.conf 失败: {}", e))?;
    conf.copysign.ssl_config = resolve_vpn_path(&conf.copysign.ssl_config);
    conf.copysign.ca_path = resolve_vpn_path(&conf.copysign.ca_path);
    conf.copysign.sign_cert_path = resolve_vpn_path(&conf.copysign.sign_cert_path);
    conf.sdk.cert_save_path = resolve_vpn_path(&conf.sdk.cert_save_path);
    Ok(conf)
}

pub fn is_running() -> bool {
    VPN_RUNNING.load(Ordering::SeqCst)
}

fn spawn_helper(helper: &str, conf_path: &str, client_conf: &str) -> Result<Child, String> {
    if !Path::new(helper).exists() {
        return Err(format!("拨号子进程不存在: {}（需部署 vpn-helper）", helper));
    }
    Command::new(helper)
        .arg(conf_path)
        .arg(client_conf)
        .spawn()
        .map_err(|e| format!("拉起 {} 失败: {}", helper, e))
}

fn supervise_loop(helper: String, conf_path: String, client_conf: String) {
    // 启动前自检：配置打日志，失败也不阻断（helper 自己会再校验并退出码说明）
    match load_conf(&conf_path) {
        Ok(conf) => log_info!(
            "[vpn] 配置: vpn={}:{} cosign={}:{} user={} helper={}",
            conf.vpn.serv_ip,
            conf.vpn.serv_port,
            conf.copysign.serv_ip,
            conf.copysign.serv_port,
            conf.auth.username,
            helper,
        ),
        Err(e) => log_error!("[vpn] 配置自检失败（仍尝试拉起）: {}", e),
    }

    loop {
        if VPN_STOP.load(Ordering::SeqCst) {
            break;
        }
        match spawn_helper(&helper, &conf_path, &client_conf) {
            Ok(child) => {
                let pid = child.id();
                log_info!("[vpn] 拨号子进程已拉起 pid={}", pid);
                *VPN_CHILD.lock().unwrap() = Some(child);
                // 轮询等待：短暂持锁 try_wait，保证 stop() 随时能拿锁 kill
                loop {
                    if VPN_STOP.load(Ordering::SeqCst) {
                        break;
                    }
                    let exited = VPN_CHILD
                        .lock()
                        .unwrap()
                        .as_mut()
                        .map(|c| c.try_wait());
                    match exited {
                        Some(Ok(Some(status))) => {
                            // 子进程已退出，取走句柄回收
                            if let Some(mut c) = VPN_CHILD.lock().unwrap().take() {
                                let _ = c.wait();
                            }
                            log_error!("[vpn] 拨号子进程退出（隧道中断）: status={}", status);
                            break;
                        }
                        Some(Ok(None)) => {} // 仍在运行
                        Some(Err(e)) => {
                            log_error!("[vpn] try_wait 拨号子进程失败: {}", e);
                            break;
                        }
                        None => break, // 句柄已被 stop() 取走
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
            Err(e) => {
                log_error!("[vpn] {}", e);
            }
        }
        if VPN_STOP.load(Ordering::SeqCst) {
            break;
        }
        log_info!("[vpn] {}s 后重新拉起拨号子进程", RESTART_BACKOFF.as_secs());
        // 可中断的等待
        let waited = RESTART_BACKOFF.as_millis() / 100;
        for _ in 0..waited {
            if VPN_STOP.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    VPN_RUNNING.store(false, Ordering::SeqCst);
    log_info!("[vpn] 保活线程退出");
}

/// 后台拉起拨号子进程并保活（不阻塞调用方），tun 建立后 agent 的服务器连接即可走 VPN。
pub fn start_background(helper: String, conf_path: String, client_conf: String) {
    if VPN_RUNNING.swap(true, Ordering::SeqCst) {
        log_info!("[vpn] 已在运行，跳过重复拉起");
        return;
    }
    VPN_STOP.store(false, Ordering::SeqCst);
    std::thread::Builder::new()
        .name("vpn-supervise".to_string())
        .spawn(move || supervise_loop(helper, conf_path, client_conf))
        .ok();
}

/// 停止保活并杀掉拨号子进程。
pub fn stop() {
    VPN_STOP.store(true, Ordering::SeqCst);
    if let Some(mut child) = VPN_CHILD.lock().unwrap().take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    VPN_RUNNING.store(false, Ordering::SeqCst);
    log_info!("[vpn] 已停止");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_relative_to_full_path() {
        assert_eq!(
            resolve_vpn_path("cosignsdk.conf"),
            "/opt/osec/vpn/cosignsdk.conf"
        );
        assert_eq!(
            resolve_vpn_path("ca/20241016_ca.cer"),
            "/opt/osec/vpn/ca/20241016_ca.cer"
        );
        assert_eq!(resolve_vpn_path("/already/abs.conf"), "/already/abs.conf");
    }

    #[test]
    fn load_system_vpn_conf_paths_are_absolute() {
        let conf = load_conf(DEFAULT_VPN_CONF).expect("应能解析 /opt/osec/vpn/vpn.conf");
        for p in [
            &conf.copysign.ssl_config,
            &conf.copysign.ca_path,
            &conf.copysign.sign_cert_path,
            &conf.sdk.cert_save_path,
        ] {
            assert!(Path::new(p).is_absolute(), "应为全路径: {}", p);
        }
    }

    #[test]
    fn missing_helper_reports_error_without_panic() {
        let r = spawn_helper("/nonexistent/vpn-helper-xyz", DEFAULT_VPN_CONF, DEFAULT_CLIENT_CONF);
        assert!(r.is_err());
        // start/stop 状态机不 panic
        VPN_STOP.store(true, Ordering::SeqCst);
        VPN_RUNNING.store(false, Ordering::SeqCst);
        stop();
        assert!(!is_running());
    }
}
