use libc::{sigaction, SIGPIPE, SIG_IGN, SA_RESTART, sigemptyset};
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use online::StartOnline;
use task::{TaskService, TimerTask};
use kernel_event::{StartKernelHandler, EventHandler,send_data_to_kernel};
use kernel_module::{LoadKernelDriver, unload_driver, ensure_kernel_hold};
use common::manager::boot::BootManager;
use reporter::{AuditLogInfo, StartBashLog};
use tokio::sync::mpsc;
use logging::{log_info, CustomLogger, log_error, log_warn};
use netlink::netlink::NlSockInfo;
use std::sync::Arc;
use tokio::sync::Mutex;
use config::net_info::NETINFO_CONFIG;
use grpc_gateway::agent_mode::{AgentMode, AGENT_MODE, ADMISSION_NETWORK_ANOMALY};
use udisk::{StartUsbService, StartUsbHotplugHandler};
use docker::StartDockerMonitor;
use virus_scan_grpc::StartVirusScanGrpcService;
use std::fs;
use std::path::Path;

const PID_FILE: &str = "/var/run/osec_backend.pid";

fn pid_is_running(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

fn ensure_single_instance() {
    if Path::new(PID_FILE).exists() {
        if let Ok(content) = fs::read_to_string(PID_FILE) {
            if let Ok(old_pid) = content.trim().parse::<u32>() {

                if pid_is_running(old_pid) {
                    eprintln!("❌ osec_backend 已在运行 (PID={})！", old_pid);
                    std::process::exit(1);
                }
            }
        }
    }

    let current_pid = std::process::id();
    if let Err(e) = fs::write(PID_FILE, current_pid.to_string()) {
        eprintln!("⚠ 无法写入 PID 文件: {}", e);
    }

    println!("✔ 单实例检查通过，当前 PID={}", current_pid);
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    ensure_single_instance(); 
    // 初始化日志
    CustomLogger::init("/opt/osec/osec_backend.conf")
        .await
        .expect("无法初始化日志");
    // 忽略 SIGPIPE 信号
    unsafe {
        let mut sa: sigaction = std::mem::zeroed();
        sa.sa_sigaction = SIG_IGN as usize;
        sa.sa_flags = SA_RESTART;
        sigemptyset(&mut sa.sa_mask);
        if sigaction(SIGPIPE, &sa, std::ptr::null_mut()) != 0 {
            panic!("sigaction failed to set SIGPIPE to ignore");
        }
    }
    log_info!("程序开始启动");

    // 卸载现有内核驱动
    let _ = unload_driver().ok();

    // 初始化 BootManager
    let init = BootManager::init().await;

    // 创建通信通道
    let (file_audit_log_tx, file_audit_log_rx) = mpsc::channel::<AuditLogInfo>(512);
    let (token_tx, token_rx) = mpsc::channel::<String>(8);
    let (host_is_offline_tx, host_is_offline_rx) = mpsc::channel::<bool>(8);

    // 加载内核驱动并更新 mod_ver
    {
        let mut cfg = NETINFO_CONFIG.lock().unwrap();
        let mut init = init.clone();
        let mod_ver = init.load_kernel_driver().await.unwrap_or_else(|e| {
            logging::log_error!("驱动加载失败: {}", e);
            String::new()
        });
        cfg.mod_ver = mod_ver;
        log_info!("load kernel driver: {}", cfg.mod_ver);
        let _ = cfg.to_ini(&format!("{}/net_info.ini", cfg.app_path));

        if !cfg.mod_ver.is_empty() {
            ensure_kernel_hold();
        }

        // 驱动加载成功后，同步 admission 到 /proc/osec/tcp_force_ecn
        let admission_enabled = cfg.admission.enabled;
        let admission_mode = cfg.admission.mode;
        let admission_switch = cfg.admission_switch;
        let admission_on = !cfg.mod_ver.is_empty();
        drop(cfg); // 释放锁
        if admission_enabled && admission_on {
            let proc_path = "/proc/osec/tcp_force_ecn";
            if std::path::Path::new(proc_path).exists() {
                let val = match admission_mode {
                    0 => "0",  // OFF
                    1 => "1",  // ON
                    2 => "0",  // AUTO — 初始先关，等自动检测逻辑来切换
                    _ => "0",
                };
                if let Err(e) = std::fs::write(proc_path, val) {
                    log_error!("写入 {} 失败: {}", proc_path, e);
                } else {
                    log_info!("准入开关同步: {} = {}", proc_path, val);
                }
            } else {
                log_info!("{} 不存在，跳过准入同步（驱动未提供该接口）", proc_path);
            }

            // 初始化全局 ADMISSION_MODE 和 ADMISSION_EFFECTIVE
            agent_local_svc::ADMISSION_MODE.store(admission_mode, std::sync::atomic::Ordering::Relaxed);
            if admission_mode == 2 {
                // AUTO 模式：effective 初始按 ini 里的 admission_switch 来
                let eff = admission_switch as u8;
                agent_local_svc::ADMISSION_EFFECTIVE.store(eff, std::sync::atomic::Ordering::Relaxed);
            } else {
                agent_local_svc::ADMISSION_EFFECTIVE.store(admission_mode, std::sync::atomic::Ordering::Relaxed);
            }

            // 如果是 AUTO 模式，启动自动检测
            if admission_mode == 2 {
                let hub = agent_local_svc::AgentDataHub::new();
                hub.start_auto_detect();
            }
        } else if !admission_enabled {
            log_info!("准入功能未启用（ENABLED=0），跳过");
        }
    }

    // 检查是否为离线模式（配置指定，直接设置，不经过阈值）
    let is_offline = NETINFO_CONFIG.lock().unwrap().is_offline_mode;
    if is_offline {
        AGENT_MODE.store(AgentMode::Offline as u8, std::sync::atomic::Ordering::Relaxed);
        ADMISSION_NETWORK_ANOMALY.store(true, std::sync::atomic::Ordering::Relaxed);
    } else {
        AGENT_MODE.store(AgentMode::Online as u8, std::sync::atomic::Ordering::Relaxed);
    }
    log_info!("当前模式: {}", if is_offline { "离线" } else { "在线" });

    // 初始化本地数据库（建表幂等，已存在时跳过）
    local_store::init_all();

    // 从 DB 恢复跳变状态到内存缓存（让重启后无需等待服务器即可返回上次跳变状态）
    match local_store::jump_status::load() {
        Ok(Some(row)) => {
            let mut js = agent_local_svc::JUMP_STATUS.lock().unwrap();
            js.current_ip        = row.current_ip;
            js.source_ip         = row.source_ip;
            js.target_ip         = row.target_ip;
            js.gateway           = row.gateway;
            js.mode              = row.mode;
            js.current_password  = row.current_password;
            js.last_ip_jump_time = row.last_ip_jump_time;
            js.last_pw_jump_time = row.last_pw_jump_time;
            js.last_pw_jump_user = row.last_pw_jump_user;
            js.ip_scheme         = row.ip_scheme;
            js.ip_cycle_label    = row.ip_cycle_label;
            js.ip_timing_label   = row.ip_timing_label;
            js.ip_way_label      = row.ip_way_label;
            js.pw_scheme         = row.pw_scheme;
            js.pw_cycle_label    = row.pw_cycle_label;
            js.pw_timing_label   = row.pw_timing_label;
            log_info!("已从 jump.db 恢复跳变状态缓存");
        }
        Ok(None) => log_info!("jump.db 无历史数据，跳过恢复"),
        Err(e)   => log_error!("从 jump.db 加载跳变状态失败: {}", e),
    }

    // 刚获得 token 时才担发 fetch，见 data_hub::update_token()

    // 创建 Netlink 套接字（在离线模式下仍尝试创建，供内核事件使用）
    let nl_sock = NlSockInfo::create_socket()
        .map_err(|e| {
            logging::log_error!("Netlink套接字创建失败: {}", e);
            e
        })
        .ok();

    if let Some(ref sock) = nl_sock {
        match send_data_to_kernel(sock) {
            Ok(msg) => log_info!("向内核发送数据成功: {}", msg),
            Err(e) => log_error!("向内核发送数据失败: {}", e),
        }
    } else {
        log_error!("Netlink socket 未创建，跳过 send_data_to_kernel");
    }

/*
    // 初始化信号处理
    let sigint = unix_signal(SignalKind::interrupt())?;
    let  sigterm = unix_signal(SignalKind::terminate())?;
*/
    
    // 启动异步任务
    let start_services_handle = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.start_services(token_tx, host_is_offline_rx)
                .await
                .map_err(|e| {
                    logging::log_error!("start_services 失败: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        }
    });

    let log_services_handler = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.start_log_services(file_audit_log_rx)
                .await
                .map_err(|e| {
                    logging::log_error!("start_log_services 失败: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        }
    });

    let task_fetcher_handle = tokio::spawn({
        let mut init = init.clone();
        let nl_sock = nl_sock.clone();
        async move {
            init.task_fetcher(host_is_offline_tx, token_rx, nl_sock)
                .await
                .map_err(|e| {
                    logging::log_error!("task_fetcher 失败: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        }
    });

    let timer_task_handle = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.start_timer_task()
                .await
                .map_err(|e| {
                    logging::log_error!("start_timer_task 失败: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        }
    });

    let event_handler = Arc::new(Mutex::new(EventHandler::new()));
    let event_handler_send = Arc::clone(&event_handler);
    let mut task_kernel_send_handler = None;
    let mut task_kernel_rcv_handler = None;
    if let Some(nl_sock) = nl_sock {
        task_kernel_send_handler = Some(tokio::spawn({
            let mut init = init.clone();
            let tx = file_audit_log_tx.clone();
            let nl_sock = nl_sock.clone();
            async move {
                init.start_kernel_send_handler(nl_sock, event_handler_send, tx)
                    .await
                    .map_err(|e| {
                        logging::log_error!("start_kernel_send_handler 失败: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e)
                    })
            }
        }));
        let event_handler_rcv = Arc::clone(&event_handler);
        task_kernel_rcv_handler = Some(tokio::spawn({
            let mut init = init.clone();
            let nl_sock = nl_sock.clone();
            async move {
                init.start_kernel_rcv_handler(nl_sock, event_handler_rcv)
                    .await
                    .map_err(|e| {
                        logging::log_error!("start_kernel_rcv_handler 失败: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e)
                    })
            }
        }));
    } else {
        logging::log_error!("无法创建 socket，跳过内核事件处理");
    }

    // 创建USB热插拔信号通道
    let (usb_hotplug_tx, usb_hotplug_rx) = mpsc::channel::<bool>(100);

    let usb_monitor_handle = tokio::spawn({
        let mut init = init.clone();
        let tx = file_audit_log_tx.clone();
        async move {
            init.start_usb_services(tx, usb_hotplug_tx)
                .await
                .map_err(|e| {
                    logging::log_error!("start_usb_services 失败: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        }
    });

    let usb_hotplug_handler_handle = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.start_usb_hotplug_handler(usb_hotplug_rx)
                .await
                .map_err(|e| {
                    logging::log_error!("start_usb_hotplug_handler 失败: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        }
    });

    let start_docker_monitor_handle = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.start_docker_monitor_services()
                .await
                .map_err(|e| {
                    logging::log_error!("start_docker_monitor_services 失败: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        }
    });

    // 启动病毒扫描 gRPC 服务
    let virus_scan_handle = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.start_virus_scan_grpc_service()
                .await
                .map_err(|e| {
                    logging::log_error!("start_virus_scan_grpc_service 失败: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        }
    });

    // 等待所有任务完成或接收退出信号
    println!("程序正在运行，按 Ctrl+C 或发送 SIGTERM 退出...");

    shutdown_signal().await;
    log_info!("程序退出，执行清理...");

    // 卸载驱动
    if let Err(e) = unload_driver() {
        log_error!("卸载驱动失败: {}", e);
    } else {
        log_info!("驱动卸载成功");
    }

    // 可选：等待一小段时间让日志 flush（如果日志是异步的）
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    log_info!("程序已安全退出");
     std::process::exit(0);
    //Ok(())

}

async fn shutdown_signal() {
    let mut sigint = unix_signal(SignalKind::interrupt()).expect("注册 SIGINT 失败");
    let mut sigterm = unix_signal(SignalKind::terminate()).expect("注册 SIGTERM 失败");

    tokio::select! {
        _ = sigint.recv() => log_info!("收到 SIGINT (Ctrl+C)"),
        _ = sigterm.recv() => log_info!("收到 SIGTERM"),
    }
}

