use libc::{sigaction, SIGPIPE, SIG_IGN, SA_RESTART, sigemptyset};
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use online::StartOnline;
use task::{TaskService, TimerTask};
use kernel_event::{StartKernelHandler, EventHandler,send_data_to_kernel};
use kernel_module::{LoadKernelDriver, unload_driver};
use common::manager::boot::BootManager;
use reporter::{AuditLogInfo, StartBashLog};
use tokio::sync::mpsc;
use logging::{log_info, CustomLogger, log_error};
use netlink::netlink::NlSockInfo;
use std::sync::Arc;
use tokio::sync::Mutex;
use config::net_info::NETINFO_CONFIG;
use udisk::StartUsbService;
use docker::StartDockerMonitor;

#[tokio::main]
async fn main() -> std::io::Result<()> {
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

    // 初始化日志
    CustomLogger::init("/opt/osec/osec_backend.conf")
        .await
        .expect("无法初始化日志");
    log_info!("程序启动");

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
    }

    // 检查是否为离线模式
    let is_offline = NETINFO_CONFIG.lock().unwrap().is_offline_mode;
    log_info!("当前模式: {}", if is_offline { "离线" } else { "在线" });

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


    let mut sigint = unix_signal(SignalKind::interrupt())?;
    let mut sigterm = unix_signal(SignalKind::terminate())?;

    let event_handler = Arc::new(Mutex::new(EventHandler::new()));
    let mut task_kernel_send_handler = None;
    let mut task_kernel_rcv_handler = None;

    if let Some(ref sock) = nl_sock {
        let event_handler_send = Arc::clone(&event_handler);
        let tx = file_audit_log_tx.clone();
        let nl_sock_send = sock.clone(); 
        task_kernel_send_handler = Some(tokio::spawn({
            let mut init = init.clone();
            async move {
                init.start_kernel_send_handler(nl_sock_send, event_handler_send, tx)
                    .await
                    .map_err(|e| {
                        logging::log_error!("start_kernel_send_handler 失败: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e)
                    })
            }
        }));

        let event_handler_rcv = Arc::clone(&event_handler);
        let nl_sock_rcv = sock.clone();
        task_kernel_rcv_handler = Some(tokio::spawn({
            let mut init = init.clone();
            async move {
                init.start_kernel_rcv_handler(nl_sock_rcv, event_handler_rcv)
                    .await
                    .map_err(|e| {
                        logging::log_error!("start_kernel_rcv_handler 失败: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e)
                    })
            }
        }));
    } else {
        logging::log_error!("无法创建 Netlink socket，跳过内核事件处理");
    }

    let task_fetcher_handle = tokio::spawn({
        let mut init = init.clone();
        let nl_sock_for_fetcher = nl_sock.clone(); // 可为 None
        async move {
            init.task_fetcher(host_is_offline_tx, token_rx, nl_sock_for_fetcher)
                .await
                .map_err(|e| {
                    logging::log_error!("task_fetcher 失败: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        }
    });

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

    // USB 服务
    let usb_monitor_handle = tokio::spawn({
        let mut init = init.clone();
        let tx = file_audit_log_tx.clone();
        async move {
            init.start_usb_services(tx)
                .await
                .map_err(|e| {
                    logging::log_error!("start_usb_services 失败: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        }
    });

    // 容器运行时检测
    let has_container_runtime = ["docker", "podman"]
        .iter()
        .any(|&cmd| {
            std::process::Command::new(cmd)
                .arg("--version")
                .output()
                .is_ok()
        });

    let start_docker_monitor_handle = if has_container_runtime {
        log_info!("检测到容器运行时，启动 Docker/Podman 监控服务");
        tokio::spawn({
            let mut init = init.clone();
            async move {
                init.start_docker_monitor_services()
                    .await
                    .map_err(|e| {
                        log_error!("start_docker_monitor_services 失败: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e)
                    })
            }
        })
    } else {
        log_info!("未检测到 docker 或 podman，跳过启动容器监控服务");
        tokio::spawn(async {
            Ok::<String, std::io::Error>("Docker monitor skipped".to_string())
        })
    };

    // 程序运行提示
    println!("程序正在运行，按 Ctrl+C 或发送 SIGTERM 退出...");

    // 等待退出信号
    shutdown_signal().await;
    log_info!("程序退出，执行清理...");

    // 卸载驱动
    if let Err(e) = unload_driver() {
        log_error!("卸载驱动失败: {}", e);
    } else {
        log_info!("驱动卸载成功");
    }

    // 等待日志 flush（如果日志是异步的）
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    log_info!("程序已安全退出");

    Ok(())
}

async fn shutdown_signal() {
    let mut sigint = unix_signal(SignalKind::interrupt()).expect("注册 SIGINT 失败");
    let mut sigterm = unix_signal(SignalKind::terminate()).expect("注册 SIGTERM 失败");

    tokio::select! {
        _ = sigint.recv() => log_info!("收到 SIGINT (Ctrl+C)"),
        _ = sigterm.recv() => log_info!("收到 SIGTERM"),
    }
}
