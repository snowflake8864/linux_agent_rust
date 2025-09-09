use libc::{sigaction, sighandler_t, SIGPIPE, SIG_IGN, SA_RESTART, sigemptyset};
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use online::StartOnline;
use task::{TaskService, TimerTask};
use kernel_event::{StartKernelHandler, EventHandler};
use kernel_module::{LoadKernelDriver, unload_driver};
use common::manager::boot::BootManager;
use reporter::{AuditLogInfo, StartBashLog};
use tokio::sync::mpsc;
use logging::{log_info, CustomLogger};
use netlink::netlink::NlSockInfo;
use std::sync::Arc;
use tokio::sync::Mutex;
use config::net_info::NETINFO_CONFIG;
use udisk::StartUsbService;
use docker::StartDockerMonitor;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    unsafe {
        let mut sa: sigaction = std::mem::zeroed();
        sa.sa_sigaction = SIG_IGN as usize;
        sa.sa_flags = SA_RESTART;
        sigemptyset(&mut sa.sa_mask);
        if sigaction(SIGPIPE, &sa, std::ptr::null_mut()) != 0 {
            panic!("sigaction failed to set SIGPIPE to ignore");
        }
    }
    CustomLogger::init("/opt/osec/osec_backend.conf")
        .await
        .expect("无法初始化日志");

    log_info!("程序启动");

    let _ = unload_driver().ok();
    let init = BootManager::init().await;
    let (file_audit_log_tx, file_audit_log_rx) = mpsc::channel::<AuditLogInfo>(512);
    let (token_tx, token_rx) = mpsc::channel::<String>(8);
    let (host_is_offline_tx, host_is_offline_rx) = mpsc::channel::<bool>(8);

    {
        let mut cfg = NETINFO_CONFIG.lock().unwrap();
        let mut init = init.clone();
        let mod_ver = init.load_kernel_driver().await.unwrap_or_else(|e| {
            logging::log_error!("驱动加载失败: {}", e);
            String::new()
        });
        cfg.mod_ver = mod_ver;
    }
    let nl_sock = NlSockInfo::create_socket()
        .map_err(|e| {
            logging::log_error!("Netlink套接字创建失败: {}", e);
            e
        })
    .ok(); 
           //
    let start_services_handle = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.start_services(token_tx, host_is_offline_rx).await.unwrap();
        }
    });

    let log_services_handler = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.start_log_services(file_audit_log_rx).await.unwrap();
        }
    });

    let task_fetcher_handle = tokio::spawn({
        let mut init = init.clone();
        let nl_sock = nl_sock.clone();
        async move {
            init.task_fetcher(host_is_offline_tx, token_rx, nl_sock).await.unwrap();
        }
    });

    let timer_task_handle = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.start_timer_task().await.unwrap();
        }
    });
    let event_handler = Arc::new(Mutex::new(EventHandler::new()));
    let event_handler_send = Arc::clone(&event_handler);

    let mut task_kernel_send_handler = None;
    let mut task_kernel_rcv_handler = None;

    if let Some(nl_sock) = nl_sock
    {
        task_kernel_send_handler = Some(tokio::spawn({
            let mut init = init.clone();
            let tx = file_audit_log_tx.clone();
            let nl_sock = nl_sock.clone();
            async move {
                init.start_kernel_send_handler(nl_sock, event_handler_send, tx)
                    .await
                    .unwrap();
            }
        }));

        let event_handler_rcv = Arc::clone(&event_handler);
        task_kernel_rcv_handler = Some(tokio::spawn({
            let mut init = init.clone();
            let nl_sock = nl_sock.clone();
            async move {
                init.start_kernel_rcv_handler(nl_sock, event_handler_rcv)
                    .await
                    .unwrap();
            }
        }));
    } else {
        logging::log_error!("无法创建 socket，跳过内核事件处理");
    }
    
    let usb_monitor_handle = tokio::spawn({
        let mut init = init.clone();
        let tx = file_audit_log_tx.clone();
        async move {
            init.start_usb_services(tx).await.unwrap();
        }
    });
    
    let start_docker_monitor_handle = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.start_docker_monitor_services().await.unwrap();            
        } 
    });
    start_services_handle.await.unwrap();
    task_fetcher_handle.await.unwrap();
    log_services_handler.await.unwrap();
    timer_task_handle.await.unwrap();
    usb_monitor_handle.await.unwrap();
    start_docker_monitor_handle.await.unwrap();

    if let Some(handle) = task_kernel_send_handler {
        handle.await.unwrap();
    }
    if let Some(handle) = task_kernel_rcv_handler {
        handle.await.unwrap();
    }

    let mut sigint = unix_signal(SignalKind::interrupt())?;
    println!("程序正在运行，按 Ctrl+C 退出...");
    sigint.recv().await;
    log_info!("收到退出信号，程序结束。");

    Ok(())
}

