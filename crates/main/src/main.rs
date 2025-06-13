use tokio::fs;
use tokio::time::{sleep, Duration};
use tokio::signal::unix::{signal, SignalKind};
use online::StartOnline;
use task::TaskService;
use kernel_event::{StartKernelHandler, EventHandler};
use common::manager::boot::BootManager;
use reporter::{FileAuditLogInfo, StartBashLog};
use tokio::sync::mpsc;
use logging;
use netlink::netlink::NlSockInfo;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    logging::CustomLogger::init("/opt/osec/osec_backend.conf")
        .await
        .expect("无法初始化日志");

    logging::log_info!("程序启动");
    let init = BootManager::init().await;

    let (file_audit_log_tx, mut file_audit_log_rx) = mpsc::channel::<FileAuditLogInfo>(128);
    let (token_tx, token_rx) = mpsc::channel::<String>(32);
    let (host_is_offline_tx, host_is_offline_rx) = mpsc::channel::<bool>(32);

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
        async move {
            init.task_fetcher(host_is_offline_tx, token_rx).await.unwrap();
        }
    });

    let nl_sock = match NlSockInfo::create_socket() {
        Ok(sock) => sock,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to create socket: {}", e),
            ));
        }
    };
    let event_handler = Arc::new(Mutex::new(EventHandler::new()));
    let event_handler_send = Arc::clone(&event_handler);
    let task_kernel_send_handler = tokio::spawn({
        let mut init = init.clone();
        let tx = file_audit_log_tx.clone();
        let nl_sock = nl_sock.clone();
        async move {
            init.start_kernel_send_handler(nl_sock, event_handler_send, tx)
                .await
                .unwrap();
        }
    });
    let event_handler_rcv = Arc::clone(&event_handler);
    let task_kernel_rcv_handler = tokio::spawn({
        let mut init = init.clone();
        let nl_sock = nl_sock.clone();
        async move {
            init.start_kernel_rcv_handler(nl_sock, event_handler_rcv)
                .await
                .unwrap();
        }
    });

    start_services_handle.await.unwrap();
    task_fetcher_handle.await.unwrap();
    task_kernel_send_handler.await.unwrap();
    task_kernel_rcv_handler.await.unwrap();
    log_services_handler.await.unwrap();

    let mut sigint = signal(SignalKind::interrupt())?;
    println!("程序正在运行，按 Ctrl+C 退出...");
    sigint.recv().await;
    println!("收到退出信号，程序结束。");
    Ok(())
}
