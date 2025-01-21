use tokio::fs;
use tokio::time::{sleep, Duration};
use tokio::signal::unix::{signal, SignalKind};
use hostinfo::HostInfo;
//use online::BaseOnline;
use online::StartOnline;
use task::TaskService;
use kernel_event::{StartKernelHandler};
use common::{manager::boot::BootManager};
use tokio::sync::mpsc;


#[tokio::main]
async fn main() -> std::io::Result<()> {

    let mut init = BootManager::init().await;

    // 生成 hostinfo.ini 文件
    let file_path = "hostinfo.ini";
    HostInfo::generate_host_info_file(file_path); 

    let (token_tx, token_rx) = mpsc::channel::<String>(32);  // 32 是通道的缓冲大小
    let (host_is_offline_tx, host_is_offline_rx) = mpsc::channel::<bool>(32);  // 32 是通道的缓冲大小
   // 启动 start_services 任务
    let start_services_handle = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.start_services(token_tx, host_is_offline_rx).await.unwrap();
        }
    });

    let task_fetcher_handle = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.task_fetcher(host_is_offline_tx, token_rx).await.unwrap();
        }
    });

    let task_kernel_handler = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.start_kernel_handler().await.unwrap();
        }
    });


    start_services_handle.await.unwrap();
    task_fetcher_handle.await.unwrap();
    task_kernel_handler.await.unwrap();



    let mut sigint = signal(SignalKind::interrupt())?;  // 捕获 Ctrl+C

    println!("程序正在运行，按 Ctrl+C 退出...");
    // 阻塞直到收到 Ctrl+C 信号
    sigint.recv().await;
    println!("收到退出信号，程序结束。");
     Ok(())
}

