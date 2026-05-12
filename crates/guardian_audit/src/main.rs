// crates/guardian_audit/src/main.rs
//
// Security Evaluator - 独立二进制入口
// 安全评估模块，提供设备认证、心跳、控制列表同步、策略查询等功能

use std::fs;
use std::path::Path;
use libc::{sigaction, SIGPIPE, SIG_IGN, SA_RESTART, sigemptyset};
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use logging::{log_info, log_error, CustomLogger};

const PID_FILE: &str = "/var/run/security-evaluator.pid";

/// 检查 PID 对应的进程是否正在运行
fn pid_is_running(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

/// 确保单实例运行
fn ensure_single_instance() {
    if Path::new(PID_FILE).exists() {
        if let Ok(content) = fs::read_to_string(PID_FILE) {
            if let Ok(old_pid) = content.trim().parse::<u32>() {
                if pid_is_running(old_pid) {
                    eprintln!("❌ security-evaluator 已在运行 (PID={})！", old_pid);
                    std::process::exit(1);
                } else {
                    log_info!("发现过期的 PID 文件 (PID={})，将覆盖", old_pid);
                }
            }
        }
    }

    let current_pid = std::process::id();
    if let Err(e) = fs::write(PID_FILE, current_pid.to_string()) {
        eprintln!("⚠ 无法写入 PID 文件: {}", e);
    }

    println!("✔ 单实例检查通过，当前 PID={}", current_pid);
    log_info!("security-evaluator 启动，PID={}", current_pid);
}

/// 忽略 SIGPIPE 信号
fn ignore_sigpipe() {
    unsafe {
        let mut sa: sigaction = std::mem::zeroed();
        sa.sa_sigaction = SIG_IGN as usize;
        sa.sa_flags = SA_RESTART;
        sigemptyset(&mut sa.sa_mask);
        if sigaction(SIGPIPE, &sa, std::ptr::null_mut()) != 0 {
            panic!("sigaction failed to set SIGPIPE to ignore");
        }
    }
}

/// 等待关闭信号
async fn shutdown_signal() {
    let mut sigint = unix_signal(SignalKind::interrupt()).expect("注册 SIGINT 失败");
    let mut sigterm = unix_signal(SignalKind::terminate()).expect("注册 SIGTERM 失败");

    tokio::select! {
        _ = sigint.recv() => log_info!("收到 SIGINT (Ctrl+C)"),
        _ = sigterm.recv() => log_info!("收到 SIGTERM"),
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // 单实例检查
    ensure_single_instance();

    // 忽略 SIGPIPE
    ignore_sigpipe();

    // 初始化日志
    let conf_path = "/opt/osec/guardian_audit.conf";
    CustomLogger::init(conf_path)
        .await
        .unwrap_or_else(|e| {
            eprintln!("⚠ 日志初始化失败: {}，使用默认配置", e);
        });

    log_info!("========================================");
    log_info!("Security Evaluator 开始启动");
    log_info!("========================================");

    // 启动安全评估服务
    let service_result = tokio::spawn(async move {
        guardian_audit::start_guardian_audit_service().await
    });

    // 等待关闭信号
    shutdown_signal().await;
    log_info!("程序退出，执行清理...");

    // 等待服务退出
    let _ = service_result.await;

    // 清理 PID 文件
    if let Err(e) = fs::remove_file(PID_FILE) {
        log_error!("清理 PID 文件失败: {}", e);
    } else {
        log_info!("PID 文件已清理");
    }

    // 等待日志 flush
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    log_info!("Security Evaluator 已安全退出");
    std::process::exit(0);
}
