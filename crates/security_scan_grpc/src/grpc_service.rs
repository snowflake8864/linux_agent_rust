//! SecurityScanService gRPC 实现
//!
//! 关键点：脚本执行时间较长（逐项检测 + 每项 0.5s 间隔，约 8~30s），不能阻塞。
//! 因此：
//!   - 使用 `tokio::process::Command` 异步拉起脚本（内部走阻塞线程池，不占 reactor 线程）；
//!   - 采用服务端流式 RPC：`run_scan` 立即返回流，脚本在后台 task 中运行，
//!     逐条读取 stdout 并流式推送 `progress`，最后推送 `completed`/`failed`。

use futures::Stream;
use grpc_gateway::security_scan::security_scan_service_server::SecurityScanService;
use grpc_gateway::security_scan::security_scan_event::Event;
use grpc_gateway::security_scan::{
    CheckSecurityResponse, RunSecurityScanRequest, ScanCompleted, ScanFailed, ScanProgress, ScanStarted,
    SecurityCheckItem, SecurityScanEvent,
};
use logging::{log_error, log_info, log_warn};
use std::pin::Pin;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

type GrpcStream = Pin<Box<dyn Stream<Item = Result<SecurityScanEvent, Status>> + Send>>;

/// 安全检测脚本路径
const SCRIPT_PATH: &str = "/opt/osec/SecurityScan_linux.sh";
/// 报告默认输出目录
const DEFAULT_OUTPUT_DIR: &str = "/tmp";

pub struct SecurityScanGrpcService;

impl SecurityScanGrpcService {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SecurityScanGrpcService {
    fn default() -> Self {
        Self::new()
    }
}

#[tonic::async_trait]
impl SecurityScanService for SecurityScanGrpcService {
    type RunScanStream = GrpcStream;

    async fn run_scan(
        &self,
        request: Request<RunSecurityScanRequest>,
    ) -> Result<Response<Self::RunScanStream>, Status> {
        let req = request.into_inner();
        let output_dir = if req.output_dir.trim().is_empty() {
            DEFAULT_OUTPUT_DIR.to_string()
        } else {
            req.output_dir.clone()
        };

        let (tx, rx) = mpsc::channel::<Result<SecurityScanEvent, Status>>(crate::STREAM_BUFFER_SIZE);

        // 脚本在后台 task 中异步运行，run_scan 立即返回，不阻塞 gRPC 处理
        tokio::spawn(async move {
            let _ = tx
                .send(Ok(SecurityScanEvent {
                    event: Some(Event::Started(ScanStarted {
                        message: "系统安全检测已启动".to_string(),
                    })),
                }))
                .await;

            if let Err(e) = run_script(&output_dir, &tx).await {
                log_error!("[SecurityScan] 检测执行失败: {}", e);
                let _ = tx
                    .send(Ok(SecurityScanEvent {
                        event: Some(Event::Failed(ScanFailed { message: e })),
                    }))
                    .await;
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx)) as GrpcStream))
    }
}

/// 异步执行脚本并流式解析结果。
///
/// 脚本 stdout 在每项检测完成后不立即输出（结果在 main() 末尾统一 echo），
/// 但这里仍然逐行读取，配合异步进程调用，保证整个过程中不阻塞 reactor。
async fn run_script(
    output_dir: &str,
    tx: &mpsc::Sender<Result<SecurityScanEvent, Status>>,
) -> Result<(), String> {
    let mut child = Command::new("bash")
        .arg(SCRIPT_PATH)
        .arg("-o")
        .arg(output_dir)
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("启动检测脚本失败: {}", e))?;

    let stdout = child.stdout.take().ok_or("无法获取脚本 stdout")?;
    let stderr = child.stderr.take().ok_or("无法获取脚本 stderr")?;

    let mut report_file = String::new();
    let mut items: Vec<SecurityCheckItem> = Vec::new();
    let mut checked: i32 = 0;

    let mut lines = BufReader::new(stdout).lines();
    while let Some(line) = lines
        .next_line()
        .await
        .map_err(|e| format!("读取脚本输出失败: {}", e))?
    {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix("HTML:") {
            report_file = rest.trim().to_string();
            continue;
        }
        if line == "SCAN_COMPLETE" {
            continue;
        }

        // 逐条解析 "LEVEL: 描述"
        if let Some((level, desc)) = line.split_once(':') {
            let level = level.trim().to_uppercase();
            let desc = desc.trim().to_string();
            if level == "SAFE" || level == "WARNING" || level == "CRITICAL" {
                checked += 1;
                let item = SecurityCheckItem {
                    level: level.clone(),
                    description: desc,
                };
                items.push(item.clone());
                let _ = tx
                    .send(Ok(SecurityScanEvent {
                        event: Some(Event::Progress(ScanProgress { checked, item: Some(item) })),
                    }))
                    .await;
                continue;
            }
        }

        log_info!("[SecurityScan] 脚本输出: {}", line);
    }

    // stdout 已 EOF（脚本已退出），reap 子进程拿到退出码
    let status = child
        .wait()
        .await
        .map_err(|e| format!("等待脚本结束失败: {}", e))?;

    // 脚本退出后再读取 stderr（子进程已结束，管道已满也不会死锁）
    let mut err_lines = BufReader::new(stderr).lines();
    while let Some(l) = err_lines.next_line().await.unwrap_or(None) {
        let l = l.trim();
        if !l.is_empty() {
            log_warn!("[SecurityScan] 脚本 stderr: {}", l);
}
}

/// ============================================================================
// 简化版：直接返回检测结果（unary RPC，仅最终汇总）
// ============================================================================

// 异步执行脚本并解析固定输出格式
// 这是一个独立函数，不实现 tonic trait - 可被网关层或其他代码调用
async fn run_check_security_inner(output_dir: &str) -> Result<CheckSecurityResponse, String> {
    let mut child = Command::new("bash")
        .arg(SCRIPT_PATH)
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("启动检测脚本失败: {}", e))?;

    let stdout = child.stdout.take().ok_or("无法获取脚本 stdout")?;
    let stderr = child.stderr.take().ok_or("无法获取脚本 stderr")?;

    let mut report_file = String::new();
    let mut safe_count = 0i32;
    let mut warning_count = 0i32;
    let mut critical_count = 0i32;
    let mut score = 0i32;

    let mut lines = BufReader::new(stdout).lines();
    while let Some(line) = lines
        .next_line()
        .await
        .map_err(|e| format!("读取脚本输出失败: {}", e))?
    {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix("HTML:") {
            report_file = rest.trim().to_string();
            continue;
        }
        if line == "SCAN_COMPLETE" {
            continue;
        }

        // 解析 "安全: 5"、"警告: 2"、"危险: 2"
        if let Some((label, value)) = line.split_once(':') {
            let level = label.trim();
            let value: i32 = value.trim().parse().unwrap_or(0);
            match level {
                "安全" => safe_count = value,
                "警告" => warning_count = value,
                "危险" => critical_count = value,
                _ => {}
            }
        }

        // 解析 "安全评分: 55%"
        if line.starts_with("安全评分:") {
            let score_str: String = line.split_once(':').unwrap().1.trim().replace("%", "");
            score = score_str.parse().unwrap_or(0);
        }
    }

    // 等待子进程结束
    let status = child
        .wait()
        .await
        .map_err(|e| format!("等待脚本结束失败: {}", e))?;

    let success = status.success();
    let message = if success {
        "检测完成".to_string()
    } else {
        format!("检测结束，退出码 {:?}", status.code())
    };

    Ok(CheckSecurityResponse {
        success,
        message,
        safe_count,
        warning_count,
        critical_count,
        score,
        report_file,
    })
}

    let success = status.success();
    let safe = items.iter().filter(|i| i.level == "SAFE").count() as i32;
    let warning = items.iter().filter(|i| i.level == "WARNING").count() as i32;
    let critical = items.iter().filter(|i| i.level == "CRITICAL").count() as i32;
    let total = safe + warning + critical;
    let score = if total > 0 { safe * 100 / total } else { 0 };

    let message = if success {
        "检测完成".to_string()
    } else {
        format!("检测结束，退出码 {:?}", status.code())
    };

    let _ = tx
        .send(Ok(SecurityScanEvent {
            event: Some(Event::Completed(ScanCompleted {
                success,
                message,
                report_file,
                safe_count: safe,
                warning_count: warning,
                critical_count: critical,
                score,
            })),
        }))
        .await;

    Ok(())
}
