use crate::proto::{ScanProgress, VirusAlert, ScanCompleted, ServerMessage, FileScanResult};
use crate::clamav_scanner::{ClamAVScanner, ScanResult};
use chrono::Utc;
use common::manager::boot::BootManager;
use logging::{log_error, log_info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::fs;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tonic::Status;
use uuid::Uuid;

const SCAN_STATE_IDLE: u8 = 0;
const SCAN_STATE_RUNNING: u8 = 1;
const SCAN_STATE_STOPPED: u8 = 2;
const SCAN_STATE_COMPLETED: u8 = 3;

#[derive(Clone, Serialize, Deserialize)]
pub struct VirusScanAlert {
    pub time: i64,
    pub file_dir: String,
    pub virus_type: String,
    pub virus_desc: String,
}

pub fn build_virus_alert_json(alerts: &[VirusScanAlert], str_json: &mut String) -> Result<(), String> {
    #[derive(Serialize)]
    struct VirusEntry {
        time: i64,
        file_dir: String,
        virus_type: String,
        virus_desc: String,
    }

    let entries: Vec<VirusEntry> = alerts
        .iter()
        .map(|alert| VirusEntry {
            time: alert.time,
            file_dir: alert.file_dir.clone(),
            virus_type: alert.virus_type.clone(),
            virus_desc: alert.virus_desc.clone(),
        })
        .collect();

    if entries.is_empty() {
        return Err("No valid virus alerts".to_string());
    }

    let entries_str = serde_json::to_string(&entries)
        .map_err(|e| format!("Entries序列化失败: {}", e))?;

    let json_obj = serde_json::json!({
        "alert": entries_str
    });

    *str_json = serde_json::to_string(&json_obj)
        .map_err(|e| format!("JSON序列化失败: {}", e))?;

    Ok(())
}

#[derive(Clone)]
pub struct ScanTask {
    pub scan_id: String,
    pub target: String,
    pub excludes: Vec<String>,
    pub state: Arc<AtomicU8>,
    pub scanned: Arc<AtomicU32>,
    pub viruses: Arc<AtomicU32>,
    pub start_time: i64,
    pub tx: mpsc::Sender<Result<ServerMessage, Status>>,
}

pub struct ScanTaskManager {
    tasks: Arc<Mutex<HashMap<String, ScanTask>>>,
    net_client: Arc<net_client::core::NetClient>,
    server_b_url: String,
    clamav_scanner: Option<Arc<ClamAVScanner>>,
    virus_tx: mpsc::Sender<VirusScanAlert>,
    virus_rx: Arc<Mutex<mpsc::Receiver<VirusScanAlert>>>,
    boot_manager: Option<BootManager>,
}

impl ScanTask {
    pub fn new(
        scan_id: String,
        target: String,
        excludes: Vec<String>,
        tx: mpsc::Sender<Result<ServerMessage, Status>>,
    ) -> Self {
        Self {
            scan_id,
            target,
            excludes,
            state: Arc::new(AtomicU8::new(SCAN_STATE_IDLE)),
            scanned: Arc::new(AtomicU32::new(0)),
            viruses: Arc::new(AtomicU32::new(0)),
            start_time: Utc::now().timestamp_millis(),
            tx,
        }
    }

    pub fn start(&self) {
        self.state.store(SCAN_STATE_RUNNING, Ordering::Relaxed);
    }

    pub fn stop(&self) {
        self.state.store(SCAN_STATE_STOPPED, Ordering::Relaxed);
    }

    pub fn complete(&self) {
        self.state.store(SCAN_STATE_COMPLETED, Ordering::Relaxed);
    }

    pub fn is_running(&self) -> bool {
        self.state.load(Ordering::Relaxed) == SCAN_STATE_RUNNING
    }
}

impl ScanTaskManager {
    pub fn new(
        net_client: Arc<net_client::core::NetClient>,
        server_b_url: String,
        clamav_scanner: Option<Arc<ClamAVScanner>>,
        boot_manager: Option<BootManager>,
    ) -> Self {
        let (virus_tx, virus_rx) = mpsc::channel(1024);
        Self {
            tasks: Arc::new(Mutex::new(HashMap::new())),
            net_client,
            server_b_url,
            clamav_scanner,
            virus_tx,
            virus_rx: Arc::new(Mutex::new(virus_rx)),
            boot_manager,
        }
    }

    pub fn start_virus_report_worker(&self) {
    }

    pub async fn report_virus_alerts(&self) {
        let mut rx = self.virus_rx.lock().await;
        let mut alerts = Vec::new();
        while let Ok(alert) = rx.try_recv() {
            alerts.push(alert);
        }
        drop(rx);

        if alerts.is_empty() {
            return;
        }

        let base_url = self.server_b_url.clone();
        let url = format!("{}/v1/upVirusScan", base_url);

        let mut json_str = String::new();
        match build_virus_alert_json(&alerts, &mut json_str) {
            Ok(()) => {
                log_info!("病毒告警上报内容: {}", json_str);
                let token = async {
                    match &self.boot_manager {
                        Some(m) => m.get_token().await,
                        None => None,
                    }
                }.await;
                match self.net_client.post_data_async(&url, &json_str, Duration::from_secs(10), token.as_deref()).await {
                    Ok(response) => log_info!("病毒告警上报成功，响应: {}", response),
                    Err(e) => log_error!("病毒告警上报失败: {}", e),
                }
            }
            Err(e) => log_error!("构建 JSON 失败: {}", e),
        }
    }

    pub async fn start_scan(
        &self,
        target: &str,
        excludes: &[String],
        tx: mpsc::Sender<Result<ServerMessage, Status>>,
    ) -> Result<String, String> {
        let path = Path::new(target);
        if !path.exists() {
            return Err(format!("路径不存在: {}", target));
        }
        if !path.is_dir() {
            return Err("扫描目标必须是目录".to_string());
        }

        let scan_id = Uuid::new_v4().to_string();

        let task = ScanTask::new(
            scan_id.clone(),
            target.to_string(),
            excludes.to_vec(),
            tx,
        );
        task.start();

        let mut tasks = self.tasks.lock().await;
        tasks.insert(scan_id.clone(), task.clone());
        drop(tasks);

        log_info!("开始扫描: scan_id={}, target={}", scan_id, target);

        let self_clone = self.clone();
        let target = target.to_string();
        let excludes = excludes.to_vec();
        let scan_id_clone = scan_id.clone();

        tokio::spawn(async move {
            self_clone
                .execute_scan(&scan_id_clone, &target, &excludes, &task)
                .await;
        });

        Ok(scan_id)
    }

    pub async fn stop_scan(&self, scan_id: &str) {
        let mut tasks = self.tasks.lock().await;
        if let Some(task) = tasks.get(scan_id) {
            task.stop();
            log_info!("扫描已停止: {}", scan_id);
        }
    }

    async fn execute_scan(
        &self,
        scan_id: &str,
        target: &str,
        excludes: &[String],
        task: &ScanTask,
    ) {
        let path = Path::new(target);

        let mut total_scanned = 0;
        self.scan_directory_recursive(path, excludes, scan_id, task, &mut total_scanned).await;

        let duration_ms = Utc::now().timestamp_millis() - task.start_time;
        task.complete();

        let completed = ScanCompleted {
            scan_id: scan_id.to_string(),
            total_scanned: total_scanned as i32,
            viruses_found: task.viruses.load(Ordering::Relaxed) as i32,
            duration_ms,
        };
        let _ = task.tx.send(Ok(ServerMessage {
            event: Some(crate::proto::server_message::Event::Completed(completed)),
        })).await;

        self.report_virus_alerts().await;

        let mut tasks = self.tasks.lock().await;
        tasks.remove(scan_id);
    }

    async fn scan_directory_recursive(
        &self,
        dir_path: &Path,
        excludes: &[String],
        scan_id: &str,
        task: &ScanTask,
        total_scanned: &mut u32,
    ) {
        let mut entries = match fs::read_dir(dir_path).await {
            Ok(e) => e,
            Err(e) => {
                log_error!("打开目录失败: {} - {}", dir_path.display(), e);
                return;
            }
        };

        while let Some(entry) = entries.next_entry().await.ok().flatten() {
            if task.state.load(Ordering::Relaxed) != SCAN_STATE_RUNNING {
                break;
            }

            let file_path = entry.path().to_string_lossy().to_string();
            if file_path.ends_with("/.") || file_path.ends_with("/..") {
                continue;
            }

            if excludes.iter().any(|e| file_path.starts_with(e)) {
                continue;
            }

            match entry.file_type().await {
                Ok(ft) if ft.is_dir() => {
                    Box::pin(self.scan_directory_recursive(&entry.path(), excludes, scan_id, task, total_scanned)).await;
                }
                Ok(ft) if ft.is_file() => {
                    let scan_start = std::time::Instant::now();
                    if let Some(scanner) = &self.clamav_scanner {
                        match scanner.scan_file(&file_path).await {
                            Ok(ScanResult::Virus { name }) => {
                                log_info!("[SCAN] {} -> VIRUS ({})", file_path, name);
                                self.send_virus_alert(scan_id, &file_path, &name, task).await;
                                self.send_file_scan_result(scan_id, &file_path, "VIRUS", Some(&name), None, scan_start.elapsed().as_millis() as i64, task).await;
                            }
                            Ok(ScanResult::Clean) => {
                                log_info!("[SCAN] {} -> OK", file_path);
                                self.send_file_scan_result(scan_id, &file_path, "OK", None, None, scan_start.elapsed().as_millis() as i64, task).await;
                            }
                            Ok(ScanResult::Error { message }) => {
                                log_error!("[SCAN] {} -> ERROR: {}", file_path, message);
                                self.send_file_scan_result(scan_id, &file_path, "ERROR", None, Some(&message), scan_start.elapsed().as_millis() as i64, task).await;
                            }
                            Err(e) => {
                                log_error!("[SCAN] {} -> ERROR: {}", file_path, e);
                                self.send_file_scan_result(scan_id, &file_path, "ERROR", None, Some(&e), scan_start.elapsed().as_millis() as i64, task).await;
                            }
                        }
                    } else {
                        log_error!("[SCAN] {} -> ERROR: ClamAV 不可用", file_path);
                        self.send_file_scan_result(scan_id, &file_path, "ERROR", None, Some("ClamAV 不可用"), scan_start.elapsed().as_millis() as i64, task).await;
                    }

                    *total_scanned += 1;

                    if *total_scanned % 10 == 0 {
                        let progress = ScanProgress {
                            scan_id: scan_id.to_string(),
                            scanned: *total_scanned as i32,
                            total: 0,
                            viruses_found: task.viruses.load(Ordering::Relaxed) as i32,
                            current_path: file_path.clone(),
                        };
                        let _ = task.tx.send(Ok(ServerMessage {
                            event: Some(crate::proto::server_message::Event::Progress(progress)),
                        })).await;
                    }
                }
                _ => {}
            }
        }
    }

    /// 发送病毒告警 (ClamAV 模式)
    async fn send_virus_alert(
        &self,
        scan_id: &str,
        file_path: &str,
        virus_name: &str,
        task: &ScanTask,
    ) {
        task.viruses.fetch_add(1, Ordering::Relaxed);

        let threat_level = self.determine_threat_level(virus_name);
        
        let alert = VirusAlert {
            scan_id: scan_id.to_string(),
            file_path: file_path.to_string(),
            virus_name: virus_name.to_string(),
            md5: "".to_string(),  // ClamAV 模式不计算 MD5
            threat_level,
            detected_at: Utc::now().timestamp_millis(),
            file_size: "".to_string(),
        };

        let _ = task.tx.send(Ok(ServerMessage {
            event: Some(crate::proto::server_message::Event::VirusAlert(alert)),
        })).await;

        let virus_scan_alert = VirusScanAlert {
            time: Utc::now().timestamp(),
            file_dir: file_path.to_string(),
            virus_type: virus_name.to_string(),
            virus_desc: "".to_string(),
        };
        let _ = self.virus_tx.send(virus_scan_alert).await;

        log_info!("[gRPC] 上报病毒告警: {} - {}", file_path, virus_name);
    }

    /// 发送单个文件扫描结果
    async fn send_file_scan_result(
        &self,
        scan_id: &str,
        file_path: &str,
        status: &str,
        virus_name: Option<&str>,
        error_message: Option<&str>,
        scan_time_ms: i64,
        task: &ScanTask,
    ) {
        let result = FileScanResult {
            scan_id: scan_id.to_string(),
            file_path: file_path.to_string(),
            status: status.to_string(),
            virus_name: virus_name.unwrap_or("").to_string(),
            error_message: error_message.unwrap_or("").to_string(),
            scan_time_ms,
            scanned_at: Utc::now().timestamp_millis(),
        };

        let _ = task.tx.send(Ok(ServerMessage {
            event: Some(crate::proto::server_message::Event::FileScanResult(result)),
        })).await;

        log_info!("[gRPC] 上报文件结果: {} -> {} ({}ms)", file_path, status, scan_time_ms);
    }

    /// 根据病毒名判断威胁级别
    fn determine_threat_level(&self, virus_name: &str) -> String {
        let name_lower = virus_name.to_lowercase();
        
        if name_lower.contains("ransomware") || name_lower.contains("crypto") {
            "CRITICAL".to_string()
        } else if name_lower.contains("trojan") || name_lower.contains("backdoor") {
            "HIGH".to_string()
        } else if name_lower.contains("adware") || name_lower.contains("pup") {
            "MEDIUM".to_string()
        } else if name_lower.contains("test") || name_lower.contains("eicar") {
            "LOW".to_string()  // 测试文件
        } else {
            "HIGH".to_string()  // 默认高危
        }
    }
}

impl Clone for ScanTaskManager {
    fn clone(&self) -> Self {
        Self {
            tasks: Arc::clone(&self.tasks),
            net_client: Arc::clone(&self.net_client),
            server_b_url: self.server_b_url.clone(),
            clamav_scanner: self.clamav_scanner.as_ref().map(|s| Arc::clone(s)),
            virus_tx: self.virus_tx.clone(),
            virus_rx: Arc::clone(&self.virus_rx),
            boot_manager: self.boot_manager.clone(),
        }
    }
}
