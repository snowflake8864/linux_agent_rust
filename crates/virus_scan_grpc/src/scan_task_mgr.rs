use crate::proto::{ScanProgress, VirusAlert, ScanCompleted, ServerMessage, FileScanResult};
use crate::vigilixav_scanner::{VigilixAVConnectionPool, ScanResult};
use chrono::Utc;
use common::manager::boot::BootManager;
use logging::{log_error, log_info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, Notify, Semaphore};
use tokio::fs;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tonic::Status;
use uuid::Uuid;

const SCAN_STATE_IDLE: u8 = 0;
const SCAN_STATE_RUNNING: u8 = 1;
const SCAN_STATE_STOPPED: u8 = 2;
const SCAN_STATE_COMPLETED: u8 = 3;
const SCAN_STATE_PAUSED: u8 = 4;

const SYSTEM_EXCLUDES: &[&str] = &[
    "/proc", "/sys", "/dev", "/run", "/snap", "/cgroup",
    "/swapfile", "/swap.img", "/var/swap", "/var/swapfile", "/lost+found",
    "/boot/System.map", "/boot/config",
];

fn merge_excludes(user_excludes: &[String]) -> Vec<String> {
    let mut merged = user_excludes.to_vec();
    for sys_excl in SYSTEM_EXCLUDES {
        let s = sys_excl.to_string();
        if !merged.iter().any(|e| e == &s) {
            merged.push(s);
        }
    }
    merged
}

enum ScanAction {
    Virus(String),
    Clean,
    Error(String),
}

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
    pub resume_notify: Arc<Notify>,
}

pub struct ScanTaskManager {
    tasks: Arc<Mutex<HashMap<String, ScanTask>>>,
    net_client: Arc<net_client::core::NetClient>,
    server_b_url: String,
    vigilixav_scanner: Option<Arc<VigilixAVConnectionPool>>,
    virus_tx: mpsc::Sender<VirusScanAlert>,
    virus_rx: Arc<Mutex<mpsc::Receiver<VirusScanAlert>>>,
    boot_manager: Option<BootManager>,
    scan_semaphore: Arc<Semaphore>,
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
            resume_notify: Arc::new(Notify::new()),
        }
    }

    pub fn start(&self) {
        self.state.store(SCAN_STATE_RUNNING, Ordering::Relaxed);
    }

    pub fn stop(&self) {
        self.state.store(SCAN_STATE_STOPPED, Ordering::Relaxed);
        // 如果当前是暂停状态，需要唤醒以便退出循环
        self.resume_notify.notify_waiters();
    }

    pub fn pause(&self) {
        let current = self.state.load(Ordering::Relaxed);
        if current == SCAN_STATE_RUNNING {
            self.state.store(SCAN_STATE_PAUSED, Ordering::Relaxed);
        }
    }

    pub fn resume(&self) {
        let current = self.state.load(Ordering::Relaxed);
        if current == SCAN_STATE_PAUSED {
            self.state.store(SCAN_STATE_RUNNING, Ordering::Relaxed);
            self.resume_notify.notify_waiters();
        }
    }

    pub fn complete(&self) {
        self.state.store(SCAN_STATE_COMPLETED, Ordering::Relaxed);
    }

    pub fn is_running(&self) -> bool {
        self.state.load(Ordering::Relaxed) == SCAN_STATE_RUNNING
    }

    pub fn is_paused(&self) -> bool {
        self.state.load(Ordering::Relaxed) == SCAN_STATE_PAUSED
    }

    /// 等待恢复：如果当前是 PAUSED 状态，则挂起直到恢复或停止
    pub async fn wait_if_paused(&self) {
        while self.state.load(Ordering::Relaxed) == SCAN_STATE_PAUSED {
            self.resume_notify.notified().await;
        }
    }
}

impl ScanTaskManager {
    pub fn new(
        net_client: Arc<net_client::core::NetClient>,
        server_b_url: String,
        vigilixav_scanner: Option<Arc<VigilixAVConnectionPool>>,
        boot_manager: Option<BootManager>,
    ) -> Self {
        let (virus_tx, virus_rx) = mpsc::channel(1024);
        let concurrency = config::net_info::NETINFO_CONFIG.lock().unwrap().vigilixav_pool_size;
        log_info!("扫描并发数设置为: {}", concurrency);
        Self {
            tasks: Arc::new(Mutex::new(HashMap::new())),
            net_client,
            server_b_url,
            vigilixav_scanner,
            virus_tx,
            virus_rx: Arc::new(Mutex::new(virus_rx)),
            boot_manager,
            scan_semaphore: Arc::new(Semaphore::new(concurrency)),
        }
    }

    pub fn vigilixav_scanner(&self) -> Option<Arc<VigilixAVConnectionPool>> {
        self.vigilixav_scanner.clone()
    }

    /// gRPC 连接断开时调用，清理该连接关联的已完成任务。
    /// 避免 task 永久驻留内存。
    pub async fn clear_completed_tasks(&self) {
        let mut tasks = self.tasks.lock().await;
        let before = tasks.len();
        tasks.retain(|_id, task| task.is_running() || task.is_paused());
        let removed = before - tasks.len();
        if removed > 0 {
            log_info!("[SCAN] gRPC 连接断开，清理已完成 task: {} 个", removed);
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
                //log_info!("病毒告警上报内容: {}", json_str);
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
    ) -> Result<(String, String), String> {
        let path = Path::new(target);
        if !path.exists() {
            return Err(format!("路径不存在: {}", target));
        }
        if !path.is_dir() {
            return Err("扫描目标必须是目录".to_string());
        }

        let merged_excludes = merge_excludes(excludes);

        let scan_id = Uuid::new_v4().to_string();
        /*
        let msg = format!(
            "扫描已启动，系统目录({})已自动排除",
            SYSTEM_EXCLUDES.join(", ")
        );
        */
        let msg = format!(
            "扫描已启动"
        );


        let task = ScanTask::new(
            scan_id.clone(),
            target.to_string(),
            merged_excludes.clone(),
            tx,
        );
        task.start();

        let mut tasks = self.tasks.lock().await;
        tasks.insert(scan_id.clone(), task.clone());
        drop(tasks);

        log_info!("开始扫描: scan_id={}, target={}, excludes={:?}", scan_id, target, merged_excludes);

        let self_clone = self.clone();
        let target = target.to_string();
        let scan_id_clone = scan_id.clone();

        tokio::spawn(async move {
            self_clone
                .execute_scan(&scan_id_clone, &target, &merged_excludes, &task)
                .await;
        });

        Ok((scan_id, msg))
    }

    pub async fn stop_scan(&self, scan_id: &str) {
        let tasks = self.tasks.lock().await;
        if let Some(task) = tasks.get(scan_id) {
            task.stop();
            log_info!("扫描已停止: {}", scan_id);
        }
    }

    pub async fn pause_scan(&self, scan_id: &str) -> Result<String, String> {
        let tasks = self.tasks.lock().await;
        if let Some(task) = tasks.get(scan_id) {
            let current = task.state.load(Ordering::Relaxed);
            if current == SCAN_STATE_RUNNING {
                task.pause();
                log_info!("扫描已暂停: {}", scan_id);
                Ok("扫描已暂停，当前批次文件扫完后生效".to_string())
            } else if current == SCAN_STATE_PAUSED {
                Err("扫描已处于暂停状态".to_string())
            } else {
                Err(format!("扫描不在运行状态，当前状态: {}", current))
            }
        } else {
            Err(format!("扫描任务不存在: {}", scan_id))
        }
    }

    pub async fn resume_scan(&self, scan_id: &str) -> Result<String, String> {
        let tasks = self.tasks.lock().await;
        if let Some(task) = tasks.get(scan_id) {
            let current = task.state.load(Ordering::Relaxed);
            if current == SCAN_STATE_PAUSED {
                task.resume();
                log_info!("扫描已恢复: {}", scan_id);
                Ok("扫描已恢复".to_string())
            } else if current == SCAN_STATE_RUNNING {
                Err("扫描已在运行中".to_string())
            } else {
                Err(format!("扫描不在暂停状态，当前状态: {}", current))
            }
        } else {
            Err(format!("扫描任务不存在: {}", scan_id))
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

        // 扫描完成后不立即移除 task：
        // 1. 用户可能在扫描完成后才选择病毒文件进行处置（DisposeFileRequest）
        // 2. scan_id 需保持可查询状态，便于 Stop/Pause 等操作返回有意义的错误
        // 3. task 清理时机改为 gRPC 连接断开时（由 clear_completed_tasks 负责）
        log_info!("[SCAN] 扫描完成，task 保留供后续处置: scan_id={}", scan_id);
    }

    async fn scan_directory_recursive(
        &self,
        dir_path: &Path,
        excludes: &[String],
        scan_id: &str,
        task: &ScanTask,
        total_scanned: &mut u32,
    ) {
        let entries = match fs::read_dir(dir_path).await {
            Ok(e) => e,
            Err(e) => {
                log_error!("打开目录失败: {} - {}", dir_path.display(), e);
                return;
            }
        };

        let mut all_entries = Vec::new();
        let mut entries = entries;
        while let Some(entry) = entries.next_entry().await.ok().flatten() {
            all_entries.push(entry);
        }

        let semaphore = Arc::clone(&self.scan_semaphore);
        
        let mut handles = Vec::new();
        let mut dirs_to_scan = Vec::new();

        for entry in all_entries {
            // 暂停检查：如果是 PAUSED 状态，在这里挂起等待恢复
            task.wait_if_paused().await;

            let current_state = task.state.load(Ordering::Relaxed);
            if current_state != SCAN_STATE_RUNNING {
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
                    dirs_to_scan.push(entry.path());
                }
                Ok(ft) if ft.is_file() => {
                    let scanner = self.vigilixav_scanner.clone();
                    let scan_id_inner = scan_id.to_string();
                    let file_path_clone = file_path.clone();
                    let semaphore_clone = semaphore.clone();
                    
                    handles.push(tokio::spawn(async move {
                        let _permit = semaphore_clone.acquire().await.unwrap();
                        let scan_start = std::time::Instant::now();
                        
                        if let Some(scanner) = &scanner {
                            match scanner.scan_file(&file_path_clone).await {
                                Ok(ScanResult::Virus { name }) => {
                                    log_info!("[SCAN] {} -> VIRUS ({})", file_path_clone, name);
                                    (ScanAction::Virus(name), file_path_clone, scan_start.elapsed().as_millis() as i64)
                                }
                                Ok(ScanResult::Clean) => {
                                    (ScanAction::Clean, file_path_clone, scan_start.elapsed().as_millis() as i64)
                                }
                                Ok(ScanResult::Error { message }) => {
                                    log_error!("[SCAN] {} -> ERROR: {}", file_path_clone, message);
                                    (ScanAction::Error(message), file_path_clone, scan_start.elapsed().as_millis() as i64)
                                }
                                Err(e) => {
                                    log_error!("[SCAN] {} -> ERROR: {}", file_path_clone, e);
                                    (ScanAction::Error(e), file_path_clone, scan_start.elapsed().as_millis() as i64)
                                }
                            }
                        } else {
                            log_error!("[SCAN] {} -> ERROR: VigilixAV 不可用", file_path_clone);
                            (ScanAction::Error("VigilixAV 不可用".to_string()), file_path_clone, scan_start.elapsed().as_millis() as i64)
                        }
                    }));
                }
                _ => {}
            }
        }

        for handle in handles {
            // 暂停检查：等待已提交的任务结果时也支持暂停
            task.wait_if_paused().await;

            let current_state = task.state.load(Ordering::Relaxed);
            if current_state != SCAN_STATE_RUNNING {
                break;
            }
            
            if let Ok((action, file_path, elapsed)) = handle.await {
                *total_scanned += 1;
                
                match action {
                    ScanAction::Virus(name) => {
                        self.send_virus_alert(scan_id, &file_path, &name, task).await;
                        self.send_file_scan_result(scan_id, &file_path, "VIRUS", Some(&name), None, elapsed, task).await;
                    }
                    ScanAction::Clean => {
                        self.send_file_scan_result(scan_id, &file_path, "OK", None, None, elapsed, task).await;
                    }
                    ScanAction::Error(msg) => {
                        self.send_file_scan_result(scan_id, &file_path, "ERROR", None, Some(&msg), elapsed, task).await;
                    }
                }

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
        }

        for dir_path in dirs_to_scan {
            // 暂停检查
            task.wait_if_paused().await;

            let current_state = task.state.load(Ordering::Relaxed);
            if current_state != SCAN_STATE_RUNNING {
                break;
            }
            Box::pin(self.scan_directory_recursive(&dir_path, excludes, scan_id, task, total_scanned)).await;
        }
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
            md5: "".to_string(),
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

        //log_info!("[gRPC] 上报文件结果: {} -> {} ({}ms)", file_path, status, scan_time_ms);
    }
}

impl Clone for ScanTaskManager {
    fn clone(&self) -> Self {
        Self {
            tasks: Arc::clone(&self.tasks),
            net_client: Arc::clone(&self.net_client),
            server_b_url: self.server_b_url.clone(),
            vigilixav_scanner: self.vigilixav_scanner.as_ref().map(|s| Arc::clone(s)),
            virus_tx: self.virus_tx.clone(),
            virus_rx: Arc::clone(&self.virus_rx),
            boot_manager: self.boot_manager.clone(),
            scan_semaphore: Arc::new(Semaphore::new(10)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use std::sync::atomic::Ordering;

    fn make_test_task() -> ScanTask {
        let (tx, _rx) = mpsc::channel(16);
        ScanTask::new(
            "test-scan-001".to_string(),
            "/tmp".to_string(),
            vec![],
            tx,
        )
    }

    #[tokio::test]
    async fn test_pause_and_resume_state_transitions() {
        let task = make_test_task();

        // 初始状态 IDLE
        assert_eq!(task.state.load(Ordering::Relaxed), SCAN_STATE_IDLE);

        // start -> RUNNING
        task.start();
        assert_eq!(task.state.load(Ordering::Relaxed), SCAN_STATE_RUNNING);
        assert!(task.is_running());
        assert!(!task.is_paused());

        // pause -> PAUSED
        task.pause();
        assert_eq!(task.state.load(Ordering::Relaxed), SCAN_STATE_PAUSED);
        assert!(!task.is_running());
        assert!(task.is_paused());

        // resume -> RUNNING
        task.resume();
        assert_eq!(task.state.load(Ordering::Relaxed), SCAN_STATE_RUNNING);
        assert!(task.is_running());
        assert!(!task.is_paused());
    }

    #[tokio::test]
    async fn test_pause_only_works_in_running_state() {
        let task = make_test_task();

        // 在 IDLE 状态 pause 不应该变化
        task.pause();
        assert_eq!(task.state.load(Ordering::Relaxed), SCAN_STATE_IDLE);

        // 在 STOPPED 状态 pause 不应该变化
        task.start();
        task.stop();
        task.pause();
        assert_eq!(task.state.load(Ordering::Relaxed), SCAN_STATE_STOPPED);
    }

    #[tokio::test]
    async fn test_resume_only_works_in_paused_state() {
        let task = make_test_task();

        // 在 RUNNING 状态 resume 不应该变化
        task.start();
        task.resume();
        assert_eq!(task.state.load(Ordering::Relaxed), SCAN_STATE_RUNNING);
    }

    #[tokio::test]
    async fn test_stop_wakes_paused_task() {
        let task = make_test_task();
        task.start();
        task.pause();

        let task_clone = task.clone();

        // 在另一个任务中等待恢复
        let handle = tokio::spawn(async move {
            task_clone.wait_if_paused().await;
            task_clone.state.load(Ordering::Relaxed)
        });

        // 给一点时间确保 spawn 的任务已经开始等待
        tokio::time::sleep(Duration::from_millis(50)).await;

        // stop 应该唤醒暂停中的任务
        task.stop();

        let final_state = handle.await.unwrap();
        assert_eq!(final_state, SCAN_STATE_STOPPED);
    }

    #[tokio::test]
    async fn test_wait_if_paused_returns_immediately_when_running() {
        let task = make_test_task();
        task.start();

        // 不应该阻塞
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            task.wait_if_paused()
        ).await;
        assert!(result.is_ok(), "wait_if_paused should return immediately when RUNNING");
    }
}
