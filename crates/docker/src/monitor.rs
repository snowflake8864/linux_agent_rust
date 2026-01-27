// crates/docker/src/monitor.rs
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;
use common::manager::boot::BootManager;
use logging::{log_debug, log_error, log_info};
use once_cell::sync::Lazy;
use tokio::sync::Mutex; 
use tokio::time::interval;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicI32, Ordering};

use tokio::io::AsyncBufReadExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DockerShimProcess {
    pid: i32,
    kind: u8,
}

#[derive(Debug, Clone, Copy)]
enum DockerEventAction {
    Add,
    Remove,
}

impl DockerEventAction {
    fn as_flag(self) -> u8 {
        match self {
            Self::Add => 1,
            Self::Remove => 0,
        }
    }
}

static LAST_PROCESSES: Lazy<Arc<Mutex<Vec<DockerShimProcess>>>> =
    Lazy::new(|| Arc::new(Mutex::new(Vec::new())));

static DETECTED_COMMAND: Lazy<Arc<Mutex<Option<(String, usize)>>>> =
    Lazy::new(|| Arc::new(Mutex::new(None)));
static LAST_ROOT_PID: Lazy<Arc<AtomicI32>> = Lazy::new(|| Arc::new(AtomicI32::new(0)));

static IS_VERSION_2: Lazy<Arc<Mutex<bool>>> = Lazy::new(|| Arc::new(Mutex::new(false)));

static DOCKER_VERSION: Lazy<Arc<Mutex<u8>>> = Lazy::new(|| Arc::new(Mutex::new(0)));

const PROC_OSEC_DOCKER_RT: &str = "/proc/osec/docker_rt";

const DETECTION_COMMANDS: &[&str] = &[
    // v1: docker-containerd-shim-current
    "ps -e -o pid,ppid,cmd | grep 'docker-containerd-shim-current' | grep -v grep | awk '{print $1,$2}'",
    // v2: containerd-shim with namespace
    "ps -e -o pid,ppid,cmd | grep 'containerd-shim' | grep 'namespace' | grep -v grep | awk '{print $1,$2}'",
    // podman: conmon
    "ps -e -o pid,ppid,cmd | grep -E '[c]onmon' | grep -- '--api-version' | grep -v grep | awk '{print $1,$2}'",
];

/// 执行 shell 命令并返回 (pid, ppid) 列表
async fn exec_shell(command: &str) -> Result<Vec<(i32, i32)>, String> {
    let output = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .await
        .map_err(|e| format!("Command failed: '{}': {}", command, e))?;

    if !output.status.success() {
        return Err(format!(
            "Command '{}' failed with status {}: {}",
            command,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut results = Vec::new();

    for line in stdout.lines() {
        let parts = line.trim().split_whitespace().collect::<Vec<_>>();
        if parts.len() < 2 {
            continue;
        }
        match (parts[0].parse(), parts[1].parse()) {
            (Ok(pid), Ok(ppid)) => results.push((pid, ppid)),
            _ => log_debug!("Failed to parse PID/PPID from line: {}", line),
        }
    }

    Ok(results)
}

async fn detect_valid_command() -> Result<(String, usize), String> {
    for (i, &cmd) in DETECTION_COMMANDS.iter().enumerate() {
        match exec_shell(cmd).await {
            Ok(entries) if !entries.is_empty() => {
                log_info!("Detected valid command [{}]: {}", i, cmd);
                return Ok((cmd.to_string(), i));
            }
            Ok(_) => {/*log_debug!("Command [{}] returned no output: {}", i, cmd);*/},
            Err(e) => log_debug!("Command [{}] failed: {}", i, e),
        }
    }
    Err("No valid container runtime shim command detected".into())
}

/// 解析当前所有 shim 进程
async fn scan_docker_processes() -> Result<Vec<DockerShimProcess>, String> {
    let mut detected = DETECTED_COMMAND.lock().await; 
    let (command, index) = if let Some(cmd) = &*detected {
        cmd.clone()
    } else {
        let cmd = detect_valid_command().await?;
        *detected = Some(cmd.clone());
        cmd
    };

    let entries = exec_shell(&command).await?;
    if entries.is_empty() {
        return Ok(Vec::new());
    }

    let ppids = entries.iter().map(|(_, ppid)| *ppid).collect::<Vec<_>>();
    let all_ppid_equal = ppids.windows(2).all(|w| w[0] == w[1]);

    let mut processes = Vec::new();

    if all_ppid_equal {
        match index {
            0 => {
                // v1: 使用 PPID
                let parent_pid = ppids[0];
                if parent_pid > 10 {
                    processes.push(DockerShimProcess {
                        pid: parent_pid,
                        kind: 1,
                    });
                }
            }
            1 | 2 => {
                // v2: 每个 shim 是一个容器
                for (pid, _) in &entries {
                    processes.push(DockerShimProcess {
                        pid: *pid,
                        kind: 2,
                    });
                }
            }
            _ => {}
        }
    }

    if let Ok(mut version) = DOCKER_VERSION.try_lock() {
        if let Some(p) = processes.first() {
            *version = p.kind;
        }
    }

    // 标记 v2
    if processes.iter().any(|p| p.kind == 2) {
        if let Ok(mut is_v2) = IS_VERSION_2.try_lock() {
            *is_v2 = true;
        }
    }

    Ok(processes)
}

/// 向 /proc/osec/docker_rt 写入事件
/// 格式："{kind},{flag},{pid}\n"
/// 特殊情况：kind=4, flag=0, pid=0 → "4,0,0\n" 表示清空所有
fn emit_event(kind: u8, action: DockerEventAction, pid: i32) {
    let line = match (kind, action, pid) {
        (4, DockerEventAction::Remove, 0) => "4,0,0\n".to_string(),
        _ => {
            let flag = action.as_flag();
            format!("{},{},{}\n", kind, flag, pid)
        }
    };
    log_debug!("Emitting: {}", line.trim());
    match OpenOptions::new().write(true).open(PROC_OSEC_DOCKER_RT) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(line.as_bytes()) {
                log_error!("Failed to write to {}: {}: {}", PROC_OSEC_DOCKER_RT, line.trim(), e);
            } else {
                log_info!("Emitted: {}", line.trim());
            }
        }
        Err(e) => {
            log_error!("Cannot open {} for writing: {}", PROC_OSEC_DOCKER_RT, e);
        }
    }
}

fn clear_docker_rt() {
    let line = "c\n".to_string();
    match OpenOptions::new().write(true).open(PROC_OSEC_DOCKER_RT) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(line.as_bytes()) {
                log_error!("Failed to write to {}: {}: {}", PROC_OSEC_DOCKER_RT, line.trim(), e);
            } else {
                log_info!("Emitted: {}", line.trim());
            }
        }
        Err(e) => {
            log_error!("Cannot open {} for writing: {}", PROC_OSEC_DOCKER_RT, e);
        }
    }
}

async fn check_residual_pids(current_pids: &HashSet<i32>) {
    let file = match tokio::fs::OpenOptions::new()
        .read(true)
        .open(PROC_OSEC_DOCKER_RT)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            log_debug!("Failed to read {}: {}", PROC_OSEC_DOCKER_RT, e);
            return;
        }
    };

    let reader = tokio::io::BufReader::new(file);
    let mut lines = reader.lines(); 

    let mut proc_pids = Vec::new();
    let mut in_data_section = false;

    while let Some(line) = lines.next_line().await.unwrap_or_default() {
        if !in_data_section {
            if line.contains("Docker Container PID:") {
                in_data_section = true;
            }
        } else if let Some(c) = line.chars().next() {
            if c.is_ascii_digit() {
                if let Ok(pid) = line.trim().parse::<i32>() {
                    proc_pids.push(pid);
                }
            }
        }
    }

    if proc_pids.len() > current_pids.len() + 2 {
        for pid in proc_pids {
            if !current_pids.contains(&pid) {
                emit_event(2, DockerEventAction::Remove, pid);
            }
        }
    }
}

async fn update_docker_state() {
    match scan_docker_processes().await {
        Ok(current) => {

            let current_set: HashSet<_> = current.iter().collect();
            let current_pids: HashSet<i32> = current.iter().map(|p| p.pid).collect();

            let mut last = LAST_PROCESSES.lock().await;

            if current.is_empty() {
                if !last.is_empty() {
                    emit_event(4, DockerEventAction::Remove, 0);
                    log_info!("All Docker containers stopped. Sent global clear.");
                    clear_docker_rt();
                    last.clear();
                }
                return;
            }

            if last.is_empty() {
                log_info!("First detection: {} container(s) found.", current.len());
                for p in &current {
                    emit_event(p.kind, DockerEventAction::Add, p.pid);
                }
                *last = current; 
                return;
            }

            let last_set: HashSet<_> = last.iter().collect();
            let mut has_change = false;

            for p in &current {
                if !last_set.contains(p) {
                    log_info!("New container detected: {}", p.pid);
                    emit_event(p.kind, DockerEventAction::Add, p.pid);
                    has_change = true;
                }
            }

            for p in &*last {
                if !current_set.contains(p) {
                    emit_event(p.kind, DockerEventAction::Remove, p.pid);
                    has_change = true;
                }
            }

            if has_change || current.len() != last.len() {
                *last = current;
            }

            if *IS_VERSION_2.lock().await {
                drop(last); 
                check_residual_pids(&current_pids).await;
            }
        }
        Err(e) => {
            //log_error!("Failed to scan container processes: {}", e);
        }
    }
}
/// 清空所有容器 PID 状态
async fn clear_container_pid() {
    emit_event(4, DockerEventAction::Remove, 0);
    clear_docker_rt();
    log_info!("Cleared all container PIDs");
}
async fn set_container_root_pid() {
    const COMMAND: &str = "ps -e -o pid,cmd | grep '/containerd$' | grep -v grep | awk '{print $1}'";
    let output = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(COMMAND)
        .output()
        .await;

    let pid_str = match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout.lines().next().map(|s| s.trim().to_string())
        }
        _ => None,
    };

    let pid: i32 = match pid_str.and_then(|s| s.parse::<i32>().ok()) {
        Some(pid) if pid > 0 => pid,
        _ => {
            // 没找到 containerd 进程
            let last = LAST_ROOT_PID.load(Ordering::SeqCst);
            if last != 0 {
                emit_event(3, DockerEventAction::Remove, 0); // 3,0,0
                log_info!("containerd not running. Sent 3,0,0");
                LAST_ROOT_PID.store(0, Ordering::SeqCst);
            }
            return;
        }
    };

    let last = LAST_ROOT_PID.load(Ordering::SeqCst);
    if pid != last {
        emit_event(3, DockerEventAction::Add, pid); // 3,1,pid
        log_info!("Container root PID: {}", pid);
        LAST_ROOT_PID.store(pid, Ordering::SeqCst);
    }
}
async fn reset_container_root_pid(pid: i32) -> Result<(), String> {
    if pid <= 0 {
        return Err("Invalid PID".into());
    }

    // 上报 3,1,pid
    emit_event(3, DockerEventAction::Add, pid);
    log_info!("Container root PID reset: {}", pid);
    LAST_ROOT_PID.store(pid, Ordering::SeqCst);

    // 根据版本决定后续行为
    let version = DOCKER_VERSION.lock().await;
    if *version == 1 {
        // v1：清空所有容器 PID
        emit_event(4, DockerEventAction::Remove, 0); // 4,0,0
        clear_docker_rt(); // 写 "c\n"
    } else {
        // v2：重新扫描 shim
        update_docker_state().await;
    }

    Ok(())
}

async fn run_monitor_loop(start_delay_handle: Arc<Mutex<u32>>) {
    log_info!("Starting Docker monitor service...");

    let mut interval = interval(tokio::time::Duration::from_secs(8));

    // 首次调用 set_container_root_pid
    set_container_root_pid().await;

    use std::sync::atomic::{AtomicU32, Ordering};
    static TIMER_COUNT: AtomicU32 = AtomicU32::new(0);

    loop {
        interval.tick().await;
        /*
           let should_force_update = {
           let mut guard = start_delay_handle.lock().await;
           if *guard > 0 {
           let val = *guard;
         *guard = val - 1;
         true
         } else {
         false
         }
         }; 

         if should_force_update {
         update_docker_state().await;
         log_info!("0 Docker monitor service started successfully");
         continue;
         }
         let count = TIMER_COUNT.fetch_add(1, Ordering::Relaxed);
         if count % 4 == 0 {
         update_docker_state().await;
         log_info!("1 Docker monitor service started successfully");
         }
         */
        update_docker_state().await;
    }
}

/// 启动 Docker 监控服务
pub trait StartDockerMonitor {
    fn start_docker_monitor_services(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>;
}

impl StartDockerMonitor for BootManager {
    fn start_docker_monitor_services(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {
            let start_delay_handle = Arc::new(Mutex::new(5));
            tokio::spawn(async move {
                run_monitor_loop(start_delay_handle).await;
            });

            Ok("Docker monitor service started successfully".to_string())
        })
    }
}




#[repr(C, packed)]
struct ComInfo {
    pid: u32,
    ppid: u32,
    flags: u32, // bitfield: type:3, version:3
}

impl ComInfo {
    fn type_(&self) -> u8 {
        (self.flags & 0x07) as u8
    }
}

#[derive(Clone)]
pub struct KernelDockerHandler {
    start_delay: Arc<Mutex<u32>>,
}

impl KernelDockerHandler {
    pub fn new(start_delay: u32) -> Self {
        KernelDockerHandler {
            start_delay: Arc::new(Mutex::new(start_delay)),
        }
    }

    /// 获取对 start_delay 的引用，供 monitor loop 使用
    pub fn get_start_delay_handle(&self) -> Arc<Mutex<u32>> {
        self.start_delay.clone()
    }

    pub async fn handle_kernel_docker_oper(
        &self,
        data: &[u8],
        data_len: u32,
    ) -> Result<(), String> {
        let expected_size = std::mem::size_of::<ComInfo>();
        if data.len() < expected_size || data_len < expected_size as u32 {
            log_error!("Invalid data length: {} (expected >= {})", data.len(), expected_size);
            return Err("Invalid length".into());
        }

        // 安全转换：bytes -> ComInfo
        let com_info: ComInfo = unsafe {
            std::ptr::read_unaligned(data.as_ptr() as *const ComInfo)
        };

        let pid = com_info.pid;
        let ppid = com_info.ppid;
        let type_ = com_info.type_();
/*
        log_info!(
            "Received kernel com_info: pid={}, ppid={}, type={}",
            pid,
            ppid,
            type_
        );
*/
        match type_ {
            3 => {
                log_info!("Kernel requests reset container root PID = {}", pid);
                if let Err(e) = reset_container_root_pid(pid as i32).await {
                    log_error!("Failed to reset container root PID: {}", e);
                }
            }
            1 => {
                log_info!("Kernel triggers immediate docker scan (type=1)");
                //let mut delay = self.start_delay.lock().await;
                //*delay = 1; 
                update_docker_state().await;
            }
            _ => {
                log_info!("Unknown com_info type {}, ignored", type_);
            }
        }

        Ok(())
    }
}


