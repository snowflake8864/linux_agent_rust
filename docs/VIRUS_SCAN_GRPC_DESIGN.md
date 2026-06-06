# 病毒扫描gRPC服务设计方案

## 1. 架构概述

```
┌─────────────────────────────────────────────────────────────────┐
│                         终端A (客户端)                           │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │ gRPC双向流 (长连接)                                        │ │
│  │ - 发送: ScanCommand (启动/停止/查询)                       │ │
│  │ - 接收: ScanEvent (进度/病毒/完成)                         │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Agent (本项目)                           │
│  ┌───────────────────┐         ┌─────────────────────────────┐  │
│  │  gRPC服务端        │         │  扫描任务管理器              │  │
│  │  - 监听终端命令    │  ◄───►  │  - 异步执行扫描             │  │
│  │  - 流式上报事件    │         │  - 管理任务状态              │  │
│  └───────────────────┘         └─────────────────────────────┘  │
│                                      │                            │
│  ┌───────────────────┐              ▼                            │
│  │  HTTP客户端        │    ┌─────────────────────────────┐      │
│  │  - POST MD5到B    │    │  文件遍历 + MD5计算          │      │
│  │  - 接收病毒结果    │    │  (复用get_md5_global)       │      │
│  └───────────────────┘    └─────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       服务器B (病毒库)                            │
│  - 接收: 批量MD5 + 文件路径                                       │
│  - 返回: 病毒检测结果                                             │
└─────────────────────────────────────────────────────────────────┘
```

## 2. 新增文件结构

```
crates/
  virus_scan_grpc/                      # 新建gRPC服务
    Cargo.toml
    src/
      lib.rs
      proto/
        virus_scan.proto                # protobuf定义
      service.rs                        # gRPC服务实现
      scanner.rs                        # 扫描逻辑
      task_mgr.rs                       # 任务管理器
      types.rs                          # 共用类型

docs/
  VIRUS_SCAN_GRPC_DESIGN.md             # 本设计文档
```

## 3. Protocol Buffer定义

### 3.1 文件: crates/virus_scan_grpc/src/proto/virus_scan.proto

```protobuf
syntax = "proto3";

package virus_scan;

// 双向流服务：终端A <-> Agent
service VirusScanService {
  // 终端A发送命令，Agent上报扫描事件
  // 使用双向流实现异步通信
  rpc Scan(stream ScanCommand) returns (stream ScanEvent);
}

// 终端A发送的命令
message ScanCommand {
  string scan_id = 1;   // 扫描任务ID，由终端A生成

  oneof cmd {
    StartScanCmd start_scan = 2;
    StopScanCmd stop_scan = 3;
    GetStatusCmd get_status = 4;
  }
}

// 启动扫描命令
message StartScanCmd {
  string target = 1;              // 扫描目标: 目录路径 或 "FULL_DISK"(全盘)
  repeated string exclude = 2;    // 排除的目录列表
  bool include_script = 3;        // 是否包含脚本文件(默认true)
}

// 停止扫描命令
message StopScanCmd {
  string reason = 1;              // 停止原因
}

// 查询状态命令
message GetStatusCmd {
  // 空消息
}

// Agent上报的扫描事件
message ScanEvent {
  string scan_id = 1;   // 对应的扫描任务ID

  oneof event {
    ScanStarted scan_started = 2;       // 扫描开始
    ScanProgress progress = 3;          // 扫描进度
    FileResult file_result = 4;         // 单文件扫描结果
    VirusFound virus_found = 5;         // 发现病毒
    ScanCompleted completed = 6;        // 扫描完成
    ScanError error = 7;                // 错误
  }
}

// 扫描开始事件
message ScanStarted {
  int32 total_files = 1;                // 预计扫描文件总数
  string message = 2;                   // 附加信息
}

// 扫描进度事件 (可选，用于进度条显示)
message ScanProgress {
  int32 scanned = 1;                    // 已扫描文件数
  int32 total = 2;                      // 预计总数
  int32 viruses_found = 3;              // 已发现病毒数
}

// 单文件扫描结果 (非病毒文件)
message FileResult {
  string file_path = 1;                 // 文件全路径
  string md5 = 2;                       // 文件MD5
  string status = 3;                    // 状态: "CLEAN"
  int64 scan_time_ms = 4;               // 扫描耗时(毫秒)
}

// 发现病毒事件
message VirusFound {
  string file_path = 1;                 // 病毒文件全路径
  string md5 = 2;                       // 文件MD5
  string virus_name = 3;                // 病毒名称
  string threat_level = 4;              // 威胁等级: LOW/MEDIUM/HIGH/CRITICAL
  string description = 5;               // 病毒描述
}

// 扫描完成事件
message ScanCompleted {
  int32 total_scanned = 1;              // 总扫描文件数
  int32 viruses_found = 2;              // 发现病毒数
  int64 duration_ms = 3;                // 总耗时(毫秒)
  string result_summary = 4;            // 结果摘要
}

// 扫描错误事件
message ScanError {
  string error = 1;                     // 错误描述
  string error_code = 2;                // 错误码
}

// 服务器B返回的病毒检测结果 (内部使用)
message ServerBResponse {
  repeated VirusCheckResult results = 1;
}

message VirusCheckResult {
  string file_path = 1;
  string md5 = 2;
  bool is_virus = 3;
  string virus_name = 4;
  string threat_level = 5;
}
```

## 4. Cargo.toml依赖

### 4.1 文件: crates/virus_scan_grpc/Cargo.toml

```toml
[package]
name = "virus_scan_grpc"
version = "0.1.0"
edition = "2021"

[dependencies]
# gRPC
tonic = "0.12"
prost = "0.13"
tokio = { version = "1", features = ["full"] }
tokio-stream = "0.1"
futures = "0.3"

# 序列化
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# 项目内部
net_client = { path = "../net_client" }
process_mgr = { path = "../process_mgr" }
common = { path = "../common" }
logging = { path = "../logging" }
config = { path = "../config" }

# 工具
uuid = { version = "1" }
chrono = { version = "0.4" }
```

### 4.2 主项目添加依赖: crates/main/Cargo.toml

```toml
# 在 [dependencies] 中添加
virus_scan_grpc = { path = "../virus_scan_grpc" }
```

## 5. 核心实现

### 5.1 文件: crates/virus_scan_grpc/src/types.rs

```rust
use serde::Serialize;
use std::sync::atomic::{AtomicU8, Ordering};

pub const SCAN_STATE_RUNNING: u8 = 1;
pub const SCAN_STATE_STOPPED: u8 = 2;
pub const SCAN_STATE_COMPLETED: u8 = 3;

#[derive(Clone, Debug)]
pub struct ScanTask {
    pub scan_id: String,
    pub target: String,
    pub exclude: Vec<String>,
    pub include_script: bool,
    pub state: Arc<AtomicU8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl ScanTask {
    pub fn new(scan_id: String, target: String) -> Self {
        Self {
            scan_id,
            target,
            exclude: Vec::new(),
            include_script: true,
            state: Arc::new(AtomicU8::new(SCAN_STATE_RUNNING)),
            created_at: chrono::Utc::now(),
        }
    }

    pub fn is_running(&self) -> bool {
        self.state.load(Ordering::Relaxed) == SCAN_STATE_RUNNING
    }

    pub fn stop(&self) {
        self.state.store(SCAN_STATE_STOPPED, Ordering::Relaxed);
    }

    pub fn complete(&self) {
        self.state.store(SCAN_STATE_COMPLETED, Ordering::Relaxed);
    }
}

#[derive(Serialize)]
pub struct Md5BatchItem {
    pub file_path: String,
    pub md5: String,
}

#[derive(Serialize)]
pub struct Md5BatchRequest {
    pub scan_id: String,
    pub items: Vec<Md5BatchItem>,
}
```

### 5.2 文件: crates/virus_scan_grpc/src/scanner.rs

```rust
use crate::types::{Md5BatchItem, Md5BatchRequest};
use common::manager::boot::BootManager;
use futures::stream::{self, StreamExt};
use logging::{log_error, log_info};
use net_client::core::NetClient;
use process_mgr::get_md5_global;
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

const BATCH_SIZE: usize = 100;
const HTTP_TIMEOUT_SECS: u64 = 30;

pub struct VirusScanner {
    net_client: NetClient,
    server_b_url: String,
}

impl VirusScanner {
    pub fn new(net_client: NetClient, server_b_url: String) -> Self {
        Self {
            net_client,
            server_b_url,
        }
    }

    /// 扫描单个目录（非递归）
    pub async fn scan_directory(
        &self,
        dir: &str,
        exclude: &[String],
        include_script: bool,
        tx: mpsc::Sender<ScanFileEvent>,
    ) -> Result<(), String> {
        let path = Path::new(dir);
        if !path.exists() || !path.is_dir() {
            return Err(format!("目录不存在或无权限: {}", dir));
        }

        let mut entries = fs::read_dir(path)
            .await
            .map_err(|e| format!("打开目录失败 {}: {}", dir, e))?;

        let mut batch: Vec<Md5BatchItem> = Vec::new();
        let mut total_scanned = 0;
        let mut viruses_found = 0;

        while let Some(entry) = entries.next_entry().await.ok().flatten() {
            let file_path = entry.path().to_string_lossy().to_string();

            // 跳过.和..
            if file_path.ends_with("/.") || file_path.ends_with("/..") {
                continue;
            }

            // 检查排除目录
            if self.should_exclude(&file_path, exclude) {
                continue;
            }

            // 跳过目录
            if entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }

            // 计算MD5
            let md5 = match get_md5_global(&file_path) {
                Ok(m) => m,
                Err(e) => {
                    log_error!("计算MD5失败 {}: {}", file_path, e);
                    continue;
                }
            };

            batch.push(Md5BatchItem {
                file_path: file_path.clone(),
                md5,
            });

            // 批量上报服务器B
            if batch.len() >= BATCH_SIZE {
                let viruses = self.check_with_server_b(&batch).await?;
                viruses_found += viruses.len();

                // 上报结果给调用方
                for item in &batch {
                    let is_virus = viruses.iter().any(|v| v.file_path == item.file_path);
                    let event = if is_virus {
                        let virus = viruses.iter().find(|v| v.file_path == item.file_path).unwrap();
                        ScanFileEvent::VirusFound(VirusFoundEvent {
                            file_path: item.file_path.clone(),
                            md5: item.md5.clone(),
                            virus_name: virus.virus_name.clone(),
                            threat_level: virus.threat_level.clone(),
                        })
                    } else {
                        ScanFileEvent::Clean(FileCleanEvent {
                            file_path: item.file_path.clone(),
                            md5: item.md5.clone(),
                        })
                    };
                    let _ = tx.send(event).await;
                }

                total_scanned += batch.len();
                batch.clear();
            }
        }

        // 处理剩余文件
        if !batch.is_empty() {
            let viruses = self.check_with_server_b(&batch).await?;
            viruses_found += viruses.len();

            for item in &batch {
                let is_virus = viruses.iter().any(|v| v.file_path == item.file_path);
                let event = if is_virus {
                    let virus = viruses.iter().find(|v| v.file_path == item.file_path).unwrap();
                    ScanFileEvent::VirusFound(VirusFoundEvent {
                        file_path: item.file_path.clone(),
                        md5: item.md5.clone(),
                        virus_name: virus.virus_name.clone(),
                        threat_level: virus.threat_level.clone(),
                    })
                } else {
                    ScanFileEvent::Clean(FileCleanEvent {
                        file_path: item.file_path.clone(),
                        md5: item.md5.clone(),
                    })
                };
                let _ = tx.send(event).await;
            }
            total_scanned += batch.len();
        }

        Ok(())
    }

    fn should_exclude(&self, path: &str, exclude: &[String]) -> bool {
        for ex in exclude {
            if path.starts_with(ex) {
                return true;
            }
        }
        false
    }

    /// 上报MD5到服务器B，接收病毒检测结果
    async fn check_with_server_b(
        &self,
        batch: &[Md5BatchItem],
    ) -> Result<Vec<VirusCheckResult>, String> {
        let request = Md5BatchRequest {
            scan_id: "current".to_string(), // TODO: 传入scan_id
            items: batch.to_vec(),
        };

        let json = serde_json::to_string(&request)
            .map_err(|e| format!("序列化失败: {}", e))?;

        let url = format!("{}/v1/scan/batch", self.server_b_url);
        log_info!("上报MD5到B: {} 个文件", batch.len());

        match timeout(
            Duration::from_secs(HTTP_TIMEOUT_SECS),
            self.net_client.post_data_async(&url, &json, Duration::from_secs(HTTP_TIMEOUT_SECS), None),
        ).await {
            Ok(Ok(response)) => {
                // 解析B服务器返回的结果
                self.parse_server_response(&response)
            }
            Ok(Err(e)) => Err(format!("HTTP请求失败: {}", e)),
            Err(_) => Err("HTTP请求超时".to_string()),
        }
    }

    fn parse_server_response(&self, response: &str) -> Result<Vec<VirusCheckResult>, String> {
        // TODO: 根据服务器B的实际返回格式实现
        // 这里假设返回格式为:
        // {"results":[{"file_path":"/bin/ls","md5":"xxx","is_virus":true,"virus_name":"Trojan","threat_level":"HIGH"}]}
        let parsed: serde_json::Value = serde_json::from_str(response)
            .map_err(|e| format!("解析响应失败: {}", e))?;

        let mut results = Vec::new();
        if let Some(items) = parsed["results"].as_array() {
            for item in items {
                if item["is_virus"].as_bool().unwrap_or(false) {
                    results.push(VirusCheckResult {
                        file_path: item["file_path"].as_str().unwrap_or("").to_string(),
                        md5: item["md5"].as_str().unwrap_or("").to_string(),
                        virus_name: item["virus_name"].as_str().unwrap_or("").to_string(),
                        threat_level: item["threat_level"].as_str().unwrap_or("").to_string(),
                    });
                }
            }
        }
        Ok(results)
    }
}

// 扫描文件事件（用于内部传递）
pub enum ScanFileEvent {
    Clean(FileCleanEvent),
    VirusFound(VirusFoundEvent),
}

pub struct FileCleanEvent {
    pub file_path: String,
    pub md5: String,
}

pub struct VirusFoundEvent {
    pub file_path: String,
    pub md5: String,
    pub virus_name: String,
    pub threat_level: String,
}

pub struct VirusCheckResult {
    pub file_path: String,
    pub md5: String,
    pub virus_name: String,
    pub threat_level: String,
}
```

### 5.3 文件: crates/virus_scan_grpc/src/task_mgr.rs

```rust
use crate::scanner::{ScanFileEvent, VirusScanner};
use crate::types::{ScanTask, SCAN_STATE_RUNNING, SCAN_STATE_STOPPED};
use common::manager::boot::BootManager;
use config::net_info::NETINFO_CONFIG;
use logging::log_info;
use net_client::core::NetClient;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Duration};

pub struct ScanTaskMgr {
    tasks: Arc<Mutex<HashMap<String, ScanTask>>>,
    net_client: NetClient,
    server_b_url: String,
}

impl ScanTaskMgr {
    pub fn new(net_client: NetClient) -> Self {
        let cfg = NETINFO_CONFIG.lock().unwrap();
        let server_b_url = cfg.server_ip_port.clone();
        drop(cfg);

        Self {
            tasks: Arc::new(Mutex::new(HashMap::new())),
            net_client,
            server_b_url,
        }
    }

    pub async fn create_task(&self, scan_id: &str, target: String) -> ScanTask {
        let task = ScanTask::new(scan_id.to_string(), target);
        let mut tasks = self.tasks.lock().await;
        tasks.insert(scan_id.to_string(), task.clone());
        task
    }

    pub async fn get_task(&self, scan_id: &str) -> Option<ScanTask> {
        let tasks = self.tasks.lock().await;
        tasks.get(scan_id).cloned()
    }

    pub async fn stop_task(&self, scan_id: &str) {
        let tasks = self.tasks.lock().await;
        if let Some(task) = tasks.get(scan_id) {
            task.stop();
        }
    }

    pub async fn remove_task(&self, scan_id: &str) {
        let mut tasks = self.tasks.lock().await;
        tasks.remove(scan_id);
    }

    /// 异步执行扫描任务
    pub async fn run_scan(
        &self,
        scan_id: &str,
        target: &str,
        exclude: Vec<String>,
        event_tx: mpsc::Sender<super::proto::ScanEvent>,
    ) {
        let task = match self.get_task(scan_id).await {
            Some(t) => t,
            None => {
                log_error!("任务不存在: {}", scan_id);
                return;
            }
        };

        let scanner = VirusScanner::new(self.net_client.clone(), self.server_b_url.clone());
        let (file_tx, mut file_rx) = mpsc::channel(256);

        // 启动扫描协程
        tokio::spawn({
            let scanner = scanner.clone();
            let exclude = exclude.clone();
            async move {
                if let Err(e) = scanner.scan_directory(target, &exclude, true, file_tx).await {
                    log_error!("扫描失败: {}", e);
                }
            }
        });

        // 接收文件扫描结果并上报给终端A
        let mut total_scanned = 0;
        let mut viruses_found = 0;
        let start_time = std::time::Instant::now();

        while let Some(event) = file_rx.recv().await {
            if !task.is_running() {
                log_info!("扫描已停止: {}", scan_id);
                break;
            }

            match event {
                ScanFileEvent::Clean(e) => {
                    total_scanned += 1;
                    let scan_event = super::proto::ScanEvent {
                        scan_id: scan_id.to_string(),
                        event: Some(super::proto::scan_event::Event::FileResult(
                            super::proto::FileResult {
                                file_path: e.file_path,
                                md5: e.md5,
                                status: "CLEAN".to_string(),
                                scan_time_ms: 0,
                            },
                        )),
                    };
                    let _ = event_tx.send(Ok(scan_event)).await;
                }
                ScanFileEvent::VirusFound(e) => {
                    total_scanned += 1;
                    viruses_found += 1;
                    let scan_event = super::proto::ScanEvent {
                        scan_id: scan_id.to_string(),
                        event: Some(super::proto::scan_event::Event::VirusFound(
                            super::proto::VirusFound {
                                file_path: e.file_path,
                                md5: e.md5,
                                virus_name: e.virus_name,
                                threat_level: e.threat_level,
                                description: "".to_string(),
                            },
                        )),
                    };
                    let _ = event_tx.send(Ok(scan_event)).await;
                }
            }

            // 每100个文件上报一次进度
            if total_scanned % 100 == 0 {
                let progress_event = super::proto::ScanEvent {
                    scan_id: scan_id.to_string(),
                    event: Some(super::proto::scan_event::Event::ScanProgress(
                        super::proto::ScanProgress {
                            scanned: total_scanned as i32,
                            total: 0, // 未知总数
                            viruses_found: viruses_found as i32,
                        },
                    )),
                };
                let _ = event_tx.send(Ok(progress_event)).await;
            }
        }

        // 发送完成事件
        let completed_event = super::proto::ScanEvent {
            scan_id: scan_id.to_string(),
            event: Some(super::proto::scan_event::Event::ScanCompleted(
                super::proto::ScanCompleted {
                    total_scanned: total_scanned as i32,
                    viruses_found: viruses_found as i32,
                    duration_ms: start_time.elapsed().as_millis() as i64,
                    result_summary: format!("扫描完成，发现 {} 个病毒", viruses_found),
                },
            )),
        };
        let _ = event_tx.send(Ok(completed_event)).await;

        // 清理任务
        self.remove_task(scan_id).await;
    }
}
```

### 5.4 文件: crates/virus_scan_grpc/src/service.rs

```rust
use crate::task_mgr::ScanTaskMgr;
use crate::types::ScanTask;
use crate::{proto, ScanEvent};
use common::manager::boot::BootManager;
use futures::stream::{self, Stream, StreamExt};
use logging::log_info;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tonic::{Request, Response, Status, Streaming};

pub struct VirusScanGrpcService {
    task_mgr: Arc<ScanTaskMgr>,
}

impl VirusScanGrpcService {
    pub fn new(task_mgr: Arc<ScanTaskMgr>) -> Self {
        Self { task_mgr }
    }

    /// gRPC双向流处理
    /// 终端A发送命令，Agent上报事件
    pub async fn handle_scan_stream(
        &self,
        request: Request<Streaming<proto::ScanCommand>>,
    ) -> Result<Response<Stream<dyn Stream<Item = Result<proto::ScanEvent, Status>> + Send>>, Status> {
        let mut stream = request.into_inner();
        let (event_tx, event_rx) = mpsc::channel(128);

        // 用于上报事件的克隆
        let event_tx_clone = event_tx.clone();
        let task_mgr = self.task_mgr.clone();

        // 启动命令处理协程
        tokio::spawn(async move {
            Self::process_commands(stream, task_mgr, event_tx_clone).await;
        });

        Ok(Response::new(Box::pin(event_rx) as Pin<Box<dyn Stream<Item = Result<proto::ScanEvent, Status>> + Send>>))
    }

    /// 处理终端A发送的命令流
    async fn process_commands(
        mut commands: impl Stream<Item = Result<proto::ScanCommand, Status>> + Unpin,
        task_mgr: Arc<ScanTaskMgr>,
        event_tx: mpsc::Sender<Result<proto::ScanEvent, Status>>,
    ) {
        while let Some(cmd_result) = commands.next().await {
            match cmd_result {
                Ok(proto::ScanCommand {
                    scan_id,
                    cmd: Some(proto_scan_command::Cmd::StartScanCmd(start)),
                }) => {
                    log_info!("收到扫描命令: scan_id={}, target={}", scan_id, start.target);

                    // 创建扫描任务
                    let task = task_mgr.create_task(&scan_id, start.target.clone()).await;

                    // 发送扫描开始事件
                    let started_event = proto::ScanEvent {
                        scan_id: scan_id.clone(),
                        event: Some(proto::scan_event::Event::ScanStarted(proto::ScanStarted {
                            total_files: 0, // 先设为0，扫描过程中更新
                            message: format!("开始扫描: {}", start.target),
                        })),
                    };
                    let _ = event_tx.send(Ok(started_event)).await;

                    // 异步执行扫描（不阻塞命令流）
                    let event_tx_clone = event_tx.clone();
                    let task_mgr_clone = task_mgr.clone();
                    tokio::spawn(async move {
                        task_mgr_clone
                            .run_scan(&scan_id, &start.target, start.exclude, event_tx_clone)
                            .await;
                    });
                }

                Ok(proto::ScanCommand {
                    scan_id,
                    cmd: Some(proto_scan_command::Cmd::StopScanCmd(stop)),
                }) => {
                    log_info!("收到停止命令: scan_id={}, reason={}", scan_id, stop.reason);
                    task_mgr.stop_task(&scan_id).await;

                    let stop_event = proto::ScanEvent {
                        scan_id: scan_id.clone(),
                        event: Some(proto::scan_event::Event::ScanCompleted(proto::ScanCompleted {
                            total_scanned: 0,
                            viruses_found: 0,
                            duration_ms: 0,
                            result_summary: format!("扫描已停止: {}", stop.reason),
                        })),
                    };
                    let _ = event_tx.send(Ok(stop_event)).await;
                }

                Ok(proto::ScanCommand {
                    scan_id,
                    cmd: Some(proto_scan_command::Cmd::GetStatusCmd(_)),
                }) => {
                    // 查询状态（可选实现）
                    log_info!("收到状态查询: scan_id={}", scan_id);
                }

                Ok(_) => {
                    // 忽略空命令
                }
                Err(e) => {
                    log_error!("命令解析错误: {}", e);
                    let _ = event_tx.send(Err(e)).await;
                    break;
                }
            }
        }
    }
}

// tonic代码生成会用到
include!(concat!(env!("OUT_DIR"), "/_, "));
```

### 5.5 文件: crates/virus_scan_grpc/src/lib.rs

```rust
pub mod proto {
    tonic::include_proto!("virus_scan");
}

mod types;
mod scanner;
mod task_mgr;
mod service;

pub use types::{Md5BatchItem, Md5BatchRequest, ScanTask};
pub use scanner::{VirusScanner, ScanFileEvent, FileCleanEvent, VirusFoundEvent};
pub use task_mgr::ScanTaskMgr;
pub use service::VirusScanGrpcService;
```

### 5.6 proto编译后的代码生成

需要添加build.rs:

```rust
// crates/virus_scan_grpc/build.rs
fn main() {
    tonic_build::compile_protos("src/proto/virus_scan.proto").unwrap();
}
```

## 6. 集成到main.rs

### 6.1 修改: crates/main/src/main.rs

```rust
// 在 imports 部分添加
use virus_scan_grpc::{
    proto::{self, scan_command, scan_event},
    ScanTaskMgr,
};
use tokio::sync::mpsc;

// ... 现有代码 ...

#[tokio::main]
async fn main() -> std::io::Result<()> {
    ensure_single_instance();

    // 初始化日志
    CustomLogger::init("/opt/osec/osec_backend.conf")
        .await
        .expect("无法初始化日志");

    // ... 现有初始化代码 (lines 47-111) ...

    // 新增：初始化扫描任务管理器
    let net_client = NetClient::new(Some(base_url), true)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let task_mgr = Arc::new(ScanTaskMgr::new(net_client));

    // 新增：gRPC服务和命令通道
    let (scan_cmd_tx, scan_cmd_rx) = mpsc::channel::<proto::ScanCommand>(32);
    let (scan_event_tx, _) = mpsc::channel::<Result<proto::ScanEvent, Status>>(128);

    // 启动病毒扫描gRPC服务
    let virus_scan_handle = tokio::spawn({
        let task_mgr = task_mgr.clone();
        let scan_event_tx = scan_event_tx.clone();
        async move {
            VirusScanGrpcServer::new(task_mgr, scan_event_tx)
                .start("127.0.0.1:50051")
                .await
        }
    });

    // 启动扫描任务处理器（从命令通道消费并执行扫描）
    let scan_task_handle = tokio::spawn({
        let task_mgr = task_mgr.clone();
        async move {
            ScanTaskProcessor::new(task_mgr)
                .run(scan_cmd_rx)
                .await
        }
    });

    // ... 现有服务启动代码 (lines 118-240) ...
    // 包括:
    // - start_services
    // - start_log_services
    // - task_fetcher
    // - timer_task
    // - kernel_event handlers
    // - usb_services
    // - docker_monitor

    // 等待退出信号
    println!("程序正在运行，按 Ctrl+C 或发送 SIGTERM 退出...");

    shutdown_signal().await;
    log_info!("程序退出，执行清理...");

    // ... 现有清理代码 ...
}

// 新增：gRPC服务器启动器
struct VirusScanGrpcServer {
    task_mgr: Arc<ScanTaskMgr>,
    event_tx: mpsc::Sender<Result<proto::ScanEvent, Status>>,
}

impl VirusScanGrpcService {
    pub fn new(task_mgr: Arc<ScanTaskMgr>, event_tx: mpsc::Sender<Result<proto::ScanEvent, Status>>) -> Self {
        Self { task_mgr, event_tx }
    }

    pub async fn start(self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let addr = addr.parse::<std::net::SocketAddr>()?;
        log_info!("病毒扫描gRPC服务启动: {}", addr);

        tonic::builder::ServerBuilder::new()
            .add_service(VirusScanServiceServer::new(self))
            .serve(addr)
            .await?;

        Ok(())
    }
}

// 实现 tonic::Service
#[tonic::async_trait]
impl VirusScanService for VirusScanGrpcServer {
    type ScanStream = Pin<Box<dyn Stream<Item = Result<proto::ScanEvent, Status>> + Send>>;

    async fn scan(
        &self,
        request: Request<Streaming<proto::ScanCommand>>,
    ) -> Result<Response<Self::ScanStream>, Status> {
        let service = VirusScanGrpcService::new(self.task_mgr.clone());
        service.handle_scan_stream(request).await
    }
}

// 新增：扫描任务处理器
struct ScanTaskProcessor {
    task_mgr: Arc<ScanTaskMgr>,
}

impl ScanTaskProcessor {
    pub fn new(task_mgr: Arc<ScanTaskMgr>) -> Self {
        Self { task_mgr }
    }

    pub async fn run(mut self, mut cmd_rx: mpsc::Receiver<proto::ScanCommand>) {
        while let Some(cmd) = cmd_rx.recv().await {
            if let Some(scan_cmd) = cmd.cmd {
                match scan_cmd {
                    scan_command::Cmd::StartScanCmd(start) => {
                        // 创建并运行扫描任务
                        let task = self.task_mgr.create_task(&cmd.scan_id, start.target.clone()).await;

                        // 异步执行扫描
                        let event_tx = self.event_tx.clone();
                        let task_mgr = self.task_mgr.clone();
                        tokio::spawn(async move {
                            task_mgr.run_scan(&cmd.scan_id, &start.target, start.exclude, event_tx).await;
                        });
                    }
                    scan_command::Cmd::StopScanCmd(stop) => {
                        self.task_mgr.stop_task(&cmd.scan_id).await;
                    }
                    _ => {}
                }
            }
        }
    }
}
```

## 7. 流程图

```
终端A (gRPC客户端)                          Agent (gRPC服务端)                        服务器B (HTTP)
    │                                           │                                          │
    │───────── Stream<ScanCommand> ────────────▶│                                          │
    │  ScanCommand {                             │                                          │
    │    scan_id: "scan_001",                    │                                          │
    │    cmd: StartScanCmd {                    │                                          │
    │      target: "/usr/bin",                   │                                          │
    │      exclude: ["/usr/bin/exclude_dir"]     │                                          │
    │    }                                       │                                          │
    │  }                                         │                                          │
    │                                           │                                          │
    │                                           ├── 遍历 /usr/bin ───────────────────────▶│
    │                                           │    计算每个文件的MD5                     │
    │                                           │                                          │
    │                                           ├── POST批量MD5 ────────────────────────▶│
    │                                           │    [{"path":"/usr/bin/ls","md5":"..."}] │
    │                                           │                                          │
    │                                           │◄──── 病毒检测结果 ──────────────────────│
    │                                           │    [{"path":"/usr/bin/ls","is_virus":true}] │
    │                                           │                                          │
    │◄──────── Stream<ScanEvent> ───────────────│                                          │
    │  ScanEvent {                               │                                          │
    │    scan_id: "scan_001",                    │                                          │
    │    event: VirusFound {                     │                                          │
    │      file_path: "/usr/bin/ls",             │                                          │
    │      virus_name: "Trojan.A",               │                                          │
    │      threat_level: "HIGH"                  │                                          │
    │    }                                       │                                          │
    │  }                                         │                                          │
    │                                           │                                          │
    │  ... 继续扫描其他文件 ...                   │                                          │
    │                                           │                                          │
    │◄──────── ScanEvent(Completed) ────────────│                                          │
    │  ScanEvent {                               │                                          │
    │    event: ScanCompleted {                  │                                          │
    │      total_scanned: 150,                   │                                          │
    │      viruses_found: 2,                     │                                          │
    │      duration_ms: 5000                     │                                          │
    │    }                                       │                                          │
    │  }                                         │                                          │
    │                                           │                                          │
    │  (可选) 发送StopScanCmd停止                │                                          │
    │───────── Stream<ScanCommand> ────────────▶│                                          │
```

## 8. 复用现有组件

| 功能 | 复用组件 | 位置 |
|------|----------|------|
| MD5计算 | `process_mgr::get_md5_global` | `crates/process_mgr/src/md5_cache.rs:89` |
| 目录遍历 | 参考`process_all_dirs` | `crates/task/src/get_process_task.rs:35` |
| HTTP上报 | `net_client::NetClient::post_data_async` | `crates/net_client/src/core/client.rs` |
| 配置读取 | `NETINFO_CONFIG` | `crates/config/src/net_info.rs` |
| 日志 | `logging::log_info/error` | 现有 |

## 9. 待确认事项

1. **服务器B的HTTP接口格式**: 需确认POST的URL路径和响应格式
2. **终端A的gRPC地址**: Agent作为服务端，监听地址是什么？
3. **是否需要认证**: gRPC连接是否需要token认证？
4. **并发扫描**: 是否支持多个扫描任务并发执行？

## 10. 后续扩展点

- [ ] 支持增量扫描（只扫描新增/修改的文件）
- [ ] 支持实时监控（监控新增可执行文件）
- [ ] 支持扫描进度持久化（重启后可恢复）
- [ ] 支持白名单配置
- [ ] 支持自定义扫描规则
