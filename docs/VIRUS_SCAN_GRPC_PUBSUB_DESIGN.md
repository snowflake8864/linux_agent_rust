# 病毒扫描gRPC服务设计方案 (Pub/Sub版本)

> **设计原则**：
> - 终端A与Agent在同一Linux机器上
> - **gRPC使用TCP 127.0.0.1:端口（方便开发调试）**
> - **无需TLS/Token（本地通信，安全可控）**
> - 服务器B通过HTTP访问（使用现有net_client）
> - Pub/Sub架构便于扩展

## 1. 架构概述

```
┌─────────────────────────────────────────────────────────────────┐
│                         终端A (外部程序，同一机器)                  │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │ 发布: ScanCommand (扫描命令)                               │ │
│  │ 订阅: ScanEvent (扫描进度/完成)                            │ │
│  │ 订阅: VirusAlert (病毒告警，高优先级)                       │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ TCP: 127.0.0.1:50051 (gRPC)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     EventBus (事件总线)                          │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                                                           │  │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │  │
│  │  │ ScanCommand │───▶│  事件路由器 │───▶│ ScanEvent   │    │  │
│  │  │   Topic     │    │             │    │   Topic     │    │  │
│  │  └─────────────┘    └─────────────┘    └─────────────┘    │  │
│  │                                                           │  │
│  │  ┌─────────────┐    ┌─────────────┐                       │  │
│  │  │ VirusAlert  │───▶│             │                       │  │
│  │  │   Topic     │    │             │                       │  │
│  │  └─────────────┘    └─────────────┘                       │  │
│  │                                                           │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│  扫描任务处理器    │ │  病毒检测服务     │ │  状态查询服务     │
│ (订阅ScanCommand)│ │ (订阅FileMd5)   │ │ (可选)          │
└────────┬─────────┘ └────────┬─────────┘ └──────────────────┘
         │                   │
         ▼                   ▼
┌──────────────────┐ ┌──────────────────┐
│  文件遍历+MD5    │ │  HTTP客户端      │
│  (复用get_md5)   │ │  (POST到服务器B) │
└────────┬─────────┘ └──────────────────┘
         │
         ▼
┌──────────────────┐
│  发布ScanEvent   │
│  发布VirusAlert  │
└──────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                       服务器B (外部HTTP服务器)                     │
│                                                                  │
│  - URL: {server_ip_port}/v1/scan/batch                          │
│  - 请求: [{"file_path": "/bin/ls", "md5": "xxx"}, ...]          │
│  - 响应: {"results": [{"file_path": "/bin/ls", "is_virus": true, "virus_name": "Trojan"}]} │
└─────────────────────────────────────────────────────────────────┘
```

## 2. 通信方式

### 2.1 终端A ↔ Agent (TCP gRPC)

```
┌─────────────────────────────────────────┐
│  终端A (外部程序)                         │
│  - gRPC客户端                            │
│  - 连接: 127.0.0.1:50051               │
│  - 无需认证、无需TLS                     │
└─────────────────────────────────────────┘
                    │
                    │ TCP (localhost)
                    ▼
┌─────────────────────────────────────────┐
│  Agent (本项目)                          │
│  - gRPC服务端                            │
│  - 监听: 127.0.0.1:50051               │
│  - 无需认证、无需TLS                     │
└─────────────────────────────────────────┘
```

**优势**：
- 方便开发调试（可分开终端运行）
- 与gRPC生态完全兼容
- 工具链支持好（grpcurl、evans等）
- 易于跨语言开发

**注意**：由于是localhost，外网无法访问，安全可控。

### 2.2 Agent ↔ 服务器B (HTTP)

```
┌─────────────────────────────────────────┐
│  Agent (本项目)                          │
│  - HTTP客户端 (复用net_client)           │
│  - POST到: {server_ip_port}/v1/scan/batch│
└─────────────────────────────────────────┘
                    │
                    │ HTTP POST
                    ▼
┌─────────────────────────────────────────┐
│  服务器B (外部HTTP服务器)                 │
│  - 接收批量MD5检测请求                    │
│  - 返回病毒检测结果                      │
└─────────────────────────────────────────┘
```

### 2.3 Protocol Buffer定义 (简化版)

```protobuf
syntax = "proto3";

package virus_scan;

// Unix Domain Socket方式，无需TLS/Token
service VirusScanService {
  // 发布扫描命令 (终端A -> Agent)
  rpc PublishCommand(ScanCommandRequest) returns (ScanCommandResponse);

  // 订阅扫描事件 (Agent -> 终端A)
  rpc SubscribeEvents(EventSubscriptionRequest) returns (stream ScanEvent);

  // 订阅病毒告警 (Agent -> 终端A，高优先级)
  rpc SubscribeVirusAlerts(VirusAlertSubscriptionRequest) returns (stream VirusAlert);
}

// 扫描命令请求
message ScanCommandRequest {
  ScanCommand cmd = 1;
}

// 扫描命令响应
message ScanCommandResponse {
  bool success = 1;
  string message = 2;
  string scan_id = 3;
}

// 事件订阅请求
message EventSubscriptionRequest {
  optional string scan_id = 1;           // 可选：只订阅特定任务
}

// 病毒告警订阅请求
message VirusAlertSubscriptionRequest {
  // 可选：只订阅特定威胁级别
  repeated string threat_levels = 1;
}

// ========== 事件定义 ==========

// 扫描命令
message ScanCommand {
  string scan_id = 1;                   // 任务ID，终端A生成
  CommandType type = 2;
  ScanTarget target = 3;
}

enum CommandType {
  START_SCAN = 0;
  STOP_SCAN = 1;
}

message ScanTarget {
  oneof target {
    string directory = 1;               // 指定目录
    bool full_disk = 2;                // true表示全盘
  }
  repeated string exclude_dirs = 3;     // 排除目录
  bool include_script = 4;              // 包含脚本文件
}

// 扫描事件
message ScanEvent {
  string scan_id = 1;
  EventType event_type = 2;
  oneof payload {
    ScanProgressPayload progress = 3;
    ScanCompletedPayload completed = 4;
    ScanErrorPayload error = 5;
  }
}

message ScanProgressPayload {
  int32 scanned = 1;
  int32 total = 2;
  int32 viruses_found = 3;
}

message ScanCompletedPayload {
  int32 total_scanned = 1;
  int32 viruses_found = 2;
  int64 duration_ms = 3;
}

message ScanErrorPayload {
  string error = 1;
}

// 病毒告警 (高优先级)
message VirusAlert {
  string scan_id = 1;
  string file_path = 2;
  string md5 = 3;
  string virus_name = 4;
  ThreatLevel threat_level = 5;
  int64 detected_at = 6;
}

enum ThreatLevel {
  LOW = 0;
  MEDIUM = 1;
  HIGH = 2;
  CRITICAL = 3;
}
```

```rust
// 事件总线 - Pub/Sub的核心
pub struct EventBus {
    // 命令通道 (终端A -> 扫描任务)
    cmd_sender: broadcast::Sender<ScanCommand>,
    // 事件通道 (扫描任务 -> 终端A)
    event_sender: broadcast::Sender<ScanEvent>,
    // 病毒告警通道 (扫描任务 -> 终端A，高优先级)
    virus_alert_sender: broadcast::Sender<VirusAlert>,
    // 文件MD5通道 (扫描任务 -> 病毒检测)
    md5_sender: broadcast::Sender<FileMd5Info>,
}

impl EventBus {
    pub fn new() -> Self {
        let (cmd_sender, _) = broadcast::channel(64);
        let (event_sender, _) = broadcast::channel(256);
        let (virus_alert_sender, _) = broadcast::channel(128);
        let (md5_sender, _) = broadcast::channel(512);

        Self {
            cmd_sender,
            event_sender,
            virus_alert_sender,
            md5_sender,
        }
    }

    // 发布命令
    pub fn publish_cmd(&self, cmd: ScanCommand) {
        let _ = self.cmd_sender.send(cmd);
    }

    // 订阅命令
    pub fn subscribe_cmd(&self) -> broadcast::Receiver<ScanCommand> {
        self.cmd_sender.subscribe()
    }

    // 发布扫描事件
    pub fn publish_event(&self, event: ScanEvent) {
        let _ = self.event_sender.send(event);
    }

    // 订阅扫描事件
    pub fn subscribe_events(&self) -> broadcast::Receiver<ScanEvent> {
        self.event_sender.subscribe()
    }

    // 发布病毒告警 (高优先级，即时推送)
    pub fn publish_virus_alert(&self, alert: VirusAlert) {
        let _ = self.virus_alert_sender.send(alert);
    }

    // 订阅病毒告警
    pub fn subscribe_virus_alerts(&self) -> broadcast::Receiver<VirusAlert> {
        self.virus_alert_sender.subscribe()
    }

    // 发布文件MD5 (用于病毒检测)
    pub fn publish_md5(&self, md5_info: FileMd5Info) {
        let _ = self.md5_sender.send(md5_info);
    }

    // 订阅文件MD5
    pub fn subscribe_md5(&self) -> broadcast::Receiver<FileMd5Info> {
        self.md5_sender.subscribe()
    }
}
```

### 2.2 Protocol Buffer定义

```protobuf
syntax = "proto3";

package virus_scan;

// gRPC服务 - 终端A与Agent交互
service VirusScanGrpcService {
  // 终端A发布命令
  rpc PublishCommand(ScanCommandRequest) returns (ScanCommandResponse);

  // 终端A订阅扫描事件 (Server Stream)
  rpc SubscribeEvents(EventSubscriptionRequest) returns (stream ScanEvent);

  // 终端A订阅病毒告警 (Server Stream，高优先级)
  rpc SubscribeVirusAlerts(VirusAlertSubscriptionRequest) returns (stream VirusAlert);
}

// 命令请求
message ScanCommandRequest {
  ScanCommand cmd = 1;
}

// 命令响应
message ScanCommandResponse {
  bool success = 1;
  string message = 2;
  string scan_id = 3;
}

// 事件订阅请求
message EventSubscriptionRequest {
  // 可选：只订阅特定scan_id的事件
  optional string scan_id = 1;
  // 可选：订阅事件类型
  repeated EventType event_types = 2;
}

enum EventType {
  ALL = 0;
  SCAN_STARTED = 1;
  SCAN_PROGRESS = 2;
  FILE_SCANNED = 3;
  SCAN_COMPLETED = 4;
  SCAN_ERROR = 5;
}

// 病毒告警订阅请求
message VirusAlertSubscriptionRequest {
  // 可选：只订阅特定级别的病毒
  repeated string threat_levels = 1;
}

// ========== 事件定义 ==========

// 扫描命令
message ScanCommand {
  string scan_id = 1;
  CommandType type = 2;
  ScanTarget target = 3;
}

enum CommandType {
  START_SCAN = 0;
  STOP_SCAN = 1;
  PAUSE_SCAN = 2;
  RESUME_SCAN = 3;
}

message ScanTarget {
  oneof target {
    string directory = 1;   // 指定目录
    bool full_disk = 2;    // 全盘扫描
  }
  repeated string exclude_dirs = 3;
  bool include_script = 4;
}

// 扫描事件
message ScanEvent {
  string scan_id = 1;
  EventType event_type = 2;
  oneof payload {
    ScanStartedPayload started = 3;
    ScanProgressPayload progress = 4;
    FileScannedPayload file_scanned = 5;
    ScanCompletedPayload completed = 6;
    ScanErrorPayload error = 7;
  }
}

message ScanStartedPayload {
  string target = 1;
  int32 estimated_files = 2;
}

message ScanProgressPayload {
  int32 scanned = 1;
  int32 total = 2;
  int32 viruses_found = 3;
}

message FileScannedPayload {
  string file_path = 1;
  string md5 = 2;
  ScanFileStatus status = 3;
}

enum ScanFileStatus {
  CLEAN = 0;
  SUSPICIOUS = 1;
  ERROR = 2;
}

message ScanCompletedPayload {
  int32 total_scanned = 1;
  int32 viruses_found = 2;
  int64 duration_ms = 3;
  string result_summary = 4;
}

message ScanErrorPayload {
  string error = 1;
  string error_code = 2;
}

// 病毒告警 (高优先级事件)
message VirusAlert {
  string scan_id = 1;
  string file_path = 2;
  string md5 = 3;
  string virus_name = 4;
  ThreatLevel threat_level = 5;
  int64 detected_at = 6;
}

enum ThreatLevel {
  LOW = 0;
  MEDIUM = 1;
  HIGH = 2;
  CRITICAL = 3;
}
```

## 3. 新增文件结构

```
crates/
  virus_scan_grpc/
    Cargo.toml
    build.rs
    src/
      lib.rs
      proto/
        virus_scan.proto
      event_bus.rs          # 事件总线 (Pub/Sub核心)
      command_handler.rs    # 命令处理器 (订阅Cmd -> 执行扫描)
      scanner.rs           # 文件扫描器
      virus_checker.rs     # 病毒检测器 (订阅MD5 -> HTTP请求B)
      grpc_service.rs      # gRPC服务实现
      types.rs             # 类型定义
```

## 4. 核心实现

### 4.1 文件: crates/virus_scan_grpc/src/event_bus.rs

```rust
use crate::types::{ScanCommand, ScanEvent, VirusAlert, FileMd5Info};
use tokio::sync::broadcast;
use std::sync::Arc;

/// 事件总线 - Pub/Sub核心组件
///
/// # 架构
/// ```
/// ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
/// │  发布者      │     │   EventBus  │     │  订阅者      │
/// │ (终端A/Agent)│────▶│             │────▶│(终端A/组件)  │
/// └─────────────┘     └─────────────┘     └─────────────┘
/// ```
///
/// # 特点
/// - 支持多发布者、多订阅者
/// - 异步非阻塞
/// - 支持事件过滤
/// - 支持背压处理
#[derive(Clone)]
pub struct EventBus {
    /// 命令通道: 终端A -> 扫描任务处理器
    cmd_tx: Arc<broadcast::Sender<ScanCommand>>,
    /// 扫描事件通道: 扫描任务 -> 终端A
    event_tx: Arc<broadcast::Sender<ScanEvent>>,
    /// 病毒告警通道: 扫描任务 -> 终端A (高优先级，即时推送)
    virus_alert_tx: Arc<broadcast::Sender<VirusAlert>>,
    /// 文件MD5通道: 扫描任务 -> 病毒检测器
    md5_tx: Arc<broadcast::Sender<FileMd5Info>>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    /// 创建新的事件总线
    pub fn new() -> Self {
        let (cmd_tx, _) = broadcast::channel(64);
        let (event_tx, _) = broadcast::channel(256);
        let (virus_alert_tx, _) = broadcast::channel(128);
        let (md5_tx, _) = broadcast::channel(512);

        Self {
            cmd_tx: Arc::new(cmd_tx),
            event_tx: Arc::new(event_tx),
            virus_alert_tx: Arc::new(virus_alert_tx),
            md5_tx: Arc::new(md5_tx),
        }
    }

    // ==================== 发布接口 ====================

    /// 发布扫描命令
    pub fn publish_cmd(&self, cmd: ScanCommand) {
        let _ = self.cmd_tx.send(cmd);
    }

    /// 发布扫描事件
    pub fn publish_event(&self, event: ScanEvent) {
        let _ = self.event_tx.send(event);
    }

    /// 发布病毒告警 (高优先级)
    pub fn publish_virus_alert(&self, alert: VirusAlert) {
        let _ = self.virus_alert_tx.send(alert);
    }

    /// 发布文件MD5信息 (用于病毒检测)
    pub fn publish_md5(&self, md5_info: FileMd5Info) {
        let _ = self.md5_tx.send(md5_info);
    }

    // ==================== 订阅接口 ====================

    /// 订阅扫描命令
    pub fn subscribe_cmd(&self) -> broadcast::Receiver<ScanCommand> {
        self.cmd_tx.subscribe()
    }

    /// 订阅扫描事件
    pub fn subscribe_events(&self) -> broadcast::Receiver<ScanEvent> {
        self.event_tx.subscribe()
    }

    /// 订阅病毒告警
    pub fn subscribe_virus_alerts(&self) -> broadcast::Receiver<VirusAlert> {
        self.virus_alert_tx.subscribe()
    }

    /// 订阅文件MD5信息
    pub fn subscribe_md5(&self) -> broadcast::Receiver<FileMd5Info> {
        self.md5_tx.subscribe()
    }

    // ==================== 统计接口 ====================

    /// 获取订阅者数量
    pub fn subscriber_count(&self) -> usize {
        self.cmd_tx.len()
    }
}
```

### 4.2 文件: crates/virus_scan_grpc/src/types.rs

```rust
use serde::Serialize;
use std::sync::atomic::{AtomicU8, Ordering};

pub const SCAN_STATE_IDLE: u8 = 0;
pub const SCAN_STATE_RUNNING: u8 = 1;
pub const SCAN_STATE_PAUSED: u8 = 2;
pub const SCAN_STATE_STOPPED: u8 = 3;
pub const SCAN_STATE_COMPLETED: u8 = 4;

#[derive(Clone, Debug)]
pub struct ScanTask {
    pub scan_id: String,
    pub target: String,
    pub exclude: Vec<String>,
    pub include_script: bool,
    pub state: Arc<AtomicU8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub scanned_count: Arc<std::sync::atomic::AtomicU32>,
    pub viruses_found: Arc<std::sync::atomic::AtomicU32>,
}

impl ScanTask {
    pub fn new(scan_id: String, target: String) -> Self {
        Self {
            scan_id,
            target,
            exclude: Vec::new(),
            include_script: true,
            state: Arc::new(AtomicU8::new(SCAN_STATE_IDLE)),
            created_at: chrono::Utc::now(),
            scanned_count: Arc::new(AtomicU32::new(0)),
            viruses_found: Arc::new(AtomicU32::new(0)),
        }
    }

    pub fn start(&self) {
        self.state.store(SCAN_STATE_RUNNING, Ordering::Relaxed);
    }

    pub fn stop(&self) {
        self.state.store(SCAN_STATE_STOPPED, Ordering::Relaxed);
    }

    pub fn pause(&self) {
        self.state.store(SCAN_STATE_PAUSED, Ordering::Relaxed);
    }

    pub fn resume(&self) {
        self.state.store(SCAN_STATE_RUNNING, Ordering::Relaxed);
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

    pub fn is_stopped(&self) -> bool {
        self.state.load(Ordering::Relaxed) == SCAN_STATE_STOPPED
    }

    pub fn increment_scanned(&self) {
        self.scanned_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_viruses(&self) {
        self.viruses_found.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct FileMd5Info {
    pub scan_id: String,
    pub file_path: String,
    pub md5: String,
    pub timestamp: i64,
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

### 4.3 文件: crates/virus_scan_grpc/src/command_handler.rs

```rust
use crate::event_bus::EventBus;
use crate::types::{ScanTask, SCAN_STATE_RUNNING};
use futures::stream::StreamExt;
use logging::{log_info, log_error};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

/// 扫描任务管理器
pub struct ScanTaskManager {
    event_bus: Arc<EventBus>,
    tasks: Arc<Mutex<HashMap<String, ScanTask>>>,
}

impl ScanTaskManager {
    pub fn new(event_bus: Arc<EventBus>) -> Self {
        Self {
            event_bus,
            tasks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 启动命令处理器 (订阅ScanCommand)
    pub async fn run(&self) {
        log_info!("扫描命令处理器启动");
        let mut cmd_rx = self.event_bus.subscribe_cmd();

        while let Ok(cmd) = cmd_rx.recv().await {
            match cmd.r#type {
                crate::proto::CommandType::StartScan as t => {
                    if let Some(target) = cmd.target {
                        self.handle_start_scan(&cmd.scan_id, target).await;
                    }
                }
                crate::proto::CommandType::StopScan => {
                    self.handle_stop_scan(&cmd.scan_id).await;
                }
                crate::proto::CommandType::PauseScan => {
                    self.handle_pause_scan(&cmd.scan_id).await;
                }
                crate::proto::CommandType::ResumeScan => {
                    self.handle_resume_scan(&cmd.scan_id).await;
                }
                _ => {}
            }
        }
    }

    async fn handle_start_scan(&self, scan_id: &str, target: crate::proto::ScanTarget) {
        let target_str = match target.target {
            Some(crate::proto::scan_target::Target::Directory(d)) => d,
            Some(crate::proto::scan_target::Target::FullDisk(_)) => "/".to_string(),
            None => return,
        };

        let task = ScanTask::new(scan_id.to_string(), target_str);
        task.start();

        let mut tasks = self.tasks.lock().await;
        tasks.insert(scan_id.to_string(), task.clone());

        log_info!("扫描任务开始: scan_id={}, target={}", scan_id, target_str);

        // 发布扫描开始事件
        let event = crate::proto::ScanEvent {
            scan_id: scan_id.to_string(),
            event_type: crate::proto::EventType::ScanStarted as i32,
            payload: Some(crate::proto::scan_event::Payload::Started(
                crate::proto::ScanStartedPayload {
                    target: target_str,
                    estimated_files: 0, // 先估算，后续更新
                },
            )),
        };
        self.event_bus.publish_event(event);

        // 异步执行扫描 (通过发布FileMd5Info事件)
        let event_bus = self.event_bus.clone();
        let scan_id = scan_id.to_string();
        let exclude = task.exclude.clone();

        tokio::spawn(async move {
            Self::execute_scan(&scan_id, &target_str, &exclude, &event_bus).await;
        });
    }

    async fn handle_stop_scan(&self, scan_id: &str) {
        let mut tasks = self.tasks.lock().await;
        if let Some(task) = tasks.get(scan_id) {
            task.stop();
            log_info!("扫描任务已停止: {}", scan_id);

            let event = crate::proto::ScanEvent {
                scan_id: scan_id.to_string(),
                event_type: crate::proto::EventType::ScanCompleted as i32,
                payload: Some(crate::proto::scan_event::Payload::Completed(
                    crate::proto::ScanCompletedPayload {
                        total_scanned: task.scanned_count.load(std::sync::atomic::Ordering::Relaxed) as i32,
                        viruses_found: task.viruses_found.load(std::sync::atomic::Ordering::Relaxed) as i32,
                        duration_ms: 0,
                        result_summary: "用户停止".to_string(),
                    },
                )),
            };
            self.event_bus.publish_event(event);
        }
    }

    async fn handle_pause_scan(&self, scan_id: &str) {
        let mut tasks = self.tasks.lock().await;
        if let Some(task) = tasks.get(scan_id) {
            task.pause();
            log_info!("扫描任务已暂停: {}", scan_id);
        }
    }

    async fn handle_resume_scan(&self, scan_id: &str) {
        let mut tasks = self.tasks.lock().await;
        if let Some(task) = tasks.get(scan_id) {
            task.resume();
            log_info!("扫描任务已恢复: {}", scan_id);
        }
    }

    /// 执行扫描 - 发布FileMd5Info事件供病毒检测器消费
    async fn execute_scan(scan_id: &str, target: &str, exclude: &[String], event_bus: &Arc<EventBus>) {
        use std::path::Path;

        let path = Path::new(target);
        if !path.exists() || !path.is_dir() {
            log_error!("目录不存在: {}", target);
            return;
        }

        let mut entries = match tokio::fs::read_dir(path).await {
            Ok(e) => e,
            Err(e) => {
                log_error!("打开目录失败 {}: {}", target, e);
                return;
            }
        };

        while let Some(entry) = entries.next_entry().await.ok().flatten() {
            // 检查任务状态
            let tasks = event_bus.tasks.lock().await;
            let task = tasks.get(scan_id);
            if task.map(|t| t.is_stopped()).unwrap_or(false) {
                break;
            }
            drop(tasks);

            // 如果暂停，等待恢复
            if let Some(task) = event_bus.get_task(scan_id).await {
                while task.is_paused() {
                    sleep(Duration::from_millis(100)).await;
                }
            }

            let file_path = entry.path().to_string_lossy().to_string();

            // 跳过.和..
            if file_path.ends_with("/.") || file_path.ends_with("/..") {
                continue;
            }

            // 检查排除
            let excluded = exclude.iter().any(|e| file_path.starts_with(e));
            if excluded {
                continue;
            }

            // 跳过目录
            if entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }

            // 计算MD5
            let md5 = match process_mgr::get_md5_global(&file_path) {
                Ok(m) => m,
                Err(e) => {
                    log_error!("计算MD5失败 {}: {}", file_path, e);
                    continue;
                }
            };

            // 发布FileMd5Info事件 (病毒检测器会订阅并处理)
            let md5_info = FileMd5Info {
                scan_id: scan_id.to_string(),
                file_path: file_path.clone(),
                md5,
                timestamp: chrono::Utc::now().timestamp(),
            };
            event_bus.publish_md5(md5_info);
        }

        // 发布扫描完成事件
        let tasks = event_bus.tasks.lock().await;
        if let Some(task) = tasks.get(scan_id) {
            let completed = crate::proto::ScanEvent {
                scan_id: scan_id.to_string(),
                event_type: crate::proto::EventType::ScanCompleted as i32,
                payload: Some(crate::proto::scan_event::Payload::Completed(
                    crate::proto::ScanCompletedPayload {
                        total_scanned: task.scanned_count.load(std::sync::atomic::Ordering::Relaxed) as i32,
                        viruses_found: task.viruses_found.load(std::sync::atomic::Ordering::Relaxed) as i32,
                        duration_ms: 0,
                        result_summary: format!(
                            "扫描完成，发现 {} 个病毒",
                            task.viruses_found.load(std::sync::atomic::Ordering::Relaxed)
                        ),
                    },
                )),
            };
            event_bus.publish_event(completed);
        }
    }
}

// 扩展EventBus以支持任务查询
trait EventBusTaskExt {
    async fn get_task(&self, scan_id: &str) -> Option<ScanTask>;
}

impl EventBusTaskExt for Arc<EventBus> {
    async fn get_task(&self, scan_id: &str) -> Option<ScanTask> {
        // 这里需要访问ScanTaskManager的tasks
        // 实际实现中可以通过共享状态来实现
        None
    }
}
```

### 4.4 文件: crates/virus_scan_grpc/src/virus_checker.rs

```rust
use crate::event_bus::EventBus;
use crate::types::{FileMd5Info, Md5BatchItem, Md5BatchRequest};
use futures::stream::StreamExt;
use logging::{log_info, log_error};
use net_client::core::NetClient;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{timeout, Duration};

const BATCH_SIZE: usize = 100;
const HTTP_TIMEOUT_SECS: u64 = 30;

/// 病毒检测器 - 订阅FileMd5Info，批量检测后发布结果
pub struct VirusChecker {
    event_bus: Arc<EventBus>,
    net_client: NetClient,
    server_b_url: String,
    buffer: Arc<tokio::sync::Mutex<Vec<FileMd5Info>>>,
}

impl VirusChecker {
    pub fn new(event_bus: Arc<EventBus>, net_client: NetClient, server_b_url: String) -> Self {
        Self {
            event_bus,
            net_client,
            server_b_url,
            buffer: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    /// 启动病毒检测器 (订阅FileMd5Info)
    pub async fn run(&self) {
        log_info!("病毒检测器启动");
        let mut md5_rx = self.event_bus.subscribe_md5();
        let buffer = self.buffer.clone();
        let event_bus = self.event_bus.clone();

        while let Ok(md5_info) = md5_rx.recv().await {
            let mut buf = buffer.lock().await;
            buf.push(md5_info);

            if buf.len() >= BATCH_SIZE {
                let batch = buf.clone();
                buf.clear();
                drop(buf);

                // 异步检测
                let event_bus = event_bus.clone();
                tokio::spawn(async move {
                    Self::check_batch(&batch, &event_bus).await;
                });
            }
        }

        // 处理剩余
        let remaining = buffer.lock().await.clone();
        if !remaining.is_empty() {
            Self::check_batch(&remaining, &event_bus).await;
        }
    }

    /// 批量检测
    async fn check_batch(batch: &[FileMd5Info], event_bus: &Arc<EventBus>) {
        let items: Vec<Md5BatchItem> = batch
            .iter()
            .map(|info| Md5BatchItem {
                file_path: info.file_path.clone(),
                md5: info.md5.clone(),
            })
            .collect();

        let request = Md5BatchRequest {
            scan_id: batch.first().map(|b| b.scan_id.clone()).unwrap_or_default(),
            items,
        };

        let json = match serde_json::to_string(&request) {
            Ok(j) => j,
            Err(e) => {
                log_error!("序列化失败: {}", e);
                return;
            }
        };

        let url = format!("{}/v1/scan/batch", event_bus.server_b_url());
        log_info!("批量检测: {} 个文件", batch.len());

        match timeout(
            Duration::from_secs(HTTP_TIMEOUT_SECS),
            event_bus.net_client.post_data_async(&url, &json, Duration::from_secs(HTTP_TIMEOUT_SECS), None),
        ).await {
            Ok(Ok(response)) => {
                Self::process_response(batch, &response, event_bus).await;
            }
            Ok(Err(e)) => {
                log_error!("HTTP请求失败: {}", e);
                // 发布错误事件
            }
            Err(_) => {
                log_error!("HTTP请求超时");
            }
        }
    }

    /// 处理服务器B的响应
    async fn process_response(batch: &[FileMd5Info], response: &str, event_bus: &Arc<EventBus>) {
        let parsed: serde_json::Value = match serde_json::from_str(response) {
            Ok(p) => p,
            Err(e) => {
                log_error!("解析响应失败: {}", e);
                return;
            }
        };

        let virus_map: HashMap<String, serde_json::Value> = parsed["results"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter(|r| r["is_virus"].as_bool().unwrap_or(false))
            .map(|r| (r["file_path"].as_str().unwrap_or("").to_string(), r.clone()))
            .collect();

        for info in batch {
            let is_virus = virus_map.contains_key(&info.file_path);

            // 发布文件扫描结果事件
            let event = if is_virus {
                let virus = virus_map.get(&info.file_path).unwrap();
                let threat_level = virus["threat_level"].as_str().unwrap_or("HIGH").to_string();
                let virus_name = virus["virus_name"].as_str().unwrap_or("Unknown").to_string();

                // 发布病毒告警 (高优先级，即时推送)
                let alert = crate::proto::VirusAlert {
                    scan_id: info.scan_id.clone(),
                    file_path: info.file_path.clone(),
                    md5: info.md5.clone(),
                    virus_name: virus_name.clone(),
                    threat_level: Self::parse_threat_level(&threat_level),
                    detected_at: info.timestamp,
                };
                event_bus.publish_virus_alert(alert);

                crate::proto::scan_event::Payload::FileScanned(
                    crate::proto::FileScannedPayload {
                        file_path: info.file_path.clone(),
                        md5: info.md5.clone(),
                        status: crate::proto::ScanFileStatus::Suspicious as i32,
                    },
                )
            } else {
                crate::proto::scan_event::Payload::FileScanned(
                    crate::proto::FileScannedPayload {
                        file_path: info.file_path.clone(),
                        md5: info.md5.clone(),
                        status: crate::proto::ScanFileStatus::Clean as i32,
                    },
                )
            };

            let scan_event = crate::proto::ScanEvent {
                scan_id: info.scan_id.clone(),
                event_type: crate::proto::EventType::FileScanned as i32,
                payload: Some(event),
            };
            event_bus.publish_event(scan_event);
        }
    }

    fn parse_threat_level(level: &str) -> i32 {
        match level.to_uppercase().as_str() {
            "LOW" => crate::proto::ThreatLevel::Low as i32,
            "MEDIUM" => crate::proto::ThreatLevel::Medium as i32,
            "HIGH" => crate::proto::ThreatLevel::High as i32,
            "CRITICAL" => crate::proto::ThreatLevel::Critical as i32,
            _ => crate::proto::ThreatLevel::Low as i32,
        }
    }
}

// 扩展EventBus (临时方案)
trait EventBusExt {
    fn net_client(&self) -> &NetClient;
    fn server_b_url(&self) -> String;
}

impl EventBusExt for Arc<EventBus> {
    fn net_client(&self) -> &NetClient {
        // 实际实现需要存储net_client
        panic!("需要注入net_client")
    }

    fn server_b_url(&self) -> String {
        panic!("需要从配置读取")
    }
}
```

### 4.5 文件: crates/virus_scan_grpc/src/grpc_service.rs

```rust
use crate::event_bus::EventBus;
use crate::proto::{
    self, ScanCommand, ScanEvent, VirusAlert,
    EventSubscriptionRequest, ScanCommandRequest, VirusAlertSubscriptionRequest,
};
use futures::stream::Stream;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};

/// gRPC服务实现
pub struct VirusScanGrpcService {
    event_bus: Arc<EventBus>,
}

impl VirusScanGrpcService {
    pub fn new(event_bus: Arc<EventBus>) -> Self {
        Self { event_bus }
    }

    /// 发布扫描命令 (终端A -> Agent)
    async fn publish_command(
        &self,
        request: Request<ScanCommandRequest>,
    ) -> Result<Response<proto::ScanCommandResponse>, Status> {
        let cmd = request.into_inner().cmd.ok_or(Status::invalid_argument("缺少命令"))?;

        // 发布到事件总线
        self.event_bus.publish_cmd(cmd.clone());

        Ok(Response::new(proto::ScanCommandResponse {
            success: true,
            message: "命令已接收".to_string(),
            scan_id: cmd.scan_id,
        }))
    }

    /// 订阅扫描事件 (Agent -> 终端A)
    async fn subscribe_events(
        &self,
        request: Request<EventSubscriptionRequest>,
    ) -> Result<Response<Pin<Box<dyn Stream<Item = Result<ScanEvent, Status>> + Send>>>, Status> {
        let filter = request.into_inner();
        let scan_id_filter = filter.scan_id;
        let event_types_filter: Vec<i32> = filter.event_types.iter().map(|&e| e as i32).collect();

        let mut rx = self.event_bus.subscribe_events();
        let (tx, stream) = mpsc::channel(128);

        tokio::spawn(async move {
            while let Ok(event) = rx.recv().await {
                // 过滤
                if let Some(ref filter_id) = scan_id_filter {
                    if event.scan_id != *filter_id {
                        continue;
                    }
                }

                if !event_types_filter.is_empty()
                    && !event_types_filter.contains(&event.event_type)
                {
                    continue;
                }

                if tx.send(Ok(event)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(Box::pin(stream) as _))
    }

    /// 订阅病毒告警 (高优先级，即时推送)
    async fn subscribe_virus_alerts(
        &self,
        _request: Request<VirusAlertSubscriptionRequest>,
    ) -> Result<Response<Pin<Box<dyn Stream<Item = Result<VirusAlert, Status>> + Send>>>, Status> {
        let mut rx = self.event_bus.subscribe_virus_alerts();
        let (tx, stream) = mpsc::channel(64);

        tokio::spawn(async move {
            while let Ok(alert) = rx.recv().await {
                if tx.send(Ok(alert)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(Box::pin(stream) as _))
    }
}
```

### 4.6 文件: crates/virus_scan_grpc/src/lib.rs

```rust
pub mod proto {
    tonic::include_proto!("virus_scan");
}

mod event_bus;
mod types;
mod command_handler;
mod virus_checker;
mod grpc_service;

pub use event_bus::EventBus;
pub use types::{ScanTask, FileMd5Info};
pub use command_handler::ScanTaskManager;
pub use virus_checker::VirusChecker;
pub use grpc_service::VirusScanGrpcService;
```

### 4.7 文件: crates/virus_scan_grpc/build.rs

```rust
fn main() {
    tonic_build::compile_protos("src/proto/virus_scan.proto").unwrap();
}
```

### 4.8 文件: crates/virus_scan_grpc/Cargo.toml

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
chrono = { version = "0.4" }
```

## 5. 集成到main.rs

```rust
// crates/main/src/main.rs

use virus_scan_grpc::{
    EventBus, ScanTaskManager, VirusChecker, VirusScanGrpcService,
    proto::virus_scan_service_server::VirusScanServiceServer,
};
use std::sync::Arc;
use tokio::sync::broadcast;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // ... 现有代码 ...

    // 新增：初始化事件总线
    let event_bus = Arc::new(EventBus::new());

    // 初始化组件
    let net_client = NetClient::new(Some(base_url), true)?;
    let task_manager = Arc::new(ScanTaskManager::new(event_bus.clone()));
    let virus_checker = Arc::new(VirusChecker::new(
        event_bus.clone(),
        net_client.clone(),
        server_b_url,
    ));

    // 启动扫描命令处理器 (订阅ScanCommand)
    let command_handler_handle = tokio::spawn({
        let task_manager = task_manager.clone();
        async move {
            task_manager.run().await;
        }
    });

    // 启动病毒检测器 (订阅FileMd5Info)
    let virus_checker_handle = tokio::spawn({
        let virus_checker = virus_checker.clone();
        async move {
            virus_checker.run().await;
        }
    });

    // 启动gRPC服务
    let grpc_service = VirusScanGrpcService::new(event_bus.clone());
    let grpc_handle = tokio::spawn({
        let grpc_service = grpc_service.clone();
        async move {
            let addr = "127.0.0.1:50051".parse::<std::net::SocketAddr>().unwrap();
            tonic::builder::ServerBuilder::new()
                .add_service(VirusScanServiceServer::new(grpc_service))
                .serve(addr)
                .await
                .unwrap();
        }
    });

    // ... 等待退出信号 ...
}
```

## 6. Pub/Sub vs 传统模式对比

| 特性 | 传统请求/响应 | Pub/Sub模式 |
|------|-------------|------------|
| 耦合度 | 高 (客户端-服务器直接绑定) | 低 (通过事件总线) |
| 扩展性 | 差 (新增订阅者需改服务器) | 好 (订阅者独立) |
| 异步支持 | 需额外处理 | 原生支持 |
| 多订阅者 | 不支持 | 支持 |
| 背压处理 | 复杂 | 需自行处理 |
| 复杂度 | 简单 | 中等 |
| 适用场景 | 简单RPC | 事件驱动、多消费者 |

## 7. 流程图 (Pub/Sub)

```
终端A                      EventBus                    扫描任务处理器              病毒检测器
  │                           │                             │                        │
  │── PublishCommand ────────▶│                             │                        │
  │  StartScan {              │                             │                        │
  │    scan_id: "001",        │                             │                        │
  │    target: "/usr/bin"     │                             │                        │
  │  }                        │                             │                        │
  │                           │── Cmd ─────────────────────▶│                        │
  │                           │                            │                        │
  │                           │                            │── 遍历+MD5 ──────────▶│
  │                           │                            │                        │
  │                           │◀── FileMd5Info ────────────│                        │
  │                           │    {scan_id, file, md5}    │                        │
  │                           │                            │                        │
  │                           │                            │◀── 批量检测结果 ───────│
  │                           │                            │                        │
  │◀── SubscribeEvents ──────│                            │                        │
  │                           │                            │                        │
  │◀── ScanEvent ────────────│                            │                        │
  │  {scan_id, file, status} │                            │                        │
  │                           │                            │                        │
  │◀── VirusAlert ───────────│                            │                        │
  │  {file, virus_name}      │                            │                        │
  │                           │                            │                        │
  │◀── ScanEvent(Completed) ─│                            │                        │
```

## 8. 优势总结

1. **松耦合**: 组件之间通过事件通信，不直接依赖
2. **可扩展**: 易于添加新的订阅者（如日志、监控）
3. **异步优先**: 天然支持异步处理
4. **多播支持**: 一个事件可被多个订阅者处理
5. **便于测试**: 可以单独测试每个组件
6. **易于扩展**: 新功能只需添加新的事件类型和处理器
