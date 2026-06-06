# 病毒扫描gRPC服务设计方案

> **设计原则**：
> - Agent与终端A可部署在不同机器
> - gRPC支持两种模式：**开发模式（对外）** / **生产模式（对内）**
> - 通过配置文件切换，灵活可控
> - Pub/Sub架构便于扩展

---

## 目录

1. [整体架构](#1-整体架构)
2. [配置文件](#2-配置文件)
3. [Topic定义](#3-topic定义)
4. [gRPC接口](#4-grpc接口)
5. [终端A接入指南](#5-终端a接入指南)
6. [核心实现](#6-核心实现)
7. [集成到main.rs](#7-集成到mainrs)
8. [流程图](#8-流程图)

---

## 1. 整体架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              终端A (外部程序)                              │
│                                                                          │
│   开发者A编写代码调用gRPC接口                                             │
│   - 开发阶段：连接 Agent:50051 (远程/本地)                                │
│   - 生产阶段：连接 Agent:50051 (localhost)                               │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ gRPC (TCP)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                              Agent (本项目)                               │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    EventBus (事件总线)                            │    │
│  │                                                                 │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │    │
│  │  │ ScanCommand  │──▶│   Topic     │──▶│ScanTaskMgr  │         │    │
│  │  │    Topic     │  │   Router    │  │              │         │    │
│  │  └──────────────┘  └──────────────┘  └──────┬───────┘         │    │
│  │                                              │                    │    │
│  │  ┌──────────────┐  ┌──────────────┐        ▼                    │    │
│  │  │ ScanEvent   │──▶│   Topic     │──▶│FileScanner │────────┐ │    │
│  │  │    Topic     │  │   Router    │  │              │        │ │    │
│  │  └──────────────┘  └──────────────┘  └──────┬───────┘        │ │    │
│  │                                              │                 │ │    │
│  │  ┌──────────────┐  ┌──────────────┐        ▼                 │ │    │
│  │  │VirusAlert   │──▶│   Topic     │──▶│VirusChecker│───┐    │ │    │
│  │  │    Topic     │  │   Router    │  │              │   │    │ │    │
│  │  └──────────────┘  └──────────────┘  └───────────────┘   │    │ │    │
│  │                                                           │    │ │    │
│  └───────────────────────────────────────────────────────────┼────┼─┼────┘
│                                                            │    │ │
│                     ┌──────────────────────────────────────┘    │ │
│                     ▼                                           │ │
│  ┌───────────────────────────────────────────────────────────┐  │ │
│  │                      服务器B (外部HTTP服务器)                  │  │ │
│  │                                                               │  │ │
│  │   POST {server_ip_port}/v1/scan/batch                      │  │ │
│  │   请求: [{"file_path": "/bin/ls", "md5": "xxx"}, ...]      │  │ │
│  │   响应: {"results": [{"file_path": "/bin/ls", "is_virus": true}]} │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 通信方式

| 通信路径 | 方式 | 说明 |
|---------|------|------|
| 终端A ↔ Agent | **gRPC (TCP)** | 端口可配置，开发对外，生产对内 |
| Agent ↔ 服务器B | **HTTP** | POST批量MD5检测 |

---

## 2. 配置文件

### 2.1 新增配置项: crates/config/src/net_info.rs

```rust
// 新增配置结构
#[derive(Debug, Clone)]
pub struct VirusScanConfig {
    /// 是否启用病毒扫描服务
    pub enabled: bool,
    /// gRPC监听地址
    pub grpc_addr: String,
    /// 是否开发模式（对外暴露）
    pub dev_mode: bool,
    /// 开发模式监听地址（可对外）
    pub dev_grpc_addr: String,
    /// 服务器B的URL
    pub server_b_url: String,
    /// 批量检测大小
    pub batch_size: usize,
    /// HTTP超时秒数
    pub http_timeout_secs: u64,
}

impl Default for VirusScanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            grpc_addr: "127.0.0.1:50051".to_string(),
            dev_mode: false,
            dev_grpc_addr: "0.0.0.0:50051".to_string(),  // 对外开放
            server_b_url: "".to_string(),
            batch_size: 100,
            http_timeout_secs: 30,
        }
    }
}
```

### 2.2 net_info.ini 配置示例

```ini
[virus_scan]
enabled = true
dev_mode = true                    ; true=对外开发联调, false=生产对内
grpc_addr = 127.0.0.1:50051       ; 生产模式监听地址
dev_grpc_addr = 0.0.0.0:50051     ; 开发模式监听地址（0.0.0.0对外）
batch_size = 100                   ; 批量检测大小
http_timeout_secs = 30             ; HTTP超时

[server_b]
ip_port = http://192.168.1.100:8080  ; 服务器B地址
```

### 2.3 启动时选择地址

```rust
fn get_grpc_addr() -> String {
    let cfg = NETINFO_CONFIG.lock().unwrap();
    if cfg.virus_scan.dev_mode {
        cfg.virus_scan.dev_grpc_addr.clone()
    } else {
        cfg.virus_scan.grpc_addr.clone()
    }
}
```

---

## 3. Topic定义

### 3.1 EventBus Topic

```
┌─────────────────────────────────────────────────────────────────┐
│                        EventBus Topics                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  【发布】 ScanCommand Topic                                       │
│  ─────────────────────────────────────────────────────────────  │
│  发布者: 终端A                                                    │
│  订阅者: ScanTaskManager                                         │
│  消息: ScanCommand (扫描命令)                                     │
│  说明: 终端A发送扫描/停止命令                                     │
│                                                                  │
│  【订阅】 ScanEvent Topic                                         │
│  ─────────────────────────────────────────────────────────────  │
│  发布者: ScanTaskManager, FileScanner, VirusChecker              │
│  订阅者: 终端A                                                    │
│  消息: ScanEvent (扫描事件)                                        │
│  说明: 扫描进度、结果、错误                                        │
│                                                                  │
│  【订阅】 VirusAlert Topic                                        │
│  ─────────────────────────────────────────────────────────────  │
│  发布者: VirusChecker                                            │
│  订阅者: 终端A                                                    │
│  消息: VirusAlert (病毒告警)                                       │
│  说明: 发现病毒时即时推送，高优先级                                  │
│                                                                  │
│  【内部】 FileMd5 Topic                                           │
│  ─────────────────────────────────────────────────────────────  │
│  发布者: FileScanner                                             │
│  订阅者: VirusChecker                                            │
│  消息: FileMd5Info (文件MD5信息)                                  │
│  说明: 内部使用，批量发送给服务器B检测                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Topic消息格式

#### 3.2.1 ScanCommand (终端A发布)

```protobuf
// ScanCommand (Topic: scan_command)
message ScanCommand {
    string scan_id = 1;           // 任务ID，终端A生成（UUID）
    CommandType type = 2;          // 命令类型
    ScanTarget target = 3;         // 扫描目标
    int64 timestamp = 4;           // 命令时间戳
}

enum CommandType {
    START_SCAN = 0;               // 开始扫描
    STOP_SCAN = 1;                // 停止扫描
}

message ScanTarget {
    oneof target {
        string directory = 1;      // 指定目录路径
        bool full_disk = 2;        // true=全盘扫描
    }
    repeated string exclude_dirs = 3;   // 排除目录
    bool include_script = 4;            // 包含脚本文件
}
```

#### 3.2.2 ScanEvent (终端A订阅)

```protobuf
// ScanEvent (Topic: scan_event)
message ScanEvent {
    string scan_id = 1;           // 对应任务ID
    EventType event_type = 2;      // 事件类型
    EventPayload payload = 3;       // 事件数据
    int64 timestamp = 4;           // 事件时间戳
}

enum EventType {
    SCAN_STARTED = 0;             // 扫描开始
    SCAN_PROGRESS = 1;             // 扫描进度
    SCAN_COMPLETED = 2;            // 扫描完成
    SCAN_ERROR = 3;               // 扫描错误
    FILE_SCANNED = 4;              // 单文件扫描完成
}

message EventPayload {
    oneof data {
        StartedPayload started = 1;
        ProgressPayload progress = 2;
        CompletedPayload completed = 3;
        ErrorPayload error = 4;
        FileScannedPayload file = 5;
    }
}

message StartedPayload {
    string target = 1;            // 扫描目标
    int32 estimated_files = 2;     // 预估文件数
}

message ProgressPayload {
    int32 scanned = 1;            // 已扫描数
    int32 total = 2;              // 总数
    int32 viruses_found = 3;       // 发现病毒数
}

message CompletedPayload {
    int32 total_scanned = 1;       // 总扫描数
    int32 viruses_found = 2;       // 病毒数
    int64 duration_ms = 3;         // 耗时(毫秒)
}

message ErrorPayload {
    string error_code = 1;         // 错误码
    string error_message = 2;      // 错误信息
}

message FileScannedPayload {
    string file_path = 1;          // 文件路径
    string md5 = 2;                // 文件MD5
    FileStatus status = 3;         // 状态
}

enum FileStatus {
    CLEAN = 0;                     // 干净
    SUSPICIOUS = 1;                // 可疑
    ERROR = 2;                     // 错误
}
```

#### 3.2.3 VirusAlert (终端A订阅)

```protobuf
// VirusAlert (Topic: virus_alert)
message VirusAlert {
    string scan_id = 1;           // 扫描任务ID
    string file_path = 2;          // 病毒文件路径
    string md5 = 3;                // 文件MD5
    string virus_name = 4;         // 病毒名称
    ThreatLevel threat_level = 5;  // 威胁等级
    int64 detected_at = 6;         // 检测时间戳
    string description = 7;        // 病毒描述
}

enum ThreatLevel {
    LOW = 0;
    MEDIUM = 1;
    HIGH = 2;
    CRITICAL = 3;
}
```

#### 3.2.4 FileMd5Info (内部使用)

```protobuf
// FileMd5Info (Topic: file_md5, 内部)
message FileMd5Info {
    string scan_id = 1;
    string file_path = 2;
    string md5 = 3;
    int64 timestamp = 4;
}
```

---

## 4. gRPC接口

### 4.1 Protocol Buffer定义

```protobuf
syntax = "proto3";

package virus_scan;

// 病毒扫描服务
service VirusScanService {
    // 发布扫描命令 (终端A -> Agent)
    rpc PublishCommand(ScanCommandRequest) returns (ScanCommandResponse);

    // 订阅扫描事件 (Agent -> 终端A)
    rpc SubscribeEvents(EventSubscriptionRequest) returns (stream ScanEvent);

    // 订阅病毒告警 (Agent -> 终端A，高优先级)
    rpc SubscribeVirusAlerts(AlertSubscriptionRequest) returns (stream VirusAlert);

    // 获取扫描状态
    rpc GetScanStatus(StatusRequest) returns (StatusResponse);
}

// ============ 命令接口 ============

message ScanCommandRequest {
    ScanCommand cmd = 1;
}

message ScanCommandResponse {
    bool success = 1;
    string message = 2;
    string scan_id = 3;
}

// ============ 事件订阅接口 ============

message EventSubscriptionRequest {
    // 可选：只订阅特定scan_id
    optional string scan_id = 1;
    // 可选：订阅特定事件类型
    repeated EventType event_types = 2;
}

message AlertSubscriptionRequest {
    // 可选：只订阅特定威胁级别
    repeated ThreatLevel threat_levels = 1;
}

// ============ 状态查询接口 ============

message StatusRequest {
    // 可选：指定scan_id
    optional string scan_id = 1;
}

message StatusResponse {
    repeated ScanStatusItem scans = 1;
}

message ScanStatusItem {
    string scan_id = 1;
    string target = 2;
    ScanState state = 3;
    int32 scanned = 4;
    int32 viruses = 5;
    int64 start_time = 6;
}

enum ScanState {
    IDLE = 0;
    RUNNING = 1;
    PAUSED = 2;
    STOPPED = 3;
    COMPLETED = 4;
}

// ============ 消息定义 ============

message ScanCommand {
    string scan_id = 1;
    CommandType type = 2;
    ScanTarget target = 3;
    int64 timestamp = 4;
}

enum CommandType {
    START_SCAN = 0;
    STOP_SCAN = 1;
}

message ScanTarget {
    oneof target {
        string directory = 1;
        bool full_disk = 2;
    }
    repeated string exclude_dirs = 3;
    bool include_script = 4;
}

message ScanEvent {
    string scan_id = 1;
    EventType event_type = 2;
    EventPayload payload = 3;
    int64 timestamp = 4;
}

enum EventType {
    SCAN_STARTED = 0;
    SCAN_PROGRESS = 1;
    SCAN_COMPLETED = 2;
    SCAN_ERROR = 3;
    FILE_SCANNED = 4;
}

message EventPayload {
    oneof data {
        StartedPayload started = 1;
        ProgressPayload progress = 2;
        CompletedPayload completed = 3;
        ErrorPayload error = 4;
        FileScannedPayload file = 5;
    }
}

message StartedPayload {
    string target = 1;
    int32 estimated_files = 2;
}

message ProgressPayload {
    int32 scanned = 1;
    int32 total = 2;
    int32 viruses_found = 3;
}

message CompletedPayload {
    int32 total_scanned = 1;
    int32 viruses_found = 2;
    int64 duration_ms = 3;
}

message ErrorPayload {
    string error_code = 1;
    string error_message = 2;
}

message FileScannedPayload {
    string file_path = 1;
    string md5 = 2;
    FileStatus status = 3;
}

enum FileStatus {
    CLEAN = 0;
    SUSPICIOUS = 1;
    ERROR = 2;
}

message VirusAlert {
    string scan_id = 1;
    string file_path = 2;
    string md5 = 3;
    string virus_name = 4;
    ThreatLevel threat_level = 5;
    int64 detected_at = 6;
    string description = 7;
}

enum ThreatLevel {
    LOW = 0;
    MEDIUM = 1;
    HIGH = 2;
    CRITICAL = 3;
}
```

### 4.2 端口配置

| 模式 | 配置文件 | 监听地址 | 说明 |
|------|---------|----------|------|
| 开发模式 | `dev_mode = true` | `0.0.0.0:50051` | 对外开放，方便联调 |
| 生产模式 | `dev_mode = false` | `127.0.0.1:50051` | 仅本地访问 |

---

## 5. 终端A接入指南

### 5.1 连接方式

```python
# 终端A (Python示例)

import grpc
from virus_scan_pb2 import *
from virus_scan_pb2_grpc import *

# 开发模式：连接远程Agent
AGENT_ADDR = "192.168.1.100:50051"  # Agent的IP地址

# 生产模式：连接本地Agent
AGENT_ADDR = "127.0.0.1:50051"      # localhost

# 创建通道（无需认证）
channel = grpc.insecure_channel(AGENT_ADDR)
client = VirusScanServiceStub(channel)
```

### 5.2 发布扫描命令

```python
import uuid
from datetime import datetime

# 生成唯一的scan_id
scan_id = str(uuid.uuid4())

# 创建扫描命令
command = ScanCommand(
    scan_id=scan_id,
    type=CommandType.START_SCAN,
    target=ScanTarget(
        directory="/usr/bin"  # 指定目录
        # full_disk=True     # 或全盘扫描
    ),
    exclude_dirs=["/usr/bin/exclude"],
    include_script=True,
    timestamp=int(datetime.now().timestamp() * 1000)
)

# 发送命令
request = ScanCommandRequest(cmd=command)
response = client.PublishCommand(request)

print(f"命令已发送: scan_id={response.scan_id}, success={response.success}")
```

### 5.3 订阅扫描事件

```python
# 订阅扫描事件
request = EventSubscriptionRequest(
    scan_id=scan_id,  # 可选：只订阅特定任务
    # event_types=[EventType.SCAN_PROGRESS, EventType.SCAN_COMPLETED]  # 可选：筛选
)

for event in client.SubscribeEvents(request):
    print(f"[{event.timestamp}] scan_id={event.scan_id}, type={event.event_type}")
    
    if event.event_type == EventType.SCAN_STARTED:
        print(f"  开始扫描: {event.payload.started.target}")
        
    elif event.event_type == EventType.SCAN_PROGRESS:
        print(f"  进度: {event.payload.progress.scanned}/{event.payload.progress.total}")
        
    elif event.event_type == EventType.FILE_SCANNED:
        status = "干净" if event.payload.file.status == FileStatus.CLEAN else "可疑"
        print(f"  文件: {event.payload.file.file_path}, MD5={event.payload.file.md5[:16]}..., 状态={status}")
        
    elif event.event_type == EventType.SCAN_COMPLETED:
        print(f"  完成: 扫描{event.payload.completed.total_scanned}个文件, 发现{event.payload.completed.viruses_found}个病毒")
        
    elif event.event_type == EventType.SCAN_ERROR:
        print(f"  错误: {event.payload.error.error_message}")
```

### 5.4 订阅病毒告警

```python
# 订阅病毒告警（高优先级，即时推送）
request = AlertSubscriptionRequest(
    # threat_levels=[ThreatLevel.HIGH, ThreatLevel.CRITICAL]  # 可选：只订阅高危
)

for alert in client.SubscribeVirusAlerts(request):
    print(f"[病毒告警] {alert.virus_name}")
    print(f"  文件: {alert.file_path}")
    print(f"  MD5: {alert.md5}")
    print(f"  威胁: {alert.threat_level}")
    print(f"  时间: {datetime.fromtimestamp(alert.detected_at/1000)}")
```

### 5.5 完整示例

```python
#!/usr/bin/env python3
"""
终端A示例 - 病毒扫描客户端
"""

import grpc
import uuid
import threading
from datetime import datetime
from virus_scan_pb2 import *
from virus_scan_pb2_grpc import *

AGENT_ADDR = "127.0.0.1:50051"  # 根据环境修改

class VirusScanClient:
    def __init__(self, addr):
        self.channel = grpc.insecure_channel(addr)
        self.stub = VirusScanServiceStub(self.channel)
        self.scan_id = None
        
    def start_scan(self, target_dir, exclude_dirs=None):
        """开始扫描"""
        self.scan_id = str(uuid.uuid4())
        
        command = ScanCommand(
            scan_id=self.scan_id,
            type=CommandType.START_SCAN,
            target=ScanTarget(directory=target_dir),
            exclude_dirs=exclude_dirs or [],
            include_script=True,
            timestamp=int(datetime.now().timestamp() * 1000)
        )
        
        response = self.stub.PublishCommand(ScanCommandRequest(cmd=command))
        print(f"命令已发送: {response.message}")
        return self.scan_id
    
    def stop_scan(self, scan_id):
        """停止扫描"""
        command = ScanCommand(
            scan_id=scan_id,
            type=CommandType.STOP_SCAN,
            timestamp=int(datetime.now().timestamp() * 1000)
        )
        response = self.stub.PublishCommand(ScanCommandRequest(cmd=command))
        print(f"停止命令: {response.message}")
    
    def subscribe_events(self, scan_id, callback):
        """订阅事件（异步）"""
        def run():
            request = EventSubscriptionRequest(scan_id=scan_id)
            for event in self.stub.SubscribeEvents(request):
                callback(event)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread
    
    def subscribe_alerts(self, callback):
        """订阅病毒告警（异步）"""
        def run():
            for alert in self.stub.SubscribeVirusAlerts(AlertSubscriptionRequest()):
                callback(alert)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return thread


def event_callback(event):
    """事件回调"""
    print(f"[事件] {event.event_type}: {event.scan_id}")
    
    if event.event_type == EventType.SCAN_PROGRESS:
        p = event.payload.progress
        print(f"  进度: {p.scanned}/{p.total}, 病毒: {p.viruses_found}")
    
    elif event.event_type == EventType.SCAN_COMPLETED:
        c = event.payload.completed
        print(f"  完成: 扫描{c.total_scanned}个, 病毒{c.viruses_found}")


def alert_callback(alert):
    """告警回调"""
    print(f"\n[!!! 病毒告警 !!!]")
    print(f"  病毒: {alert.virus_name}")
    print(f"  文件: {alert.file_path}")
    print(f"  MD5: {alert.md5}")
    print(f"  威胁: {alert.threat_level}")


if __name__ == "__main__":
    client = VirusScanClient(AGENT_ADDR)
    
    # 开始扫描
    scan_id = client.start_scan("/usr/bin", ["/usr/bin/exclude"])
    print(f"scan_id: {scan_id}")
    
    # 订阅事件
    client.subscribe_events(scan_id, event_callback)
    
    # 订阅告警
    client.subscribe_alerts(alert_callback)
    
    # 保持运行
    try:
        input("按Enter停止...\n")
    except KeyboardInterrupt:
        pass
    
    # 停止扫描
    client.stop_scan(scan_id)
```

### 5.6 其他语言示例

```cpp
// C++ 示例
#include <grpcpp/grpcpp.h>
#include "virus_scan.pb.h"

auto channel = grpc::CreateChannel("127.0.0.1:50051", grpc::InsecureChannelCredentials());
auto stub = VirusScanService::NewStub(channel);

// 发送命令
ScanCommand cmd;
cmd.set_scan_id("xxx");
cmd.set_type(START_SCAN);
cmd.mutable_target()->set_directory("/usr/bin");

ScanCommandRequest req;
*req.mutable_cmd() = cmd;

ScanCommandResponse resp;
stub->PublishCommand(&ctx, &req, &resp);

// 订阅事件
EventSubscriptionRequest sub_req;
sub_req.set_scan_id("xxx");
std::unique_ptr<grpc::ClientReader<ScanEvent>> reader = stub->SubscribeEvents(&ctx, sub_req);

while (reader->Read(&event)) {
    // 处理事件
}
```

```go
// Go 示例
conn, _ := grpc.Dial("127.0.0.1:50051", grpc.WithInsecure())
client := pb.NewVirusScanServiceClient(conn)

// 发送命令
cmd := &pb.ScanCommand{
    ScanId: "xxx",
    Type: pb.CommandType_START_SCAN,
    Target: &pb.ScanTarget{
        Directory: "/usr/bin",
    },
}
resp, _ := client.PublishCommand(context.Background(), &pb.ScanCommandRequest{Cmd: cmd})

// 订阅事件
stream, _ := client.SubscribeEvents(context.Background(), &pb.EventSubscriptionRequest{ScanId: "xxx"})
for {
    event, err := stream.Recv()
    // 处理事件
}
```

---

## 6. 核心实现

### 6.1 EventBus

```rust
// crates/virus_scan_grpc/src/event_bus.rs

use tokio::sync::broadcast;
use std::sync::Arc;

#[derive(Clone)]
pub struct EventBus {
    // ScanCommand Topic
    cmd_tx: Arc<broadcast::Sender<super::proto::ScanCommand>>,
    // ScanEvent Topic
    event_tx: Arc<broadcast::Sender<super::proto::ScanEvent>>,
    // VirusAlert Topic
    alert_tx: Arc<broadcast::Sender<super::proto::VirusAlert>>,
    // FileMd5Info Topic (内部)
    md5_tx: Arc<broadcast::Sender<super::proto::FileMd5Info>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            cmd_tx: Arc::new(broadcast::channel(64).0),
            event_tx: Arc::new(broadcast::channel(256).0),
            alert_tx: Arc::new(broadcast::channel(128).0),
            md5_tx: Arc::new(broadcast::channel(512).0),
        }
    }

    // ===== Topic: scan_command =====

    pub fn publish_cmd(&self, cmd: super::proto::ScanCommand) {
        let _ = self.cmd_tx.send(cmd);
    }

    pub fn subscribe_cmd(&self) -> broadcast::Receiver<super::proto::ScanCommand> {
        self.cmd_tx.subscribe()
    }

    // ===== Topic: scan_event =====

    pub fn publish_event(&self, event: super::proto::ScanEvent) {
        let _ = self.event_tx.send(event);
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<super::proto::ScanEvent> {
        self.event_tx.subscribe()
    }

    // ===== Topic: virus_alert =====

    pub fn publish_alert(&self, alert: super::proto::VirusAlert) {
        let _ = self.alert_tx.send(alert);
    }

    pub fn subscribe_alerts(&self) -> broadcast::Receiver<super::proto::VirusAlert> {
        self.alert_tx.subscribe()
    }

    // ===== Topic: file_md5 (内部) =====

    pub fn publish_md5(&self, md5: super::proto::FileMd5Info) {
        let _ = self.md5_tx.send(md5);
    }

    pub fn subscribe_md5(&self) -> broadcast::Receiver<super::proto::FileMd5Info> {
        self.md5_tx.subscribe()
    }
}
```

### 6.2 扫描任务管理器

```rust
// crates/virus_scan_grpc/src/scan_task_mgr.rs

use crate::event_bus::EventBus;
use crate::proto::{ScanCommand, ScanEvent, FileMd5Info};
use futures::stream::StreamExt;
use logging::{log_info, log_error};
use process_mgr::get_md5_global;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

const SCAN_STATE_IDLE: u8 = 0;
const SCAN_STATE_RUNNING: u8 = 1;
const SCAN_STATE_STOPPED: u8 = 2;
const SCAN_STATE_COMPLETED: u8 = 3;

pub struct ScanTaskManager {
    event_bus: Arc<EventBus>,
    tasks: Arc<Mutex<HashMap<String, Arc<ScanTask>>>>,
    net_client: NetClient,
    server_b_url: String,
    batch_size: usize,
}

struct ScanTask {
    scan_id: String,
    target: String,
    exclude: Vec<String>,
    state: AtomicU8,
    scanned: AtomicU32,
    viruses: AtomicU32,
}

impl ScanTask {
    fn new(scan_id: String, target: String) -> Self {
        Self {
            scan_id,
            target,
            exclude: Vec::new(),
            state: AtomicU8::new(SCAN_STATE_IDLE),
            scanned: AtomicU32::new(0),
            viruses: AtomicU32::new(0),
        }
    }

    fn start(&self) {
        self.state.store(SCAN_STATE_RUNNING, Ordering::Relaxed);
    }

    fn stop(&self) {
        self.state.store(SCAN_STATE_STOPPED, Ordering::Relaxed);
    }

    fn is_running(&self) -> bool {
        self.state.load(Ordering::Relaxed) == SCAN_STATE_RUNNING
    }
}

impl ScanTaskManager {
    pub fn new(event_bus: Arc<EventBus>, net_client: NetClient, server_b_url: String) -> Self {
        Self {
            event_bus,
            tasks: Arc::new(Mutex::new(HashMap::new())),
            net_client,
            server_b_url,
            batch_size: 100,
        }
    }

    pub async fn run(&self) {
        log_info!("扫描任务管理器启动");
        let mut cmd_rx = self.event_bus.subscribe_cmd();

        while let Ok(cmd) = cmd_rx.recv().await {
            match cmd.type {
                crate::proto::CommandType::START_SCAN => {
                    if let Some(target) = cmd.target {
                        self.handle_start_scan(&cmd.scan_id, target, cmd.exclude_dirs).await;
                    }
                }
                crate::proto::CommandType::STOP_SCAN => {
                    self.handle_stop_scan(&cmd.scan_id).await;
                }
                _ => {}
            }
        }
    }

    async fn handle_start_scan(&self, scan_id: &str, target: crate::proto::ScanTarget, exclude: Vec<String>) {
        let target_str = match target.target {
            Some(crate::proto::scan_target::Target::Directory(d)) => d,
            Some(crate::proto::scan_target::Target::FullDisk(_)) => "/".to_string(),
            None => return,
        };

        let task = Arc::new(ScanTask::new(scan_id.to_string(), target_str));
        task.start();
        task.exclude = exclude;

        let mut tasks = self.tasks.lock().await;
        tasks.insert(scan_id.to_string(), task.clone());

        log_info!("开始扫描: scan_id={}, target={}", scan_id, target_str);

        // 发布开始事件
        self.event_bus.publish_event(ScanEvent {
            scan_id: scan_id.to_string(),
            event_type: crate::proto::EventType::SCAN_STARTED as i32,
            payload: Some(crate::proto::scan_event::Payload::Started(
                crate::proto::StartedPayload {
                    target: target_str.clone(),
                    estimated_files: 0,
                }
            )),
            timestamp: chrono::Utc::now().timestamp_millis(),
        });

        // 异步执行扫描
        let event_bus = self.event_bus.clone();
        let task = task.clone();
        tokio::spawn(async move {
            Self::execute_scan(scan_id, &target_str, &task, &event_bus).await;
        });
    }

    async fn handle_stop_scan(&self, scan_id: &str) {
        let tasks = self.tasks.lock().await;
        if let Some(task) = tasks.get(scan_id) {
            task.stop();
            log_info!("扫描已停止: {}", scan_id);

            self.event_bus.publish_event(ScanEvent {
                scan_id: scan_id.to_string(),
                event_type: crate::proto::EventType::SCAN_COMPLETED as i32,
                payload: Some(crate::proto::scan_event::Payload::Completed(
                    crate::proto::CompletedPayload {
                        total_scanned: task.scanned.load(Ordering::Relaxed) as i32,
                        viruses_found: task.viruses.load(Ordering::Relaxed) as i32,
                        duration_ms: 0,
                    }
                )),
                timestamp: chrono::Utc::now().timestamp_millis(),
            });
        }
    }

    async fn execute_scan(scan_id: &str, target: &str, task: &Arc<ScanTask>, event_bus: &Arc<EventBus>) {
        let path = Path::new(target);
        if !path.exists() || !path.is_dir() {
            log_error!("目录不存在: {}", target);
            return;
        }

        let mut batch: Vec<FileMd5Info> = Vec::new();
        let mut entries = match fs::read_dir(path).await {
            Ok(e) => e,
            Err(e) => {
                log_error!("打开目录失败 {}: {}", target, e);
                return;
            }
        };

        while let Some(entry) = entries.next_entry().await.ok().flatten() {
            if !task.is_running() {
                break;
            }

            let file_path = entry.path().to_string_lossy().to_string();
            if file_path.ends_with("/.") || file_path.ends_with("/..") {
                continue;
            }

            // 跳过排除目录
            let excluded = task.exclude.iter().any(|e| file_path.starts_with(e));
            if excluded {
                continue;
            }

            // 跳过目录
            if entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }

            // 计算MD5
            let md5 = match get_md5_global(&file_path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            let md5_info = FileMd5Info {
                scan_id: scan_id.to_string(),
                file_path: file_path.clone(),
                md5,
                timestamp: chrono::Utc::now().timestamp_millis(),
            };

            batch.push(md5_info);

            // 批量处理
            if batch.len() >= 100 {
                Self::check_batch(&batch, task, event_bus).await;
                batch.clear();
            }
        }

        // 处理剩余
        if !batch.is_empty() {
            Self::check_batch(&batch, task, event_bus).await;
        }

        // 扫描完成
        task.scanned.store(batch.len() as u32, Ordering::Relaxed);
        event_bus.publish_event(ScanEvent {
            scan_id: scan_id.to_string(),
            event_type: crate::proto::EventType::SCAN_COMPLETED as i32,
            payload: Some(crate::proto::scan_event::Payload::Completed(
                crate::proto::CompletedPayload {
                    total_scanned: task.scanned.load(Ordering::Relaxed) as i32,
                    viruses_found: task.viruses.load(Ordering::Relaxed) as i32,
                    duration_ms: 0,
                }
            )),
            timestamp: chrono::Utc::now().timestamp_millis(),
        });
    }

    async fn check_batch(batch: &[FileMd5Info], task: &Arc<ScanTask>, event_bus: &Arc<EventBus>) {
        // 发送MD5到服务器B检测
        // ... 复用net_client发送HTTP请求 ...
        // 根据结果发布事件和告警
    }
}
```

### 6.3 gRPC服务

```rust
// crates/virus_scan_grpc/src/grpc_service.rs

use crate::event_bus::EventBus;
use crate::proto::*;
use futures::stream::Stream;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};

pub struct VirusScanGrpcService {
    event_bus: Arc<EventBus>,
}

impl VirusScanGrpcService {
    pub fn new(event_bus: Arc<EventBus>) -> Self {
        Self { event_bus }
    }

    async fn publish_command(
        &self,
        request: Request<ScanCommandRequest>,
    ) -> Result<Response<ScanCommandResponse>, Status> {
        let cmd = request.into_inner().cmd.ok_or(Status::invalid_argument("缺少命令"))?;
        self.event_bus.publish_cmd(cmd.clone());

        Ok(Response::new(ScanCommandResponse {
            success: true,
            message: "命令已接收".to_string(),
            scan_id: cmd.scan_id,
        }))
    }

    async fn subscribe_events(
        &self,
        request: Request<EventSubscriptionRequest>,
    ) -> Result<Response<Pin<Box<dyn Stream<Item = Result<ScanEvent, Status>> + Send>>>, Status> {
        let req = request.into_inner();
        let mut rx = self.event_bus.subscribe_events();
        let (tx, stream) = mpsc::channel(128);

        tokio::spawn(async move {
            while let Ok(event) = rx.recv().await {
                // 过滤
                if let Some(filter_id) = req.scan_id {
                    if event.scan_id != filter_id {
                        continue;
                    }
                }

                if tx.send(Ok(event)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(Box::pin(stream) as _))
    }

    async fn subscribe_alerts(
        &self,
        _request: Request<AlertSubscriptionRequest>,
    ) -> Result<Response<Pin<Box<dyn Stream<Item = Result<VirusAlert, Status>> + Send>>>, Status> {
        let mut rx = self.event_bus.subscribe_alerts();
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

// tonic代码生成会自动添加service实现
```

---

## 7. 集成到main.rs

```rust
// crates/main/src/main.rs

use virus_scan_grpc::{
    EventBus, ScanTaskManager, VirusScanGrpcService,
    proto::virus_scan_service_server::VirusScanServiceServer,
};
use std::sync::Arc;
use tokio::spawn;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // ... 现有代码 ...

    // 新增：病毒扫描服务
    let cfg = NETINFO_CONFIG.lock().unwrap();
    if cfg.virus_scan.enabled {
        let event_bus = Arc::new(EventBus::new());
        let net_client = NetClient::new(Some(base_url), true)?;
        let server_b_url = cfg.virus_scan.server_b_url.clone();
        let batch_size = cfg.virus_scan.batch_size;
        let http_timeout = cfg.virus_scan.http_timeout_secs;

        // 启动扫描任务管理器
        let task_mgr = Arc::new(ScanTaskManager::new(
            event_bus.clone(),
            net_client.clone(),
            server_b_url,
        ));
        spawn({
            let task_mgr = task_mgr.clone();
            async move {
                task_mgr.run().await;
            }
        });

        // 启动gRPC服务
        let grpc_addr = if cfg.virus_scan.dev_mode {
            &cfg.virus_scan.dev_grpc_addr
        } else {
            &cfg.virus_scan.grpc_addr
        };

        let grpc_service = VirusScanGrpcService::new(event_bus.clone());
        spawn({
            let grpc_service = grpc_service.clone();
            async move {
                let addr: std::net::SocketAddr = grpc_addr.parse().unwrap();
                tonic::builder::ServerBuilder::new()
                    .add_service(VirusScanServiceServer::new(grpc_service))
                    .serve(addr)
                    .await
                    .unwrap();
            }
        });

        log_info!("病毒扫描服务已启动: {}", grpc_addr);
    }

    // ... 等待退出 ...
}
```

---

## 8. 流程图

### 8.1 扫描流程

```
终端A                          Agent                         服务器B
  │                             │                               │
  │── PublishCommand ─────────▶│                               │
  │  StartScan {               │                               │
  │    scan_id: "uuid",        │                               │
  │    target: "/usr/bin"      │                               │
  │  }                         │                               │
  │                             │                               │
  │                             │── 遍历目录 ──────────────────▶│
  │                             │   计算每个文件MD5              │
  │                             │                               │
  │                             │── POST批量MD5 ───────────────▶│
  │                             │   [{"path":"...","md5":"..."}]│
  │                             │                               │
  │                             │◄── 病毒结果 ──────────────────│
  │                             │   [{"path":"...","is_virus":true}]│
  │                             │                               │
  │◀── SubscribeEvents ────────│                               │
  │  ScanEvent {               │                               │
  │    scan_id: "uuid",        │                               │
  │    type: PROGRESS,         │                               │
  │    scanned: 100            │                               │
  │  }                         │                               │
  │                             │                               │
  │◀── VirusAlert ─────────────│                               │
  │  {                        │                               │
  │    file_path: "/bin/ls",  │                               │
  │    virus_name: "Trojan"   │                               │
  │  }                        │                               │
  │                             │                               │
  │◀── ScanEvent(Completed) ────│                               │
  │  {total_scanned: 500}      │                               │
```

### 8.2 Topic流程

```
┌─────────────────────────────────────────────────────────────┐
│                        EventBus                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   【scan_command】                                            │
│   ┌─────────┐     ┌─────────┐     ┌─────────┐              │
│   │ 终端A   │────▶│  Topic  │────▶│ScanTask │              │
│   │ (发布)  │     │ Router  │     │ Manager │              │
│   └─────────┘     └─────────┘     └────┬────┘              │
│                                        │                     │
│   【scan_event】                        ▼                     │
│   ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌──────┐ │
│   │FileScan│────▶│  Topic  │────▶│ 终端A   │────▶│ 终端B│ │
│   │   ner   │     │ Router  │     │ (订阅)  │     │      │ │
│   └─────────┘     └─────────┘     └─────────┘     └──────┘ │
│                                                              │
│   【virus_alert】                                             │
│   ┌─────────┐     ┌─────────┐     ┌─────────┐              │
│   │Virus   │────▶│  Topic  │────▶│ 终端A   │              │
│   │Checker │     │ Router  │     │ (订阅)  │              │
│   └─────────┘     └─────────┘     └─────────┘              │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 9. 总结

| 项目 | 说明 |
|------|------|
| **开发模式** | `dev_mode=true` → 监听 `0.0.0.0:50051` (对外) |
| **生产模式** | `dev_mode=false` → 监听 `127.0.0.1:50051` (仅本地) |
| **Topic** | scan_command, scan_event, virus_alert, file_md5 |
| **无需认证** | localhost安全可控 |
| **多语言支持** | Python/C++/Go/Java等 |

---

## 附录：服务器B接口格式

```
POST {server_b_url}/v1/scan/batch

请求体:
{
    "scan_id": "uuid-xxx",
    "items": [
        {"file_path": "/bin/ls", "md5": "abc123..."},
        {"file_path": "/bin/cp", "md5": "def456..."}
    ]
}

响应体:
{
    "results": [
        {
            "file_path": "/bin/ls",
            "md5": "abc123...",
            "is_virus": true,
            "virus_name": "Trojan.Generic",
            "threat_level": "HIGH"
        }
    ]
}
```
