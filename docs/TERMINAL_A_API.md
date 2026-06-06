# 终端A开发者接口说明

> 本文档描述Agent病毒扫描服务的gRPC接口，与编程语言无关。

---

## 目录

1. [接口概览](#1-接口概览)
2. [连接方式](#2-连接方式)
3. [接口详情](#3-接口详情)
4. [Topic说明](#4-topic说明)
5. [数据类型](#5-数据类型)
6. [交互流程](#6-交互流程)
7. [错误码](#7-错误码)
8. [协议文件](#8-协议文件)

---

## 1. 接口概览

### 1.1 服务地址

| 环境 | 地址 | 说明 |
|------|------|------|
| 开发环境 | `0.0.0.0:50051` | Agent需配置`dev_mode=true` |
| 生产环境 | `127.0.0.1:50051` | 仅本地访问 |

### 1.2 gRPC服务

```
Service: VirusScanService
Methods:
  1. PublishCommand      // 发布扫描命令 (A → Agent)
  2. SubscribeEvents     // 订阅扫描事件 (Agent → A)
  3. SubscribeVirusAlerts // 订阅病毒告警 (Agent → A)
  4. GetScanStatus       // 查询扫描状态 (A → Agent)
```

### 1.3 通信模式

```
终端A                                    Agent
  │                                        │
  │  ── PublishCommand (请求/响应) ───────▶│  开始扫描
  │                                        │
  │                              ┌─────────▼─────────┐
  │                              │  执行扫描         │
  │                              │  - 遍历目录       │
  │                              │  - 计算MD5       │
  │                              │  - 询问B         │
  │                              └─────────┬─────────┘
  │                                        │
  │◀── SubscribeEvents (流式推送) ─────────│  进度/结果
  │                                        │
  │◀── SubscribeVirusAlerts (流式推送) ────│  病毒告警
```

---

## 2. 连接方式

### 2.1 连接参数

| 参数 | 值 |
|------|-----|
| 协议 | gRPC over TCP |
| 认证 | 无 |
| TLS | 无 |

### 2.2 连接示例

```
# gRPC地址格式
<ip>:<port>

# 开发环境 (远程连接)
192.168.1.100:50051

# 生产环境 (本地连接)
127.0.0.1:50051
```

### 2.3 连接要求

- 使用gRPC框架（各语言均有实现）
- 支持双向流（Server Streaming）
- 无需认证
- 无需TLS

---

## 3. 接口详情

### 3.1 PublishCommand - 发布扫描命令

**方向**: 终端A → Agent

**功能**: 发送扫描命令（开始/停止）

**请求**:

```json
{
  "cmd": {
    "scan_id": "string",           // 任务ID，客户端生成
    "type": "START_SCAN | STOP_SCAN",  // 命令类型
    "target": {                     // 扫描目标 (START_SCAN时必填)
      "directory": "string" OR
      "full_disk": true
    },
    "exclude_dirs": ["string"],     // 排除目录
    "include_script": true,        // 是否包含脚本
    "timestamp": 1234567890         // 时间戳(毫秒)
  }
}
```

**响应**:

```json
{
  "success": true,
  "message": "string",
  "scan_id": "string"
}
```

**示例流程**:

```
1. 客户端生成scan_id: "a1b2c3d4-e5f6-7890-1234-567890abcdef"
2. 发送PublishCommand请求
3. 接收响应
4. 用此scan_id订阅事件
```

---

### 3.2 SubscribeEvents - 订阅扫描事件

**方向**: Agent → 终端A (Server Streaming)

**功能**: 接收扫描过程的事件推送

**请求**:

```json
{
  "scan_id": "string (可选)",        // 空=订阅所有，可指定
  "event_types": [1, 2, 3]          // 可选，筛选事件类型
}
```

**响应 (流式)**:

```json
{
  "scan_id": "string",
  "event_type": "SCAN_STARTED | SCAN_PROGRESS | FILE_SCANNED | SCAN_COMPLETED | SCAN_ERROR",
  "payload": { /* 事件数据 */ },
  "timestamp": 1234567890
}
```

**事件类型**:

| 值 | 名称 | 说明 | payload |
|----|------|------|---------|
| 0 | SCAN_STARTED | 开始扫描 | target, estimated_files |
| 1 | SCAN_PROGRESS | 进度 | scanned, total, viruses_found |
| 2 | FILE_SCANNED | 单文件完成 | file_path, md5, status |
| 3 | SCAN_COMPLETED | 扫描完成 | total_scanned, viruses_found, duration_ms |
| 4 | SCAN_ERROR | 错误 | error_code, error_message |

**payload详情**:

```json
// SCAN_STARTED
{
  "target": "/usr/bin",
  "estimated_files": 500
}

// SCAN_PROGRESS
{
  "scanned": 100,
  "total": 500,
  "viruses_found": 2
}

// FILE_SCANNED
{
  "file_path": "/usr/bin/ls",
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "status": 0  // 0=CLEAN, 1=SUSPICIOUS, 2=ERROR
}

// SCAN_COMPLETED
{
  "total_scanned": 500,
  "viruses_found": 2,
  "duration_ms": 5000
}

// SCAN_ERROR
{
  "error_code": "ERR_001",
  "error_message": "目录不存在"
}
```

---

### 3.3 SubscribeVirusAlerts - 订阅病毒告警

**方向**: Agent → 终端A (Server Streaming)

**功能**: 接收病毒告警（高优先级，即时推送）

**请求**:

```json
{
  "threat_levels": [2, 3]  // 可选，筛选威胁等级
}
```

**威胁等级**:

| 值 | 名称 | 说明 |
|----|------|------|
| 0 | LOW | 低危 |
| 1 | MEDIUM | 中危 |
| 2 | HIGH | 高危 |
| 3 | CRITICAL | 严重 |

**响应 (流式)**:

```json
{
  "scan_id": "string",
  "file_path": "/bin/suspicious",
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "virus_name": "Trojan.Generic",
  "threat_level": 2,
  "detected_at": 1234567890,
  "description": "string"
}
```

---

### 3.4 GetScanStatus - 查询扫描状态

**方向**: 终端A → Agent

**功能**: 查询当前扫描任务状态

**请求**:

```json
{
  "scan_id": "string (可选)"   // 空=查询所有
}
```

**响应**:

```json
{
  "scans": [
    {
      "scan_id": "string",
      "target": "/usr/bin",
      "state": 1,              // 0=IDLE, 1=RUNNING, 2=PAUSED, 3=STOPPED, 4=COMPLETED
      "scanned": 100,
      "viruses": 2,
      "start_time": 1234567890
    }
  ]
}
```

---

## 4. Topic说明

### 4.1 Topic列表

```
EventBus包含以下Topic：

【发布】scan_command
  发布者: 终端A
  订阅者: ScanTaskManager
  消息: ScanCommand (扫描命令)

【订阅】scan_event
  发布者: ScanTaskManager, VirusChecker
  订阅者: 终端A
  消息: ScanEvent (扫描事件)

【订阅】virus_alert
  发布者: VirusChecker
  订阅者: 终端A
  消息: VirusAlert (病毒告警)
```

### 4.2 Topic消息流

```
终端A ──PublishCommand(scan_command)──▶ EventBus ──▶ ScanTaskManager
                                                    │
                                                    ▼
                                             执行扫描/计算MD5
                                                    │
                                                    ▼
                                            PublishEvent(scan_event) ──▶ 终端A
                                                    │
                                                    ▼
                                            PublishFileMd5 ──▶ VirusChecker
                                                    │
                                                    ▼
                                            PublishAlert(virus_alert) ──▶ 终端A
```

---

## 5. 数据类型

### 5.1 枚举类型

**CommandType (命令类型)**:

| 名称 | 值 | 说明 |
|------|-----|------|
| START_SCAN | 0 | 开始扫描 |
| STOP_SCAN | 1 | 停止扫描 |

**EventType (事件类型)**:

| 名称 | 值 | 说明 |
|------|-----|------|
| SCAN_STARTED | 0 | 扫描开始 |
| SCAN_PROGRESS | 1 | 扫描进度 |
| FILE_SCANNED | 2 | 单文件完成 |
| SCAN_COMPLETED | 3 | 扫描完成 |
| SCAN_ERROR | 4 | 扫描错误 |

**FileStatus (文件状态)**:

| 名称 | 值 | 说明 |
|------|-----|------|
| CLEAN | 0 | 干净 |
| SUSPICIOUS | 1 | 可疑 |
| ERROR | 2 | 错误 |

**ThreatLevel (威胁等级)**:

| 名称 | 值 | 说明 |
|------|-----|------|
| LOW | 0 | 低危 |
| MEDIUM | 1 | 中危 |
| HIGH | 2 | 高危 |
| CRITICAL | 3 | 严重 |

**ScanState (扫描状态)**:

| 名称 | 值 | 说明 |
|------|-----|------|
| IDLE | 0 | 空闲 |
| RUNNING | 1 | 运行中 |
| PAUSED | 2 | 已暂停 |
| STOPPED | 3 | 已停止 |
| COMPLETED | 4 | 已完成 |

---

## 6. 交互流程

### 6.1 完整扫描流程

```
┌─────────────────────────────────────────────────────────────────────┐
│ 步骤1: 开始扫描                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   终端A                                                              │
│     │                                                               │
│     │ 1. 生成scan_id (UUID)                                         │
│     │                                                               │
│     │ 2. 发送 PublishCommand {                                      │
│     │      scan_id: "a1b2c3d4-e5f6-7890-1234-567890abcdef",      │
│     │      type: START_SCAN,                                        │
│     │      target: { directory: "/usr/bin" }                        │
│     │    }                                                          │
│     │                                                               │
│     ▼                                                               │
│   Agent                                                              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 步骤2: 订阅事件                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   终端A                                                              │
│     │                                                               │
│     │ 3. 建立 SubscribeEvents 流                                    │
│     │    请求: { scan_id: "a1b2c3d4-e5f6-7890-1234-567890abcdef" }│
│     │                                                               │
│     │ 4. 建立 SubscribeVirusAlerts 流                               │
│     │    请求: { threat_levels: [2, 3] }  // 可选                   │
│     │                                                               │
│     ▼                                                               │
│   Agent (流式推送)                                                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 步骤3: 扫描执行                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Agent                                                              │
│     │                                                               │
│     │ 5. ◀─── ScanEvent {                                         │
│     │        scan_id: "a1b2c3d4-e5f6-7890-1234-567890abcdef",      │
│     │        event_type: SCAN_STARTED,                              │
│     │        payload: { target: "/usr/bin" }                       │
│     │      }                                                        │
│     │                                                               │
│     │ 6. 遍历目录，计算每个文件的MD5                                 │
│     │                                                               │
│     │ 7. ◀─── ScanEvent {                                         │
│     │        event_type: SCAN_PROGRESS,                            │
│     │        payload: { scanned: 100, total: 500, viruses_found: 0 }│
│     │      }                                                        │
│     │                                                               │
│     │ 8. ◀─── ScanEvent {                                         │
│     │        event_type: FILE_SCANNED,                             │
│     │        payload: {                                            │
│     │          file_path: "/usr/bin/ls",                           │
│     │          md5: "d41d8cd98f00b204e9800998ecf8427e",           │
│     │          status: CLEAN                                        │
│     │        }                                                      │
│     │      }                                                        │
│     │                                                               │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 步骤4: 病毒检测                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Agent ───HTTP POST──▶ 服务器B                                      │
│   POST /v1/scan/batch                                               │
│   Body: {                                                          │
│     scan_id: "a1b2c3d4-e5f6-7890-1234-567890abcdef",              │
│     items: [                                                        │
│       { file_path: "/usr/bin/ls", md5: "d41d8cd..." },             │
│       { file_path: "/usr/bin/cp", md5: "a1b2c3..." }              │
│     ]                                                               │
│   }                                                                 │
│                                                                     │
│   Agent ◀──HTTP响应── 服务器B                                        │
│   Body: {                                                          │
│     results: [                                                       │
│       { file_path: "/usr/bin/suspicious", is_virus: true,           │
│         virus_name: "Trojan.Generic", threat_level: "HIGH" }        │
│     ]                                                               │
│   }                                                                 │
│                                                                     │
│   Agent ◀── VirusAlert {                                            │
│          scan_id: "a1b2c3d4-e5f6-7890-1234-567890abcdef",          │
│          file_path: "/usr/bin/suspicious",                          │
│          md5: "c3d4e5f6...",                                       │
│          virus_name: "Trojan.Generic",                              │
│          threat_level: HIGH                                         │
│        }                                                            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 步骤5: 扫描完成                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Agent ◀── ScanEvent {                                            │
│          scan_id: "a1b2c3d4-e5f6-7890-1234-567890abcdef",          │
│          event_type: SCAN_COMPLETED,                                │
│          payload: {                                                  │
│            total_scanned: 500,                                       │
│            viruses_found: 2,                                         │
│            duration_ms: 5234                                         │
│          }                                                          │
│        }                                                            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 6.2 时序图

```
终端A                              Agent                          服务器B
  │                                  │                              │
  │1. PublishCommand                 │                              │
  │   {START_SCAN, dir="/usr/bin"}  │                              │
  │                                  │                              │
  │                                  │── 扫描 /usr/bin ────────────▶│
  │                                  │   计算MD5                     │
  │                                  │                              │
  │◀──2. ScanEvent(STARTED) ────────│                              │
  │                                  │                              │
  │3. SubscribeEvents ──────────────▶│                              │
  │                                  │                              │
  │◀──4. ScanEvent(PROGRESS) ───────│                              │
  │   {scanned: 100, total: 500}    │                              │
  │                                  │                              │
  │◀──5. ScanEvent(FILE_SCANNED) ───│                              │
  │   {file: "/usr/bin/ls", CLEAN}  │                              │
  │                                  │                              │
  │                                  │── POST /v1/scan/batch ─────▶│
  │                                  │   {items: [...]}             │
  │                                  │                              │
  │                                  │◀── results ─────────────────│
  │                                  │                              │
  │◀──6. VirusAlert ─────────────────│                              │
  │   {virus: "Trojan.Generic"}      │                              │
  │                                  │                              │
  │◀──7. ScanEvent(COMPLETED) ──────│                              │
  │   {total: 500, viruses: 2}       │                              │
```
┌─────────────────────────────────────────────────────────────────────┐
│ 步骤1: 开始扫描                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   终端A                                                              │
│     │                                                               │
│     │ 1. 生成scan_id (UUID)                                         │
│     │                                                               │
│     │ 2. 发送 PublishCommand {                                      │
│     │      scan_id: "xxx",                                         │
│     │      type: START_SCAN,                                        │
│     │      target: { directory: "/usr/bin" }                        │
│     │    }                                                          │
│     │                                                               │
│     ▼                                                               │
│   Agent                                                              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 步骤2: 订阅事件                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   终端A                                                              │
│     │                                                               │
│     │ 3. 建立 SubscribeEvents 流                                    │
│     │    请求: { scan_id: "xxx" }                                   │
│     │                                                               │
│     │ 4. 建立 SubscribeVirusAlerts 流                               │
│     │    请求: { threat_levels: [2, 3] }  // 可选                   │
│     │                                                               │
│     ▼                                                               │
│   Agent (流式推送)                                                   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 步骤3: 扫描执行                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Agent                                                              │
│     │                                                               │
│     │ 5. ◀─── ScanEvent {                                         │
│     │        event_type: SCAN_STARTED,                             │
│     │        payload: { target: "/usr/bin" }                       │
│     │      }                                                        │
│     │                                                               │
│     │ 6. 遍历目录，计算每个文件的MD5                                 │
│     │                                                               │
│     │ 7. ◀─── ScanEvent {                                         │
│     │        event_type: SCAN_PROGRESS,                            │
│     │        payload: { scanned: 100, total: 500 }                  │
│     │      }                                                        │
│     │                                                               │
│     │ 8. ◀─── ScanEvent {                                         │
│     │        event_type: FILE_SCANNED,                             │
│     │        payload: {                                            │
│     │          file_path: "/usr/bin/ls",                           │
│     │          md5: "d41d8cd98f00b204...",                        │
│     │          status: CLEAN                                        │
│     │        }                                                      │
│     │      }                                                        │
│     │                                                               │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 步骤4: 病毒检测                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Agent ───HTTP POST──▶ 服务器B                                      │
│   请求: {                                                           │
│     scan_id: "xxx",                                                │
│     items: [                                                        │
│       { file_path: "/usr/bin/ls", md5: "..." },                     │
│       { file_path: "/usr/bin/cp", md5: "..." }                     │
│     ]                                                               │
│   }                                                                 │
│                                                                     │
│   Agent ◀──HTTP响应── 服务器B                                         │
│   响应: {                                                           │
│     results: [                                                      │
│       { file_path: "/usr/bin/suspicious", is_virus: true }          │
│     ]                                                               │
│   }                                                                 │
│                                                                     │
│   Agent ◀── VirusAlert {                                            │
│          scan_id: "xxx",                                            │
│          file_path: "/usr/bin/suspicious",                          │
│          virus_name: "Trojan.Generic",                              │
│          threat_level: HIGH                                         │
│        }                                                            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 步骤5: 扫描完成                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Agent ◀── ScanEvent {                                            │
│          event_type: SCAN_COMPLETED,                                │
│          payload: {                                                 │
│            total_scanned: 500,                                      │
│            viruses_found: 2,                                        │
│            duration_ms: 5000                                        │
│          }                                                          │
│        }                                                            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 6.2 时序图

```
终端A                              Agent                          服务器B
  │                                  │                              │
  │── PublishCommand ───────────────▶│                              │
  │  {START_SCAN, dir="/usr/bin"}   │                              │
  │                                  │                              │
  │                                  │── 扫描 /usr/bin ───────────▶│
  │                                  │   计算MD5                     │
  │                                  │                              │
  │◀── ScanEvent(STARTED) ─────────│                              │
  │                                  │                              │
  │                                  │── POST /v1/scan/batch ─────▶│
  │                                  │   {items: [...]}            │
  │                                  │                              │
  │                                  │◀── results ─────────────────│
  │                                  │                              │
  │◀── VirusAlert ──────────────────│                              │
  │  {virus_name: "Trojan"}          │                              │
  │                                  │                              │
  │◀── ScanEvent(COMPLETED) ────────│                              │
  │  {total_scanned: 500}           │                              │
```

---

## 7. 错误码

### 7.1 gRPC状态码

| 状态码 | 名称 | 说明 |
|--------|------|------|
| 0 | OK | 成功 |
| 3 | INVALID_ARGUMENT | 参数错误 |
| 5 | NOT_FOUND | scan_id不存在 |
| 7 | UNAVAILABLE | 服务不可用 |
| 1 | CANCELLED | 连接取消 |

### 7.2 应用错误码 (ScanEvent.error_code)

| 错误码 | 说明 |
|--------|------|
| ERR_001 | 目录不存在 |
| ERR_002 | 无权限访问 |
| ERR_003 | 扫描任务不存在 |
| ERR_004 | 扫描已被停止 |
| ERR_500 | 服务器内部错误 |

---

## 8. 协议文件

### 8.1 proto文件

```protobuf
syntax = "proto3";

package virus_scan;

service VirusScanService {
    rpc PublishCommand(ScanCommandRequest) returns (ScanCommandResponse);
    rpc SubscribeEvents(EventSubscriptionRequest) returns (stream ScanEvent);
    rpc SubscribeVirusAlerts(AlertSubscriptionRequest) returns (stream VirusAlert);
    rpc GetScanStatus(StatusRequest) returns (StatusResponse);
}

// ========== 命令 ==========

message ScanCommandRequest {
    ScanCommand cmd = 1;
}

message ScanCommandResponse {
    bool success = 1;
    string message = 2;
    string scan_id = 3;
}

message ScanCommand {
    string scan_id = 1;
    int32 type = 2;          // CommandType
    ScanTarget target = 3;
    int64 timestamp = 4;
}

message ScanTarget {
    oneof target {
        string directory = 1;
        bool full_disk = 2;
    }
    repeated string exclude_dirs = 3;
    bool include_script = 4;
}

// ========== 事件 ==========

message EventSubscriptionRequest {
    optional string scan_id = 1;
    repeated int32 event_types = 2;
}

message ScanEvent {
    string scan_id = 1;
    int32 event_type = 2;    // EventType
    EventPayload payload = 3;
    int64 timestamp = 4;
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
    int32 status = 3;       // FileStatus
}

// ========== 告警 ==========

message AlertSubscriptionRequest {
    repeated int32 threat_levels = 1;
}

message VirusAlert {
    string scan_id = 1;
    string file_path = 2;
    string md5 = 3;
    string virus_name = 4;
    int32 threat_level = 5;  // ThreatLevel
    int64 detected_at = 6;
    string description = 7;
}

// ========== 状态 ==========

message StatusRequest {
    optional string scan_id = 1;
}

message StatusResponse {
    repeated ScanStatusItem scans = 1;
}

message ScanStatusItem {
    string scan_id = 1;
    string target = 2;
    int32 state = 3;         // ScanState
    int32 scanned = 4;
    int32 viruses = 5;
    int64 start_time = 6;
}

// ========== 枚举 ==========

enum CommandType { START_SCAN = 0; STOP_SCAN = 1; }
enum EventType { SCAN_STARTED = 0; SCAN_PROGRESS = 1; FILE_SCANNED = 2; SCAN_COMPLETED = 3; SCAN_ERROR = 4; }
enum FileStatus { CLEAN = 0; SUSPICIOUS = 1; ERROR = 2; }
enum ThreatLevel { LOW = 0; MEDIUM = 1; HIGH = 2; CRITICAL = 3; }
enum ScanState { IDLE = 0; RUNNING = 1; PAUSED = 2; STOPPED = 3; COMPLETED = 4; }
```

---

## 9. 接口调用实例

> 以下展示各接口的具体调用示例，开发者可据此参考实现

### 9.1 实例1：终端A发布扫描指定目录

```
场景：终端A要让Agent扫描 /usr/bin 目录
```

**步骤1：生成scan_id**
```
scan_id = "a1b2c3d4-e5f6-7890-1234-567890abcdef"
```

**步骤2：发送 PublishCommand**

请求：
```
POST /VirusScanService/PublishCommand

Request:
{
  "cmd": {
    "scan_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "type": 0,                          // START_SCAN
    "target": {
      "directory": "/usr/bin"
    },
    "exclude_dirs": ["/usr/bin/test"],
    "include_script": true,
    "timestamp": 1704067200000
  }
}
```

响应：
```
{
  "success": true,
  "message": "扫描任务已创建",
  "scan_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef"
}
```

---

### 9.2 实例2：终端A发布扫描全盘

```
场景：终端A要让Agent扫描整个硬盘
```

**步骤1：生成scan_id**
```
scan_id = "b2c3d4e5-f6a7-8901-2345-678901234567"
```

**步骤2：发送 PublishCommand**

请求：
```
POST /VirusScanService/PublishCommand

Request:
{
  "cmd": {
    "scan_id": "b2c3d4e5-f6a7-8901-2345-678901234567",
    "type": 0,                          // START_SCAN
    "target": {
      "full_disk": true                 // 全盘扫描
    },
    "exclude_dirs": ["/proc", "/sys", "/dev"],
    "include_script": false,
    "timestamp": 1704067200000
  }
}
```

响应：
```
{
  "success": true,
  "message": "扫描任务已创建",
  "scan_id": "b2c3d4e5-f6a7-8901-2345-678901234567"
}
```

---

### 9.3 实例3：终端A停止扫描

```
场景：终端A要停止正在进行的扫描任务
```

**步骤1：发送 PublishCommand (STOP_SCAN)**

请求：
```
POST /VirusScanService/PublishCommand

Request:
{
  "cmd": {
    "scan_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
    "type": 1,                          // STOP_SCAN
    "timestamp": 1704067200000
  }
}
```

响应：
```
{
  "success": true,
  "message": "扫描任务已停止",
  "scan_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef"
}
```

---

### 9.4 实例4：终端A订阅扫描事件

```
场景：终端A要接收扫描过程中的事件推送
```

**步骤1：建立 SubscribeEvents 流**

请求：
```
POST /VirusScanService/SubscribeEvents

Request:
{
  "scan_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef"
}
```

**步骤2：接收推送的事件流**

Agent会持续推送事件，直到扫描完成或连接断开：

```
# 事件1：扫描开始
{
  "scan_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "event_type": 0,                    // SCAN_STARTED
  "payload": {
    "started": {
      "target": "/usr/bin",
      "estimated_files": 523
    }
  },
  "timestamp": 1704067200001
}

# 事件2：扫描进度
{
  "scan_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "event_type": 1,                    // SCAN_PROGRESS
  "payload": {
    "progress": {
      "scanned": 100,
      "total": 523,
      "viruses_found": 0
    }
  },
  "timestamp": 1704067200500
}

# 事件3：单文件扫描完成
{
  "scan_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "event_type": 2,                    // FILE_SCANNED
  "payload": {
    "file": {
      "file_path": "/usr/bin/ls",
      "md5": "d41d8cd98f00b204e9800998ecf8427e",
      "status": 0                     // CLEAN
    }
  },
  "timestamp": 1704067200510
}

# 事件4：扫描完成
{
  "scan_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "event_type": 3,                    // SCAN_COMPLETED
  "payload": {
    "completed": {
      "total_scanned": 523,
      "viruses_found": 2,
      "duration_ms": 5432
    }
  },
  "timestamp": 1704067210000
}
```

---

### 9.5 实例5：终端A订阅病毒告警

```
场景：终端A要实时接收病毒告警（高优先级）
```

**步骤1：建立 SubscribeVirusAlerts 流**

请求：
```
POST /VirusScanService/SubscribeVirusAlerts

Request:
{
  "threat_levels": [2, 3]             // 只接收 HIGH 和 CRITICAL
}
```

**步骤2：接收告警流**

```
# 告警1
{
  "scan_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "file_path": "/usr/bin/malware",
  "md5": "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f",
  "virus_name": "Trojan.GenericKD.1234",
  "threat_level": 2,                 // HIGH
  "detected_at": 1704067200500,
  "description": "恶意木马程序"
}

# 告警2
{
  "scan_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "file_path": "/usr/bin/rootkit",
  "md5": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
  "virus_name": "Rootkit.Linux.Kernel",
  "threat_level": 3,                 // CRITICAL
  "detected_at": 1704067200600,
  "description": "内核级 rootkit"
}
```

---

### 9.6 实例6：终端A查询扫描状态

```
场景：终端A要查询当前所有扫描任务的状态
```

**步骤1：发送 GetScanStatus**

请求：
```
POST /VirusScanService/GetScanStatus

Request:
{
  "scan_id": ""                      // 空=查询所有
}
```

响应：
```
{
  "scans": [
    {
      "scan_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
      "target": "/usr/bin",
      "state": 1,                    // RUNNING
      "scanned": 250,
      "viruses": 1,
      "start_time": 1704067200000
    },
    {
      "scan_id": "b2c3d4e5-f6a7-8901-2345-678901234567",
      "target": "/",
      "state": 4,                    // COMPLETED
      "scanned": 10000,
      "viruses": 5,
      "start_time": 1704067000000
    }
  ]
}
```

---

### 9.7 完整交互示例：扫描 /opt/app 目录

**Step 1: 开始扫描**
```
# 客户端
scan_id = generate_uuid()  # "c3d4e5f6-a7b8-9012-3456-7890abcdef12"

PublishCommand({
  cmd: {
    scan_id: "c3d4e5f6-a7b8-9012-3456-7890abcdef12",
    type: START_SCAN,
    target: { directory: "/opt/app" },
    exclude_dirs: ["/opt/app/tmp", "/opt/app/cache"],
    include_script: true,
    timestamp: 1704067200000
  }
})

# 响应
{
  success: true,
  message: "扫描任务已创建",
  scan_id: "c3d4e5f6-a7b8-9012-3456-7890abcdef12"
}
```

**Step 2: 订阅事件**
```
# 建立流
SubscribeEvents({ scan_id: "c3d4e5f6-a7b8-9012-3456-7890abcdef12" })

SubscribeVirusAlerts({})
```

**Step 3: 接收事件**
```
# ScanStarted
{
  scan_id: "c3d4e5f6-a7b8-9012-3456-7890abcdef12",
  event_type: SCAN_STARTED,
  payload: { target: "/opt/app", estimated_files: 150 }
}

# FileScanned (每个文件)
{
  scan_id: "c3d4e5f6-a7b8-9012-3456-7890abcdef12",
  event_type: FILE_SCANNED,
  payload: { file_path: "/opt/app/launcher", md5: "abc123...", status: CLEAN }
}
{
  scan_id: "c3d4e5f6-a7b8-9012-3456-7890abcdef12",
  event_type: FILE_SCANNED,
  payload: { file_path: "/opt/app/update", md5: "def456...", status: CLEAN }
}

# VirusAlert (发现病毒时)
{
  scan_id: "c3d4e5f6-a7b8-9012-3456-7890abcdef12",
  file_path: "/opt/app/suspicious.so",
  md5: "xyz789...",
  virus_name: "Trojan.Downloader",
  threat_level: HIGH,
  detected_at: 1704067200500
}

# ScanCompleted
{
  scan_id: "c3d4e5f6-a7b8-9012-3456-7890abcdef12",
  event_type: SCAN_COMPLETED,
  payload: { total_scanned: 150, viruses_found: 1, duration_ms: 2345 }
}
```

---

### 9.8 常见调用模式

**模式1：同步等待扫描完成**

```
1. PublishCommand (START_SCAN)
2. SubscribeEvents
3. 循环读取事件
4. 收到 SCAN_COMPLETED 或 SCAN_ERROR 时退出
```

**模式2：异步回调**

```
1. PublishCommand (START_SCAN)
2. 启动后台线程订阅事件
3. 主线程继续执行
4. 事件通过回调处理
```

**模式3：只关心病毒告警**

```
1. PublishCommand (START_SCAN)
2. 只订阅 SubscribeVirusAlerts
3. 忽略其他事件
```

---

## 快速参考

### 最小实现

```
1. 连接: 127.0.0.1:50051 (gRPC)
2. 发送: PublishCommand { type: START_SCAN, target: { directory: "/path" } }
3. 接收: SubscribeEvents (循环读取流)
4. 处理: 根据 event_type 判断
5. 完成: 收到 SCAN_COMPLETED 或 SCAN_ERROR
```

### 完整示例 (伪代码)

```
# 1. 连接
channel = grpc.connect("127.0.0.1:50051")
stub = VirusScanServiceStub(channel)

# 2. 开始扫描
scan_id = generate_uuid()
response = stub.PublishCommand({
    cmd: {
        scan_id: scan_id,
        type: START_SCAN,
        target: { directory: "/usr/bin" }
    }
})

# 3. 订阅事件
events = stub.SubscribeEvents({ scan_id: scan_id })
for event in events:
    switch event.event_type:
        case SCAN_STARTED:
            print("开始: " + event.payload.target)
        case SCAN_PROGRESS:
            print("进度: " + event.payload.scanned + "/" + event.payload.total)
        case FILE_SCANNED:
            print("文件: " + event.payload.file_path)
        case SCAN_COMPLETED:
            print("完成: " + event.payload.total_scanned)
            break
        case SCAN_ERROR:
            print("错误: " + event.payload.error_message)
            break
```
