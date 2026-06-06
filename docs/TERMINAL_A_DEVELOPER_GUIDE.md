# 终端A开发者接入指南

> 本文档指导开发者如何接入Agent的病毒扫描gRPC服务。

---

## 目录

1. [快速开始](#1-快速开始)
2. [连接Agent](#2-连接agent)
3. [发布扫描命令](#3-发布扫描命令)
4. [订阅扫描事件](#4-订阅扫描事件)
5. [订阅病毒告警](#5-订阅病毒告警)
6. [完整示例代码](#6-完整示例代码)
7. [错误处理](#7-错误处理)
8. [多语言支持](#8-多语言支持)
9. [常见问题](#9-常见问题)

---

## 1. 快速开始

### 1.1 前置条件

- Agent服务已启动
- 已知Agent的IP地址和端口
- 了解gRPC基础（可选，本文有完整示例）

### 1.2 获取proto文件

开发者需要获取以下文件来生成客户端代码：

1. 从Agent项目获取：`virus_scan.proto`
2. 使用`protoc`或对应语言的gRPC工具生成客户端代码

```bash
# 安装 protoc 和 grpc 工具
# Linux (Ubuntu/Debian)
sudo apt-get install protobuf-compiler
pip install grpcio-tools

# 生成 Python 客户端代码
python -m grpc_tools.protoc \
    -I./proto \
    --python_out=. \
    --grpc_python_out=. \
    virus_scan.proto
```

### 1.3 配置Agent地址

根据环境配置Agent地址：

```python
# 开发环境（Agent在远程机器）
AGENT_ADDR = "192.168.1.100:50051"  # Agent的IP地址

# 生产环境（Agent在同一机器）
AGENT_ADDR = "127.0.0.1:50051"
```

**注意**：开发时Agent需配置`dev_mode=true`以允许远程连接。

---

## 2. 连接Agent

### 2.1 创建gRPC通道

```python
import grpc

# 创建 insecure 通道（无需认证）
channel = grpc.insecure_channel(AGENT_ADDR)

# 创建客户端存根
client = VirusScanServiceStub(channel)

# 测试连接
# （可选）发送一个空请求测试
```

### 2.2 连接参数说明

| 参数 | 说明 | 开发环境 | 生产环境 |
|------|------|----------|----------|
| 地址格式 | `IP:端口` | `192.168.1.100:50051` | `127.0.0.1:50051` |
| 认证方式 | 无 | 无 | 无 |
| TLS | 无需 | 无需 | 无需 |

### 2.3 连接池（生产环境推荐）

```python
# 创建连接池，复用连接
from grpc import PooledChannel

# 创建包含5个连接的池
channel_pool = grpc.create_pool(
    targets=[AGENT_ADDR],
    target_pool_size=5,
    options=[
        ('grpc.max_receive_message_length', 10 * 1024 * 1024),  # 10MB
    ]
)
```

---

## 3. 发布扫描命令

### 3.1 命令类型

| 命令类型 | 说明 |
|----------|------|
| `START_SCAN` | 开始扫描 |
| `STOP_SCAN` | 停止扫描 |

### 3.2 扫描目标

```protobuf
message ScanTarget {
    oneof target {
        string directory = 1;   // 指定目录
        bool full_disk = 2;     // 全盘扫描
    }
    repeated string exclude_dirs = 3;  // 排除目录
    bool include_script = 4;           // 包含脚本文件
}
```

### 3.3 示例代码

```python
import uuid
from datetime import datetime

def start_scan(client, target_dir, exclude_dirs=None):
    """开始扫描"""

    # 1. 生成唯一的scan_id
    scan_id = str(uuid.uuid4())

    # 2. 创建扫描命令
    command = ScanCommand(
        scan_id=scan_id,
        type=CommandType.START_SCAN,
        target=ScanTarget(
            directory=target_dir,           # 指定目录
            # full_disk=True,             # 或全盘扫描
            exclude_dirs=exclude_dirs or [],  # 排除目录
            include_script=True,            # 包含脚本文件
        ),
        timestamp=int(datetime.now().timestamp() * 1000)
    )

    # 3. 发送命令
    request = ScanCommandRequest(cmd=command)
    response = client.PublishCommand(request)

    # 4. 检查结果
    if response.success:
        print(f"✓ 命令已发送成功")
        print(f"  scan_id: {response.scan_id}")
        return scan_id
    else:
        print(f"✗ 命令发送失败: {response.message}")
        return None

def stop_scan(client, scan_id):
    """停止扫描"""

    # 1. 创建停止命令
    command = ScanCommand(
        scan_id=scan_id,
        type=CommandType.STOP_SCAN,
        timestamp=int(datetime.now().timestamp() * 1000)
    )

    # 2. 发送命令
    request = ScanCommandRequest(cmd=command)
    response = client.PublishCommand(request)

    # 3. 检查结果
    if response.success:
        print(f"✓ 停止命令已发送: {response.message}")
    else:
        print(f"✗ 停止失败: {response.message}")
```

### 3.4 参数说明

| 参数 | 必填 | 说明 | 示例 |
|------|------|------|------|
| `scan_id` | 是 | 任务ID，开发者生成，建议UUID | `"a1b2c3d4-..."` |
| `target.directory` | 是 | 要扫描的目录路径 | `"/usr/bin"` |
| `target.full_disk` | 是 | 是否全盘扫描 | `True` |
| `exclude_dirs` | 否 | 排除的目录列表 | `["/usr/bin/tmp"]` |
| `include_script` | 否 | 是否包含脚本文件 | `True` |

---

## 4. 订阅扫描事件

### 4.1 事件类型

| 事件类型 | 说明 | payload |
|----------|------|----------|
| `SCAN_STARTED` | 扫描开始 | `StartedPayload` |
| `SCAN_PROGRESS` | 扫描进度 | `ProgressPayload` |
| `FILE_SCANNED` | 单文件完成 | `FileScannedPayload` |
| `SCAN_COMPLETED` | 扫描完成 | `CompletedPayload` |
| `SCAN_ERROR` | 扫描错误 | `ErrorPayload` |

### 4.2 示例代码

```python
def subscribe_events(client, scan_id):
    """订阅扫描事件"""

    # 1. 创建订阅请求
    request = EventSubscriptionRequest(
        scan_id=scan_id,  # 可选：只订阅特定任务
        # event_types=[     # 可选：筛选事件类型
        #     EventType.SCAN_PROGRESS,
        #     EventType.SCAN_COMPLETED
        # ]
    )

    # 2. 开始订阅（流式接收）
    for event in client.SubscribeEvents(request):
        print(f"[{event.timestamp}] scan_id={event.scan_id}")

        # 3. 根据事件类型处理
        if event.event_type == EventType.SCAN_STARTED:
            print(f"  ✓ 开始扫描: {event.payload.started.target}")

        elif event.event_type == EventType.SCAN_PROGRESS:
            p = event.payload.progress
            print(f"  📊 进度: {p.scanned}/{p.total}, 病毒: {p.viruses_found}")

        elif event.event_type == EventType.FILE_SCANNED:
            f = event.payload.file
            status = "干净" if f.status == FileStatus.CLEAN else "可疑"
            print(f"  📄 {f.file_path}")
            print(f"     MD5: {f.md5[:16]}... 状态: {status}")

        elif event.event_type == EventType.SCAN_COMPLETED:
            c = event.payload.completed
            print(f"  ✓ 扫描完成")
            print(f"     总文件: {c.total_scanned}")
            print(f"     发现病毒: {c.viruses_found}")
            print(f"     耗时: {c.duration_ms}ms")
            break  # 可选：完成后退出

        elif event.event_type == EventType.SCAN_ERROR:
            e = event.payload.error
            print(f"  ✗ 错误: {e.error_code} - {e.error_message}")
            break
```

### 4.3 事件数据结构

```protobuf
// 开始事件
message StartedPayload {
    string target = 1;        // 扫描目标
    int32 estimated_files = 2;  // 预估文件数
}

// 进度事件
message ProgressPayload {
    int32 scanned = 1;        // 已扫描
    int32 total = 2;          // 总数
    int32 viruses_found = 3;   // 发现病毒
}

// 文件扫描完成
message FileScannedPayload {
    string file_path = 1;      // 文件路径
    string md5 = 2;           // MD5
    FileStatus status = 3;     // 状态
}

// 完成事件
message CompletedPayload {
    int32 total_scanned = 1;   // 总扫描数
    int32 viruses_found = 2;   // 病毒数
    int64 duration_ms = 3;    // 耗时(ms)
}

// 错误事件
message ErrorPayload {
    string error_code = 1;     // 错误码
    string error_message = 2;   // 错误信息
}
```

---

## 5. 订阅病毒告警

### 5.1 告警数据结构

```protobuf
message VirusAlert {
    string scan_id = 1;        // 扫描任务ID
    string file_path = 2;      // 病毒文件路径
    string md5 = 3;           // 文件MD5
    string virus_name = 4;     // 病毒名称
    ThreatLevel threat_level = 5;  // 威胁等级
    int64 detected_at = 6;     // 检测时间戳
    string description = 7;    // 病毒描述
}

enum ThreatLevel {
    LOW = 0;       // 低危
    MEDIUM = 1;    // 中危
    HIGH = 2;      // 高危
    CRITICAL = 3;  // 严重
}
```

### 5.2 示例代码

```python
def subscribe_alerts(client, scan_id=None):
    """订阅病毒告警"""

    # 1. 创建订阅请求
    request = AlertSubscriptionRequest(
        # threat_levels=[ThreatLevel.HIGH, ThreatLevel.CRITICAL]  # 可选：筛选威胁级别
    )

    # 2. 开始订阅
    for alert in client.SubscribeVirusAlerts(request):
        # 3. 显示告警
        print(f"\n{'='*50}")
        print(f"[病毒告警] {alert.virus_name}")
        print(f"{'='*50}")
        print(f"  文件: {alert.file_path}")
        print(f"  MD5: {alert.md5}")
        print(f"  威胁: {alert.threat_level}")
        print(f"  时间: {datetime.fromtimestamp(alert.detected_at/1000)}")
        if alert.description:
            print(f"  描述: {alert.description}")

        # 4. 可选：处理告警
        # - 记录日志
        # - 发送通知
        # - 隔离文件
```

---

## 6. 完整示例代码

### 6.1 Python完整示例

```python
#!/usr/bin/env python3
"""
病毒扫描客户端示例
"""

import grpc
import uuid
import threading
import sys
from datetime import datetime
from virus_scan_pb2 import *
from virus_scan_pb2_grpc import *

# 配置
AGENT_ADDR = "127.0.0.1:50051"  # 根据环境修改


class VirusScanClient:
    """病毒扫描客户端"""

    def __init__(self, addr):
        self.channel = grpc.insecure_channel(addr)
        self.stub = VirusScanServiceStub(self.channel)
        self.scan_id = None
        self.event_thread = None
        self.alert_thread = None

    def start_scan(self, target_dir, exclude_dirs=None):
        """开始扫描"""
        self.scan_id = str(uuid.uuid4())

        command = ScanCommand(
            scan_id=self.scan_id,
            type=CommandType.START_SCAN,
            target=ScanTarget(
                directory=target_dir,
                exclude_dirs=exclude_dirs or [],
                include_script=True,
            ),
            timestamp=int(datetime.now().timestamp() * 1000)
        )

        response = self.stub.PublishCommand(ScanCommandRequest(cmd=command))

        if response.success:
            print(f"✓ 开始扫描: {target_dir}")
            print(f"  scan_id: {self.scan_id}")
            return self.scan_id
        else:
            print(f"✗ 失败: {response.message}")
            return None

    def stop_scan(self):
        """停止扫描"""
        if not self.scan_id:
            print("✗ 没有正在进行的扫描")
            return

        command = ScanCommand(
            scan_id=self.scan_id,
            type=CommandType.STOP_SCAN,
            timestamp=int(datetime.now().timestamp() * 1000)
        )

        response = self.stub.PublishCommand(ScanCommandRequest(cmd=command))
        print(f"✓ {response.message}")

    def _event_callback(self, event):
        """事件回调"""
        if event.event_type == EventType.SCAN_STARTED:
            print(f"[{event.timestamp}] 开始扫描: {event.payload.started.target}")

        elif event.event_type == EventType.SCAN_PROGRESS:
            p = event.payload.progress
            print(f"[{event.timestamp}] 进度: {p.scanned}/{p.total}, 病毒: {p.viruses_found}")

        elif event.event_type == EventType.FILE_SCANNED:
            f = event.payload.file
            status = "干净" if f.status == FileStatus.CLEAN else "可疑"
            print(f"[{event.timestamp}] {f.file_path[:50]}... [{status}]")

        elif event.event_type == EventType.SCAN_COMPLETED:
            c = event.payload.completed
            print(f"\n[{event.timestamp}] ✓ 扫描完成")
            print(f"  总文件: {c.total_scanned}")
            print(f"  发现病毒: {c.viruses_found}")
            print(f"  耗时: {c.duration_ms}ms")

        elif event.event_type == EventType.SCAN_ERROR:
            e = event.payload.error
            print(f"[{event.timestamp}] ✗ 错误: {e.error_message}")

    def _alert_callback(self, alert):
        """告警回调"""
        print(f"\n{'!'*50}")
        print(f"[病毒告警] {alert.virus_name}")
        print(f"  文件: {alert.file_path}")
        print(f"  MD5: {alert.md5}")
        print(f"  威胁: {alert.threat_level}")
        print(f"{'!'*50}")

    def subscribe_events_async(self):
        """异步订阅事件"""
        if not self.scan_id:
            return

        def run():
            request = EventSubscriptionRequest(scan_id=self.scan_id)
            try:
                for event in self.stub.SubscribeEvents(request):
                    self._event_callback(event)
            except grpc.RpcError as e:
                print(f"订阅事件结束: {e.code()}")

        self.event_thread = threading.Thread(target=run, daemon=True)
        self.event_thread.start()

    def subscribe_alerts_async(self):
        """异步订阅告警"""
        def run():
            try:
                for alert in self.stub.SubscribeVirusAlerts(AlertSubscriptionRequest()):
                    self._alert_callback(alert)
            except grpc.RpcError as e:
                print(f"订阅告警结束: {e.code()}")

        self.alert_thread = threading.Thread(target=run, daemon=True)
        self.alert_thread.start()


def main():
    """主函数"""
    client = VirusScanClient(AGENT_ADDR)

    # 解析参数
    if len(sys.argv) < 2:
        print("用法: python virus_scan_client.py <扫描目录>")
        print("示例: python virus_scan_client.py /usr/bin")
        sys.exit(1)

    target_dir = sys.argv[1]

    # 开始扫描
    scan_id = client.start_scan(target_dir)
    if not scan_id:
        sys.exit(1)

    # 订阅事件和告警
    client.subscribe_events_async()
    client.subscribe_alerts_async()

    print("\n按 Ctrl+C 停止...\n")

    # 等待
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n正在停止...")
        client.stop_scan()


if __name__ == "__main__":
    main()
```

### 6.2 运行示例

```bash
# 生成客户端代码
python -m grpc_tools.protoc \
    -I./proto \
    --python_out=. \
    --grpc_python_out=. \
    virus_scan.proto

# 运行
$ python virus_scan_client.py /usr/bin

✓ 开始扫描: /usr/bin
  scan_id: a1b2c3d4-e5f6-7890-1234-567890abcdef

按 Ctrl+C 停止...

[1701234567000] 开始扫描: /usr/bin
[1701234567001] 进度: 100/500, 病毒: 0
[1701234567002] /usr/bin/ls [干净]
[1701234567003] /usr/bin/cp [干净]
[1701234567100] 进度: 200/500, 病毒: 0
...
[1701234567500] ✓ 扫描完成
  总文件: 523
  发现病毒: 0
  耗时: 5000ms

```

### 6.3 输出示例（发现病毒）

```
✓ 开始扫描: /tmp/scan_test
  scan_id: a1b2c3d4-e5f6-7890-1234-567890abcdef

[1701234567000] 开始扫描: /tmp/scan_test
[1701234567001] /tmp/scan_test/suspicious.sh [可疑]

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[病毒告警] Trojan.GenericKD
  文件: /tmp/scan_test/suspicious.sh
  MD5: d41d8cd98f00b204e9800998ecf8427e
  威胁: HIGH
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

[1701234567500] ✓ 扫描完成
  总文件: 10
  发现病毒: 1
  耗时: 2000ms
```

---

## 7. 错误处理

### 7.1 常见错误码

| 错误码 | 说明 | 处理方式 |
|--------|------|----------|
| `OK` | 成功 | - |
| `INVALID_ARGUMENT` | 参数错误 | 检查请求参数 |
| `NOT_FOUND` | scan_id不存在 | 确认scan_id是否正确 |
| `UNAVAILABLE` | 服务不可连接 | 检查Agent是否启动 |
| `CANCELLED` | 连接被取消 | 重连 |

### 7.2 错误处理示例

```python
import grpc

def safe_call(func):
    """安全的gRPC调用装饰器"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except grpc.RpcError as e:
            print(f"gRPC错误: {e.code()} - {e.details()}")
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                print("Agent服务不可用，请检查Agent是否启动")
            elif e.code() == grpc.StatusCode.INVALID_ARGUMENT:
                print("参数错误，请检查请求参数")
            return None
        except Exception as e:
            print(f"未知错误: {e}")
            return None
    return wrapper

@safe_call
def start_scan_safe(client, target_dir):
    return client.start_scan(target_dir)
```

### 7.3 重试机制

```python
from grpc import RpcError

def retry_on_failure(func, max_retries=3, delay=1):
    """失败重试"""
    def wrapper(*args, **kwargs):
        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs)
            except RpcError as e:
                if e.code() == grpc.StatusCode.UNAVAILABLE:
                    print(f"连接失败，{delay}秒后重试 ({attempt+1}/{max_retries})")
                    import time
                    time.sleep(delay)
                else:
                    raise
        return None
    return wrapper

@retry_on_failure
def start_scan_with_retry(client, target_dir):
    return client.start_scan(target_dir)
```

---

## 8. 多语言支持

### 8.1 C++示例

```cpp
#include <grpcpp/grpcpp.h>
#include "virus_scan.pb.h"
#include <iostream>
#include <thread>

class VirusScanClient {
private:
    std::unique_ptr<VirusScanService::Stub> stub_;

public:
    VirusScanClient(std::string addr) {
        auto channel = grpc::CreateChannel(
            addr, grpc::InsecureChannelCredentials()
        );
        stub_ = VirusScanService::NewStub(channel);
    }

    std::string start_scan(std::string target_dir) {
        ScanCommand cmd;
        cmd.set_scan_id(generate_uuid());
        cmd.set_type(CommandType::START_SCAN);
        cmd.mutable_target()->set_directory(target_dir);

        ScanCommandRequest req;
        *req.mutable_cmd() = cmd;

        ScanCommandResponse resp;
        grpc::ClientContext ctx;
        auto status = stub_->PublishCommand(&ctx, req, &resp);

        if (status.ok()) {
            return resp.scan_id();
        }
        return "";
    }

    void subscribe_events(std::string scan_id) {
        EventSubscriptionRequest req;
        req.set_scan_id(scan_id);

        grpc::ClientContext ctx;
        std::unique_ptr<grpc::ClientReader<ScanEvent>> reader =
            stub_->SubscribeEvents(&ctx, req);

        while (reader->Read(&event)) {
            // 处理事件
            std::cout << "事件: " << event.event_type() << std::endl;
        }
    }

private:
    std::string generate_uuid() {
        // 实现UUID生成
        return "uuid-placeholder";
    }
};

int main() {
    auto client = VirusScanClient("127.0.0.1:50051");
    auto scan_id = client.start_scan("/usr/bin");
    client.subscribe_events(scan_id);
    return 0;
}
```

### 8.2 Go示例

```go
package main

import (
    "context"
    "fmt"
    "log"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    pb "path/to/proto"
)

func main() {
    // 连接
    conn, err := grpc.Dial("127.0.0.1:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    client := pb.NewVirusScanServiceClient(conn)

    // 开始扫描
    cmd := &pb.ScanCommand{
        ScanId: generateUUID(),
        Type:   pb.CommandType_START_SCAN,
        Target: &pb.ScanTarget{
            Target: &pb.ScanTarget_Directory{Directory: "/usr/bin"},
        },
    }

    resp, _ := client.PublishCommand(context.Background(), &pb.ScanCommandRequest{Cmd: cmd})
    fmt.Printf("scan_id: %s\n", resp.ScanId)

    // 订阅事件
    stream, _ := client.SubscribeEvents(context.Background(), &pb.EventSubscriptionRequest{
        ScanId: resp.ScanId,
    })

    for {
        event, err := stream.Recv()
        if err != nil {
            break
        }
        fmt.Printf("事件: %v\n", event.EventType)
    }
}

func generateUUID() string {
    // 实现UUID生成
    return "uuid-placeholder"
}
```

### 8.3 Java示例

```java
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.stub.StreamObserver;

public class VirusScanClient {
    private VirusScanServiceGrpc.VirusScanServiceBlockingStub blockingStub;
    private VirusScanServiceGrpc.VirusScanServiceStub asyncStub;

    public VirusScanClient(String addr) {
        ManagedChannel channel = ManagedChannelBuilder.forAddress(addr, 50051)
            .usePlaintext()
            .build();
        blockingStub = VirusScanServiceGrpc.newBlockingStub(channel);
        asyncStub = VirusScanServiceGrpc.newStub(channel);
    }

    public String startScan(String targetDir) {
        ScanCommand cmd = ScanCommand.newBuilder()
            .setScanId(UUID.randomUUID().toString())
            .setType(CommandType.START_SCAN)
            .setTarget(ScanTarget.newBuilder()
                .setDirectory(targetDir)
                .build())
            .build();

        ScanCommandResponse resp = blockingStub.publishCommand(
            ScanCommandRequest.newBuilder().setCmd(cmd).build()
        );

        return resp.getScanId();
    }

    public void subscribeEvents(String scanId) {
        EventSubscriptionRequest req = EventSubscriptionRequest.newBuilder()
            .setScanId(scanId)
            .build();

        asyncStub.subscribeEvents(req, new StreamObserver<ScanEvent>() {
            @Override
            public void onNext(ScanEvent event) {
                System.out.println("事件: " + event.getEventType());
            }

            @Override
            public void onError(Throwable t) {}

            @Override
            public void onCompleted() {}
        });
    }
}
```

---

## 9. 常见问题

### Q1: 连接失败

**错误**：`grpc.RpcError: UNAVAILABLE`

**原因**：
- Agent未启动
- 地址错误
- 防火墙阻止

**解决**：
```python
# 检查Agent是否启动
$ curl http://127.0.0.1:50051  # 无响应说明未启动

# 检查端口
$ netstat -tlnp | grep 50051
```

### Q2: 收不到事件

**原因**：
- scan_id错误
- 订阅时机不对

**解决**：
```python
# 确保在开始扫描后才订阅
client.start_scan("/usr/bin")
client.subscribe_events_async()  # 扫描开始后订阅
```

### Q3: 事件流卡住

**原因**：
- 扫描时间过长
- 网络不稳定

**解决**：
```python
# 设置超时
for event in client.SubscribeEvents(request):
    # 处理事件
    pass  # 如果卡住，考虑添加超时
```

### Q4: 如何处理大量文件扫描

**建议**：
```python
# 不要订阅所有FILE_SCANNED事件
# 只订阅进度和完成事件
request = EventSubscriptionRequest(
    scan_id=scan_id,
    event_types=[
        EventType.SCAN_PROGRESS,
        EventType.SCAN_COMPLETED
    ]
)
```

### Q5: 如何同时管理多个扫描

```python
class MultiScanManager:
    def __init__(self):
        self.scans = {}  # scan_id -> client

    def start_scan(self, scan_id, target_dir):
        client = VirusScanClient(AGENT_ADDR)
        client.start_scan(target_dir)
        client.subscribe_events_async()
        client.subscribe_alerts_async()
        self.scans = client

    def stop_all(self):
        for[scan_id] client in self.scans.values():
            client.stop_scan()
```

### Q6: proto文件更新

当Agent的proto文件更新时：

1. 获取最新的`virus_scan.proto`
2. 重新生成客户端代码
3. 更新你的代码以适配新接口

```bash
# 重新生成
python -m grpc_tools.protoc -I./proto --python_out=. --grpc_python_out=. virus_scan.proto
```

---

## 附录A: proto文件

```protobuf
// virus_scan.proto
syntax = "proto3";

package virus_scan;

service VirusScanService {
    rpc PublishCommand(ScanCommandRequest) returns (ScanCommandResponse);
    rpc SubscribeEvents(EventSubscriptionRequest) returns (stream ScanEvent);
    rpc SubscribeVirusAlerts(AlertSubscriptionRequest) returns (stream VirusAlert);
    rpc GetScanStatus(StatusRequest) returns (StatusResponse);
}

message ScanCommandRequest {
    ScanCommand cmd = 1;
}

message ScanCommandResponse {
    bool success = 1;
    string message = 2;
    string scan_id = 3;
}

message EventSubscriptionRequest {
    optional string scan_id = 1;
    repeated int32 event_types = 2;
}

message AlertSubscriptionRequest {
    repeated int32 threat_levels = 1;
}

message StatusRequest {
    optional string scan_id = 1;
}

message StatusResponse {
    repeated ScanStatusItem scans = 1;
}

message ScanStatusItem {
    string scan_id = 1;
    string target = 2;
    int32 state = 3;
    int32 scanned = 4;
    int32 viruses = 5;
    int64 start_time = 6;
}

message ScanCommand {
    string scan_id = 1;
    int32 type = 2;
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

message ScanEvent {
    string scan_id = 1;
    int32 event_type = 2;
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
    int32 status = 3;
}

message VirusAlert {
    string scan_id = 1;
    string file_path = 2;
    string md5 = 3;
    string virus_name = 4;
    int32 threat_level = 5;
    int64 detected_at = 6;
    string description = 7;
}
```

---

## 附录B: 联系方式

如有问题，请联系：

- **Agent开发团队**: [Agent开发者邮箱]
- **文档问题**: [你的邮箱]
