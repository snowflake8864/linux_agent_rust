# 安全评估协议设计文档

## 一、协议概述

本文档描述客户端与安全评估服务器之间的 UDP 通信协议。客户端定期向服务器发送本机安全评估数据（IP、MAC、安全评分），服务器返回处理结果。

---

## 二、协议定义

### 2.1 固定头部（20字节）

| 偏移 | 字段 | 类型 | 长度 | 描述 |
|------|------|------|------|------|
| 0 | magic | [u8; 4] | 4字节 | 协议标识 `0x53454356` ("SECV") |
| 4 | version | u8 | 1字节 | 协议版本，当前为 `0x01` |
| 5 | msg_type | u8 | 1字节 | 消息类型定义见下表 |
| 6 | seq | u16 | 2字节 | 序列号（大端序），请求响应匹配 |
| 8 | timestamp | u32 | 4字节 | Unix时间戳（大端序） |
| 12 | checksum | u32 | 4字节 | CRC32 校验和（大端序） |
| 16 | enc_type | u8 | 1字节 | 加密类型：1=RC4 |
| 17 | reserved | [u8; 3] | 3字节 | 保留，填充0 |

### 2.2 消息类型定义

| 类型值 | 名称 | 方向 | 说明 |
|--------|------|------|------|
| 0x01 | EvalRequest | 客户端→服务器 | 安全评估请求 |
| 0x02 | EvalResponse | 服务器→客户端 | 安全评估响应 |

### 2.3 安全评估载荷（27字节）- RC4加密

| 偏移 | 字段 | 类型 | 长度 | 描述 |
|------|------|------|------|------|
| 0 | ip_type | u8 | 1字节 | IP类型：4=IPv4, 6=IPv6 |
| 1 | ip | [u8; 16] | 16字节 | IP地址（IPv4用前4字节，其余填0） |
| 17 | mac | [u8; 6] | 6字节 | MAC地址 |
| 23 | score | u32 | 4字节 | 安全评分（大端序） |

### 2.4 响应载荷（变长）

| 偏移 | 字段 | 类型 | 长度 | 描述 |
|------|------|------|------|------|
| 0 | code | i32 | 4字节 | 错误码：0=成功（大端序） |
| 4 | message_len | u8 | 1字节 | 消息长度 |
| 5 | message | [u8] | N字节 | 消息内容（ASCII） |

---

## 三、完整消息结构

```
+----------------+----------------+
|    固定头部    |    载荷数据    |
|    20 字节    |   27 字节     |
+----------------+----------------+
       ↓                ↓
     明文            RC4加密
```

**请求消息总长度：47字节**

---

## 四、Rust 结构体定义

```rust
/// 固定头部 (20字节)
pub struct ProtocolHeader {
    pub magic: [u8; 4],     // "SECV"
    pub version: u8,        // 0x01
    pub msg_type: u8,      // 0x01=请求, 0x02=响应
    pub seq: u16,          // 序列号
    pub timestamp: u32,    // 时间戳
    pub checksum: u32,     // CRC32
    pub enc_type: u8,     // 1=RC4
    pub reserved: [u8; 3],
}

/// 安全评估请求载荷 (27字节)
pub struct SecurityEvalData {
    pub ip_type: u8,        // 4=IPv4, 6=IPv6
    pub ip: [u8; 16],      // IP地址
    pub mac: [u8; 6],      // MAC地址
    pub score: u32,        // 安全评分
}

/// 安全评估响应载荷 (变长)
pub struct SecurityEvalResponse {
    pub code: i32,          // 0=成功
    pub message_len: u8,   // 消息长度
    pub message: Vec<u8>,  // 消息内容
}
```

---

## 五、加密说明

### 5.1 RC4 算法

- 密钥长度：32字节
- 密钥内容：硬编码 `0x01, 0x02, 0x03, ... 0x20`
- 加密范围：整个载荷部分（Header 后的所有数据）

### 5.2 校验和计算

- 算法：CRC32（多项式 0xEDB88320）
- 计算范围：magic(4) + version(1) + msg_type(1) + seq(2) + timestamp(4) + enc_type(1) + reserved(3) = 16字节

---

## 六、通信流程

```
客户端 (Rust)                   服务器 (C)
    |                               |
    |--- UDP 请求 (47字节) -------->|  端口: 62201
    |    - Header (明文)           |
    |    - Payload (RC4加密)       |
    |                               |
    |<-- UDP 响应 (变长) ----------|
    |    - Header (明文)           |
    |    - Payload (RC4加密)       |
    |                               |
```

### 6.1 正常流程

1. 客户端获取本机 IP 和 MAC
2. 构造 ProtocolHeader（魔数 "SECV"，msg_type=0x01）
3. 构造 SecurityEvalData（ip_type, ip, mac, score）
4. RC4 加密载荷
5. 发送 UDP 数据报
6. 等待响应（超时 5 秒）
7. 解析响应，检查 code=0

### 6.2 超时处理

- 客户端：响应超时 5 秒则返回错误
- 服务器：无超时机制，持续监听

---

## 七、UDP 通信参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| 目的端口 | 62201 | 可通过配置 `security_eval_server_addr` 下发 |
| 源端口 | 随机 | 客户端 bind("0.0.0.0:0") |
| 协议 | UDP | 无连接传输 |

---

## 八、配置说明

客户端通过 `NETINFO_CONFIG` 配置项控制：

```rust
pub struct NetInfoConfig {
    pub security_eval_enabled: bool,    // 是否启用
    pub security_eval_interval: u64,     // 发送间隔（秒）
    pub security_eval_server_addr: String, // 服务器地址
}
```

---

## 九、安全考虑

1. **载荷加密**：整个载荷部分使用 RC4 加密传输
2. **防重放**：序列号递增，服务器可记录已处理的序列号
3. **协议识别**：魔数 "SECV" 防止误解析
4. **时间戳校验**：Header 中包含时间戳，可用于时效性校验
5. **校验和**：CRC32 校验 header 完整性