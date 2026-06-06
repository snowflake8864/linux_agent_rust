# ClamAV 连接方式配置说明

## 1. ClamAV 支持的连接方式

ClamAV 支持两种连接方式：
- **TCP Socket**: 通过 TCP 端口连接（默认 3310）
- **Unix Socket**: 通过本地 Unix 域套接字连接（默认 `/run/clamav/clamd.ctl`）

## 2. ClamAV 服务端配置

### 2.1 仅使用 TCP Socket

编辑 `/etc/clamav/clamd.conf`，确保以下配置：

```conf
TCPSocket 3310
TCPAddr 127.0.0.1
```

重启服务：
```bash
sudo systemctl restart clamav-daemon
```

### 2.2 仅使用 Unix Socket

编辑 `/etc/clamav/clamd.conf`：

```conf
LocalSocket /run/clamav/clamd.ctl
LocalSocketGroup clamav
LocalSocketMode 666
```

重启服务：
```bash
sudo systemctl restart clamav-daemon
```

### 2.3 同时支持 TCP 和 Unix Socket

使用 systemd socket 单元覆盖配置。

创建 `/etc/systemd/system/clamav-daemon.socket.d/both.conf`：

```ini
[Socket]
ListenStream=127.0.0.1:3310
ListenStream=/run/clamav/clamd.ctl
```

重新加载并重启：
```bash
sudo systemctl daemon-reload
sudo systemctl restart clamav-daemon.socket clamav-daemon
```

验证监听状态：
```bash
ss -tlnp | grep clamd
```

## 3. 客户端配置

### 3.1 配置文件

在 `/opt/osec/net_info.ini` 中配置：

```ini
CLAMAV_ENABLED=1
CLAMAV_HOST=127.0.0.1          ; TCP 模式：IP 地址
CLAMAV_PORT=3310               ; TCP 模式：端口

; 或者使用 Unix Socket：
; CLAMAV_HOST=/run/clamav/clamd.ctl
; CLAMAV_PORT=3310              ; 端口配置会被忽略
```

### 3.2 配置规则

- **TCP 模式**: `CLAMAV_HOST` 以点分十进制 IP 开头（如 `127.0.0.1`）
- **Unix Socket 模式**: `CLAMAV_HOST` 是文件路径（包含 `/` 或 `.sock`）

## 4. 代码自动检测机制

### 4.1 检测逻辑

程序启动时，`ClamAVScanner::auto_connect()` 会按以下顺序尝试连接：

1. **优先尝试 TCP 连接**
   - 使用配置的 `CLAMAV_HOST:CLAMAV_PORT`
   - 超时时间：2 秒

2. **TCP 失败则尝试 Unix Socket**
   - 使用默认路径 `/run/clamav/clamd.ctl`
   - 超时时间：2 秒

3. **如果配置本身就是 Unix Socket 路径**
   - 直接使用配置的路径尝试连接

### 4.2 连接失败处理

- 如果所有连接方式都失败，程序会：
  - 记录警告日志
  - **继续启动 gRPC 服务**
  - 病毒扫描功能标记为不可用

- 扫描请求会返回错误：`"ClamAV 不可用"`

### 4.3 扫描流程

```
扫描请求
    ↓
检查 ClamAV 是否可用
    ↓
可用 → 通过 TCP 或 Unix Socket 发送扫描请求
不可用 → 返回错误
```

## 5. 端口监听状态验证

### 5.1 检查 TCP 监听
```bash
ss -tlnp | grep 3310
# 或
netstat -tlnp | grep 3310
```

### 5.2 检查 Unix Socket
```bash
ls -la /run/clamav/clamd.ctl
# 输出应包含: srw-rw-rw- 1 clamav clamav 0 ... clamd.ctl
```

### 5.3 测试连接

TCP 模式：
```bash
echo "PING" | nc 127.0.0.1 3310
# 应返回: PONG
```

Unix Socket 模式：
```bash
echo "PING" | socat - UNIX:/run/clamav/clamd.ctl
# 或使用 Python 测试
python3 -c "
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/run/clamav/clamd.ctl')
s.send(b'PING\n')
print(s.recv(1024))
s.close()
"
```

## 6. 故障排除

### 6.1 TCP 连接被拒绝
- 检查 ClamAV 是否运行：`systemctl status clamav-daemon`
- 检查防火墙是否阻止 3310 端口

### 6.2 Unix Socket 连接超时
- 检查 socket 文件权限
- 确保 clamav 用户有访问权限

### 6.3 双方都不可用
- 检查 `/etc/clamav/clamd.conf` 配置
- 查看 ClamAV 日志：`journalctl -u clamav-daemon`

## 7. 推荐配置

### 7.1 开发测试环境
同时启用 TCP 和 Unix Socket，代码会自动检测。

### 7.2 生产环境
根据实际需求选择：
- **仅 TCP**: 适用于容器化部署或需要远程连接
- **仅 Unix Socket**: 适用于本地服务，性能更好
