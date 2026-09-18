//! 自保后门 — Unix domain socket 监听（复刻驱动模式 /proc/osec/self 的口令后门）。
//!
//! eBPF 模式下没有内核模块、没有 /proc/osec/self，无法靠内核校验口令关自保。
//! 这里由 agent 进程自己监听一个本地 Unix socket（.self.sock），收到
//! `veda <token> <0|1>` 格式的口令：
//!   - token = YYYY + M(去前导0) + D(去前导0) + 1（与驱动模式算法完全一致）
//!   - 0 = 关自保，1 = 开自保
//! 校验通过后调用后端 write_self_protection，把 agent PID 从 protected_pids
//! map 移除/加入，从而突破 eBPF 对 kill 的拦截。

use std::io::{Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::Duration;

use log::{error, info, warn};
use common::backend::SecurityBackend;

/// 后门 socket 文件路径。
pub const SELF_BACKDOOR_SOCKET: &str = "/tmp/.self.sock";

/// 按驱动模式口径计算当日口令 token：`YYYY` + `M`(去前导0) + `D`(去前导0)，再 +1。
/// 例如 2026-09-09 → "2026"+"9"+"9" = 202699，+1 = 2026100。
/// 使用 libc localtime_r 取本机时区日期，与 shell `date` 输出完全一致。
pub fn self_protect_token() -> String {
    let now = std::time::SystemTime::now();
    let secs = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let (y, mo, d) = local_date_from_epoch(secs);
    format!("{}{}{}", y, mo, d).parse::<u64>().map(|n| n + 1).unwrap_or(0).to_string()
}

/// epoch 秒 → 本地时区 (年, 月, 日)，与 `date +%Y%m%d` 一致。
fn local_date_from_epoch(secs: u64) -> (u32, u32, u32) {
    let t: libc::time_t = secs as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&t, &mut tm) };
    (tm.tm_year as u32 + 1900, tm.tm_mon as u32 + 1, tm.tm_mday as u32)
}

/// 校验一行口令 `veda <token> <0|1>`，返回 Some(true=开自保) / Some(false=关自保) / None(非法)。
/// 与驱动 /proc/osec/self 完全一致：token 必须是当日口令，末尾 0=关、1=开。
pub fn parse_self_backdoor(line: &str) -> Option<bool> {
    let line = line.trim();
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() != 3 || parts[0] != "veda" {
        return None;
    }
    // 口令 token 必须匹配当日（本地日期）口令
    if parts[1] != self_protect_token() {
        return None;
    }
    match parts[2] {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

/// 读取 socket 连接，返回读取到的整行内容。
fn read_line(stream: &mut UnixStream) -> Option<String> {
    let mut buf = [0u8; 256];
    let mut acc = Vec::new();
    loop {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        acc.extend_from_slice(&buf[..n]);
        if acc.len() > 4096 {
            break;
        }
        if acc.contains(&b'\n') {
            break;
        }
    }
    Some(String::from_utf8_lossy(&acc).to_string())
}

/// 处理一个连接：读口令，校验通过则执行关/开自保。
fn handle_connection(backend: &Arc<dyn SecurityBackend>, mut stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let line = match read_line(&mut stream) {
        Some(l) => l,
        None => {
            let _ = stream.write_all(b"no data\n");
            return;
        }
    };
    info!("[SelfBackdoor] 收到口令请求: {}", line.trim());
    match parse_self_backdoor(&line) {
        Some(enable) => {
            let action = if enable { "开" } else { "关" };
            info!("[SelfBackdoor] ✅ 口令校验通过，{}自保", action);
            match backend.write_self_protection(enable as u32) {
                Ok(()) => {
                    let _ = stream.write_all(if enable { b"system is in self protect\n" } else { b"system is out of self protect\n" });
                    info!("[SelfBackdoor] 自保已{}", action);
                }
                Err(e) => {
                    let msg = format!("write_self_protection 失败: {}\n", e);
                    let _ = stream.write_all(msg.as_bytes());
                    error!("[SelfBackdoor] ❌ {}", msg.trim());
                }
            }
        }
        None => {
            let _ = stream.write_all(b"invalid token\n");
            warn!("[SelfBackdoor] ❌ 口令校验失败: {}", line.trim());
        }
    }
}

/// 启动自保后门 listener（Unix domain socket，/tmp/.self.sock）。
/// eBPF 模式下由 agent 启动时调用；驱动模式不使用。
pub fn start_self_backdoor(backend: Arc<dyn SecurityBackend>) {
    let path = SELF_BACKDOOR_SOCKET;
    // 清理可能残留的旧 socket 文件
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_socket() {
            let _ = std::fs::remove_file(path);
        } else {
            warn!("[SelfBackdoor] {} 已存在且非 socket（{}），不覆盖", path, meta.file_type().is_dir() as u8);
            return;
        }
    }
    let listener = match UnixListener::bind(path) {
        Ok(l) => l,
        Err(e) => {
            error!("[SelfBackdoor] ❌ 绑定 {} 失败: {}", path, e);
            return;
        }
    };
    // 只允许本机（0600）：后门口令虽强，仍限制访问方为 root/agent 用户
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    //info!("[SelfBackdoor] 🛡️ 自保后门已启动: {} （操作: echo \"veda ... 0\" | nc -U {}）", path, path);
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let backend = backend.clone();
                    std::thread::spawn(move || {
                        handle_connection(&backend, stream);
                    });
                }
                Err(e) => {
                    warn!("[SelfBackdoor] accept 失败: {}", e);
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    });
}
