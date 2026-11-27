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

use common::backend::SecurityBackend;
use log::{error, info, warn};

/// 后门 socket 文件路径。
pub const SELF_BACKDOOR_SOCKET: &str = "/tmp/.self.sock";

/// 按驱动模式口径计算当日口令 token：`YYYY` + `M`(去前导0) + `D`(去前导0)，再 +1。
/// 例如 2026-09-09 → "2026"+"9"+"9" = 202699，+1 = 202700。
///
/// 日期换算不再每次请求都调 libc::localtime_r（要读 /etc/localtime、可能拿时区锁），
/// 改为"本地偏移按天缓存 + 纯算术换算"：localtime_r 一天最多触发一次。
pub fn self_protect_token() -> String {
    let now = std::time::SystemTime::now();
    let secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (y, mo, d) = local_date_from_epoch(secs);
    format!("{}{}{}", y, mo, d)
        .parse::<u64>()
        .map(|n| n + 1)
        .unwrap_or(0)
        .to_string()
}

/// 本地时区相对 UTC 的秒偏移，按 UTC 日缓存（DST 跨日后自动重新取一次）。
fn local_utc_offset_secs(secs: u64) -> i64 {
    static CACHE: std::sync::Mutex<(i64, i64)> = std::sync::Mutex::new((i64::MIN, 0));
    let utc_day = (secs / 86_400) as i64;
    let mut guard = match CACHE.lock() {
        Ok(g) => g,
        // 曾在这个锁里 panic 过：复用内部值，别让后门从此永久算不出 token
        Err(e) => e.into_inner(),
    };
    if guard.0 == utc_day {
        return guard.1;
    }
    let offset = unsafe {
        let t: libc::time_t = secs as libc::time_t;
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            // 取时区失败时退回 UTC，至少 token 是可计算的确定值，而不是垃圾数据
            0
        } else {
            tm.tm_gmtoff as i64
        }
    };
    *guard = (utc_day, offset);
    offset
}

/// epoch 秒 → 本地时区 (年, 月, 日)，与 `date +%Y%m%d` 一致。
fn local_date_from_epoch(secs: u64) -> (u32, u32, u32) {
    let local = secs as i64 + local_utc_offset_secs(secs);
    civil_from_days(local.div_euclid(86_400))
}

/// 自 1970-01-01 起的天数 → (年, 月, 日)。纯算术，无锁、无分配、无系统调用。
fn civil_from_days(days: i64) -> (u32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y } as u32, m, d)
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
///
/// 处理线程 panic 只会结束这一个线程、进程照常运行，日志里往往只剩第一行，
/// 现场无法定位（见 2026-11-26 分析）。这里兜住 panic，并保证各阶段都留痕。
fn handle_connection(backend: &Arc<dyn SecurityBackend>, mut stream: UnixStream) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        handle_connection_inner(backend, &mut stream)
    }));
    if let Err(payload) = result {
        let msg = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<非字符串 panic payload>".to_string());
        error!("[SelfBackdoor] ❌ 处理线程 panic: {}", msg);
        let _ = stream.write_all(b"internal error\n");
    }
}

/// 后门实际处理逻辑：每个阶段各打一条日志，出问题时不会只剩"收到口令请求"。
fn handle_connection_inner(backend: &Arc<dyn SecurityBackend>, stream: &mut UnixStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let line = match read_line(stream) {
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
                    let _ = stream.write_all(if enable {
                        b"system is in self protect\n"
                    } else {
                        b"system is out of self protect\n"
                    });
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
            warn!(
                "[SelfBackdoor] {} 已存在且非 socket（{}），不覆盖",
                path,
                meta.file_type().is_dir() as u8
            );
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
    // 预计算当日口令 token：把时区换算（localtime_r）的首次调用放在启动阶段，
    // 而不是放在处理口令的请求线程里，避免"请求线程第一次算 token 就炸"的静默失败。
    let _ = std::panic::catch_unwind(self_protect_token);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_454), (2026, 1, 1));
        // 2026-11-27：与 `date +%Y%m%d` 对齐
        assert_eq!(civil_from_days(20_784), (2026, 11, 27));
    }

    #[test]
    fn token_format_matches_driver() {
        // 与 install.sh 的 $(date +%Y)$(date +%m|sed s/^0//)$(date +%d|sed s/^0//)+1 对齐：
        // 2026-09-09 -> "2026"+"9"+"9" = 202699 -> +1 = 202700
        let (y, mo, d) = civil_from_days(20_705);
        assert_eq!((y, mo, d), (2026, 9, 9));
        let token = format!("{}{}{}", y, mo, d)
            .parse::<u64>()
            .map(|n| n + 1)
            .unwrap();
        assert_eq!(token, 202_700);
    }
}
