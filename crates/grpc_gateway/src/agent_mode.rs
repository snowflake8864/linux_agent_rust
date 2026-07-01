/// Agent connectivity mode — shared across all crates.
///
/// - Online:  agent is connected to the server, write operations via gRPC are blocked
/// - Offline: agent lost connection to the server, local gRPC write operations are allowed
use std::sync::{Mutex, LazyLock, atomic::{AtomicU8, AtomicU32, AtomicBool, Ordering}};
use tonic::Status;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AgentMode {
    Online = 0,
    Offline = 1,
}

/// 连续失败多少次才算"网络异常"（避免单次超时误报）
const NETWORK_ANOMALY_THRESHOLD: u32 = 3;

/// Global agent mode, writable from online/task_fetcher, readable from gRPC handlers.
pub static AGENT_MODE: AtomicU8 = AtomicU8::new(AgentMode::Online as u8);
/// 网络异常标记：连续失败达阈值才置 true，一旦成功立即置 false。
pub static ADMISSION_NETWORK_ANOMALY: AtomicBool = AtomicBool::new(false);
/// 连续失败计数器，由 set_online / set_offline 管理
static CONSECUTIVE_FAILURES: AtomicU32 = AtomicU32::new(0);

/// Set agent to Online mode (server connected).
/// 重置连续失败计数和网络异常标记。
pub fn set_online() {
    let prev = AGENT_MODE.swap(AgentMode::Online as u8, Ordering::Relaxed);
    if prev != AgentMode::Online as u8 {
        println!("[agent_mode] 离线 → 在线");
    }
    CONSECUTIVE_FAILURES.store(0, Ordering::Relaxed);
    ADMISSION_NETWORK_ANOMALY.store(false, Ordering::Relaxed);
}

/// Set agent to Offline mode (server unreachable).
/// 单次失败不会立即切离线，连续失败达阈值才切，同时标记网络异常。
/// 返回 true 表示本次调用真正触发了切离线（首次达到阈值）。
pub fn set_offline() -> bool {
    let fails = CONSECUTIVE_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
    if fails < NETWORK_ANOMALY_THRESHOLD {
        return false; // 还没到阈值，不切离线
    }
    let prev = AGENT_MODE.swap(AgentMode::Offline as u8, Ordering::Relaxed);
    let switched = prev != AgentMode::Offline as u8;
    if switched {
        println!("[agent_mode] 在线 → 离线（连续 {} 次失败）", fails);
    }
    if !ADMISSION_NETWORK_ANOMALY.load(Ordering::Relaxed) {
        println!("[agent_mode] 连续 {} 次失败，标记网络异常", fails);
        ADMISSION_NETWORK_ANOMALY.store(true, Ordering::Relaxed);
    }
    switched
}

/// Check if we are in offline mode. If online, return PERMISSION_DENIED.
pub fn require_offline() -> Result<(), Status> {
    if AGENT_MODE.load(Ordering::Relaxed) == AgentMode::Online as u8 {
        return Err(Status::permission_denied(
            "在线模式下不允许此操作，请通过管理平台执行"
        ));
    }
    Ok(())
}

// ── 网络故障回调：各 crate 在请求服务器失败时通知，由 agent_local_svc 注册处理 ──

/// 网络故障回调类型（准入检查 + 重连逻辑）
type NetworkFailureCallback = fn();

/// 注册的网络故障回调，由 agent_local_svc 在初始化时设置
static NETWORK_FAILURE_CALLBACK: LazyLock<Mutex<Option<NetworkFailureCallback>>> =
    LazyLock::new(|| Mutex::new(None));

/// 注册网络故障回调（由 agent_local_svc 调用一次）
pub fn register_network_failure_callback(cb: NetworkFailureCallback) {
    *NETWORK_FAILURE_CALLBACK.lock().unwrap() = Some(cb);
}

/// 通知网络故障：累计失败计数，仅在首次切离线时触发一次准入检查。
///
/// 供 task_fetcher / reporter 等任意 crate 在请求服务器超时/失败时调用。
/// 无轮询，纯事件驱动。已离线后不会重复触发——由 auto-detection 自身循环负责重试。
pub fn notify_network_failure() {
    let just_went_offline = set_offline();
    if just_went_offline {
        if let Some(cb) = *NETWORK_FAILURE_CALLBACK.lock().unwrap() {
            cb();
        }
    }
}
