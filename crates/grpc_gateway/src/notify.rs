//! Global broadcast/sender channels shared across crates.
//! Placed in grpc_gateway to avoid circular dependencies.

use std::sync::{LazyLock, OnceLock};
use tokio::sync::{broadcast, mpsc};

use crate::alert::AlertEvent;
use crate::policy_watch::PolicyChangeType;

// ============================================================================
// Policy change notifications (task_fetcher → gRPC PolicyWatchService)
// ============================================================================

pub static POLICY_CHANGE_TX: LazyLock<broadcast::Sender<PolicyChangeType>> =
    LazyLock::new(|| {
        let (tx, _) = broadcast::channel(64);
        tx
    });

pub fn notify_policy_change(change: PolicyChangeType) {
    let _ = POLICY_CHANGE_TX.send(change);
}

pub fn subscribe_policy_changes() -> broadcast::Receiver<PolicyChangeType> {
    POLICY_CHANGE_TX.subscribe()
}

// ============================================================================
// Alert broadcast (log_worker → gRPC AlertService)
// ============================================================================

pub static ALERT_TX: LazyLock<broadcast::Sender<AlertEvent>> =
    LazyLock::new(|| {
        let (tx, _) = broadcast::channel(256);
        tx
    });

/// Called by log_worker when a new AuditLogInfo arrives.
pub fn broadcast_alert(event: AlertEvent) {
    let _ = ALERT_TX.send(event);
}

/// Called by gRPC AlertService to subscribe.
pub fn subscribe_alerts() -> broadcast::Receiver<AlertEvent> {
    ALERT_TX.subscribe()
}

// ============================================================================
// Local task submission (gRPC LocalTaskService → task_fetcher)
// ============================================================================

/// Sender for locally submitted task IDs (from gRPC to task_fetcher).
/// Initialized by task_fetcher::run() on startup.
pub static LOCAL_TASK_TX: OnceLock<mpsc::UnboundedSender<i32>> = OnceLock::new();

/// Called by task_fetcher::run() to set itself as the receiver.
pub fn init_local_task_rx() -> mpsc::UnboundedReceiver<i32> {
    let (tx, rx) = mpsc::unbounded_channel();
    LOCAL_TASK_TX.set(tx).ok(); // silently ignore double-init
    rx
}

/// Called by gRPC LocalTaskService to submit a task.
/// Returns false if task_fetcher hasn't initialized the channel yet.
pub fn submit_local_task(task_id: i32) -> bool {
    match LOCAL_TASK_TX.get() {
        Some(tx) => tx.send(task_id).is_ok(),
        None => false,
    }
}

// ============================================================================
// DirPolicy / ExtortPolicy caches (populated by task_fetcher, read by gRPC)
// ============================================================================

use std::sync::Mutex;

pub static DIR_POLICY_CACHE: LazyLock<Mutex<Vec<crate::dir_policy::DirectionScanRule>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

pub static EXTORT_POLICY_CACHE: LazyLock<Mutex<Vec<crate::extort_policy::ExtortProtectRule>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));
