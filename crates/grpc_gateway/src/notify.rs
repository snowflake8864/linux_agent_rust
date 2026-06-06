//! Global broadcast channel for policy change notifications.
//! Both HTTP handlers (task_fetcher) and gRPC handlers (agent_local_svc) use this.
//! Placed in grpc_gateway to avoid circular dependencies between crates.

use std::sync::LazyLock;
use tokio::sync::broadcast;

use crate::policy_watch::PolicyChangeType;

/// Global broadcast sender for policy change events.
/// HTTP handlers call `send()` after updating policies.
/// gRPC PolicyWatchService subscribers receive from this.
pub static POLICY_CHANGE_TX: LazyLock<broadcast::Sender<PolicyChangeType>> =
    LazyLock::new(|| {
        let (tx, _) = broadcast::channel(64);
        tx
    });

/// Send a policy change notification. Called by HTTP handlers.
pub fn notify_policy_change(change: PolicyChangeType) {
    let _ = POLICY_CHANGE_TX.send(change);
}

/// Subscribe to policy change notifications. Called by gRPC PolicyWatchService.
pub fn subscribe_policy_changes() -> broadcast::Receiver<PolicyChangeType> {
    POLICY_CHANGE_TX.subscribe()
}
