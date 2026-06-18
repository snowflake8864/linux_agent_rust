pub mod data_hub;

// Implemented handlers
pub mod agent_status_impl;
pub mod alert_impl;
pub mod config_impl;
pub mod task_local_impl;
pub mod process_policy_impl;
pub mod peripheral_policy_impl;
pub mod ip_policy_impl;
pub mod data_query_impl;
pub mod outreach_detect_impl;
pub mod policy_watch_impl;
pub mod protection_mode_impl;
pub mod admission_impl;

// Stub handlers (need deeper integration)
pub mod stub_handlers;

// Re-exports
pub use data_hub::{AgentDataHub, AgentMode, AGENT_MODE, require_offline, set_online, set_offline,
    set_offline_and_check_admission, start_connectivity_monitor, check_server_reachable,
    ADMISSION_MODE, ADMISSION_EFFECTIVE, ADMISSION_DETECTING, ADMISSION_NETWORK_ANOMALY};
pub use config_impl::ConfigServiceImpl;
pub use process_policy_impl::ProcessPolicyServiceImpl;
pub use peripheral_policy_impl::PeripheralPolicyServiceImpl;
pub use ip_policy_impl::IpPolicyServiceImpl;
pub use data_query_impl::DataQueryServiceImpl;
pub use outreach_detect_impl::OutreachDetectServiceImpl;
pub use policy_watch_impl::PolicyWatchServiceImpl;
pub use protection_mode_impl::{ProcessDefenseServiceImpl, PeripheralDefenseServiceImpl};
pub use admission_impl::AdmissionServiceImpl;
pub use agent_status_impl::AgentStatusServiceImpl;
pub use alert_impl::AlertServiceImpl;
pub use task_local_impl::LocalTaskServiceImpl;
pub use stub_handlers::{
    DirPolicyServiceImpl, ExtortPolicyServiceImpl, JumpServiceImpl,
    BackupServiceImpl, TrustDirServiceImpl, VirtualPortServiceImpl,
};
