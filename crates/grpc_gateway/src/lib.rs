// Each tonic::include_proto! call creates a module at the crate root level.
// Generated cross-package references use `super::super::package::Type`,
// which resolves correctly when all packages are siblings at crate root.

pub mod common { tonic::include_proto!("common"); }
pub mod virus_scan { tonic::include_proto!("virus_scan"); }
pub mod vuln_scan { tonic::include_proto!("vuln_scan"); }
pub mod agent_status { tonic::include_proto!("agent_status"); }
pub mod alert { tonic::include_proto!("alert"); }
pub mod config { tonic::include_proto!("config"); }
pub mod task_local { tonic::include_proto!("task_local"); }
pub mod process_policy { tonic::include_proto!("process_policy"); }
pub mod peripheral_policy { tonic::include_proto!("peripheral_policy"); }
pub mod dir_policy { tonic::include_proto!("dir_policy"); }
pub mod extort_policy { tonic::include_proto!("extort_policy"); }
pub mod ip_policy { tonic::include_proto!("ip_policy"); }
pub mod jump { tonic::include_proto!("jump"); }
pub mod backup { tonic::include_proto!("backup"); }
pub mod outreach_detect { tonic::include_proto!("outreach_detect"); }
pub mod trust_dir { tonic::include_proto!("trust_dir"); }
pub mod virtual_port { tonic::include_proto!("virtual_port"); }
pub mod data_query { tonic::include_proto!("data_query"); }
pub mod policy_watch { tonic::include_proto!("policy_watch"); }
pub mod protection_mode { tonic::include_proto!("protection_mode"); }
pub mod admission { tonic::include_proto!("admission"); }
pub mod backend { tonic::include_proto!("backend"); }

pub mod notify;

pub mod agent_mode;
