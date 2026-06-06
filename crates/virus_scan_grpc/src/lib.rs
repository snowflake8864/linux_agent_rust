// Re-export proto types from grpc_gateway
pub use grpc_gateway::virus_scan;
pub use grpc_gateway::vuln_scan;

pub mod clamav_scanner;
pub mod scan_task_mgr;
pub mod grpc_service;
pub mod service;
pub mod vuln_service;

pub use clamav_scanner::{ClamAVConnectionPool, ClamAVConfig, ScanResult};
pub use scan_task_mgr::ScanTaskManager;
pub use grpc_service::VirusScanGrpcService;
pub use vuln_service::VulnScanGrpcService;
pub use service::StartVirusScanGrpcService;

pub const STREAM_BUFFER_SIZE: usize = 256;
