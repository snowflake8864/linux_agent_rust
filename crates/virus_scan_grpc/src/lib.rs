pub mod proto {
    tonic::include_proto!("virus_scan");
    tonic::include_proto!("vuln_scan");
}

pub mod clamav_scanner;
pub mod scan_task_mgr;
pub mod grpc_service;
pub mod service;
pub mod vuln_service;

pub use clamav_scanner::{ClamAVScanner, ClamAVConfig, ScanResult};
pub use scan_task_mgr::ScanTaskManager;
pub use grpc_service::VirusScanGrpcService;
pub use vuln_service::VulnScanGrpcService;
pub use service::StartVirusScanGrpcService;

pub const STREAM_BUFFER_SIZE: usize = 256;
