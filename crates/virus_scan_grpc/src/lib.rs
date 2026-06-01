pub mod proto {
    tonic::include_proto!("virus_scan");
    tonic::include_proto!("vuln_scan");
    tonic::include_proto!("lynis_scan");
}

pub mod vigilixav_scanner;
pub mod scan_task_mgr;
pub mod grpc_service;
pub mod service;
pub mod vuln_service;
pub mod lynis_scanner;
pub mod lynis_service;

pub use vigilixav_scanner::{VigilixAVConnectionPool, VigilixAVConfig, ScanResult, DispositionAction, DispositionResult};
pub use scan_task_mgr::ScanTaskManager;
pub use grpc_service::VirusScanGrpcService;
pub use vuln_service::VulnScanGrpcService;
pub use lynis_service::LynisScanGrpcService;
pub use service::StartVirusScanGrpcService;

pub const STREAM_BUFFER_SIZE: usize = 256;
