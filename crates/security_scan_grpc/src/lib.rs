//! 系统安全检测 gRPC 服务
//!
//! 单独拆成一个 crate，只依赖 `grpc_gateway`（proto 定义）+ tonic/tokio/logging，
//! 不依赖 agent_local_svc 等其它业务 crate。
//!
//! 职责：通过 gRPC 触发 `/opt/osec/SecurityScan_linux.sh` 系统安全检测脚本，
//! 脚本执行时间较长（逐项检测、每项间隔 0.5s），因此使用 `tokio::process::Command`
//! 异步拉起、服务端流式返回，避免阻塞 tokio runtime 与 gRPC 处理线程。

// Re-export proto types from grpc_gateway
pub use grpc_gateway::security_scan;

pub mod grpc_service;

pub use grpc_service::SecurityScanGrpcService;

/// 服务端事件流缓冲大小
pub const STREAM_BUFFER_SIZE: usize = 256;
