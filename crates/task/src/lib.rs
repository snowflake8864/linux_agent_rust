// crates/task/src/lib.rs
pub mod task_fetcher;
pub mod virtual_port_rule;
pub mod tamper_protect_rule;

// 导出结构体和函数供外部使用
pub use virtual_port_rule::{VirtualPortRule, deserialize_port_range, deserialize_dest_port};
pub use task_fetcher::TaskService;
