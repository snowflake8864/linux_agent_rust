//crates/kernel_event/src/lib.rs
// crates/kernel_event/src/lib.rs
pub mod event_handler;
pub use event_handler::StartKernelHandler;
pub use event_handler::EventHandler;
pub mod msg_handler;
pub use msg_handler::KosecsMsgData;



// 定义 CallbackFn 类型
type CallbackFn = Box<dyn Fn(&[u8], u32) -> Result<(), String> + Send + Sync>;

// 定义 EventCallback trait（实例方法）
pub trait EventCallback: Send + Sync + 'static {
    fn handle_event(&self, data: &[u8], data_len: u32) -> Result<(), String>;
}

// 为自由函数实现 EventCallback
impl<F: Fn(&[u8], u32) -> Result<(), String> + Send + Sync + 'static> EventCallback for F {
    fn handle_event(&self, data: &[u8], data_len: u32) -> Result<(), String> {
        (self)(data, data_len) // 使用 self 调用 Fn
    }
}
