// crates/kernel_event/src/lib.rs
pub mod event_handler;
pub use event_handler::StartKernelHandler;
pub use event_handler::EventHandler;
pub use event_handler::send_data_to_kernel;
pub mod msg_handler;
pub use msg_handler::KosecsMsgData;
use std::future::Future;
use std::pin::Pin;


pub type CallbackFn = Box<
    dyn Fn(&[u8], u32) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send + Sync + 'static,
>;

pub trait EventCallback: Send + Sync + 'static {
    fn handle_event(
        &self,
        data: &[u8],
        data_len: u32,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
}

impl<F, Fut> EventCallback for F
where
    F: Fn(&[u8], u32) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), String>> + Send + 'static,
{
    fn handle_event(&self, data: &[u8], data_len: u32) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> {
        Box::pin((self)(data, data_len))
    }
}
