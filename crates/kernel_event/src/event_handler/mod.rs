//crates/kernel_event/src/event_handler/mod.rs
#![allow(dead_code)]
use std::io::{self, Write};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex; // 使用 tokio::sync::Mutex
use tokio::sync::mpsc;
use reporter::FileAuditLogInfo;
use std::fmt;
use crate::msg_handler::KosecsMsgData;
use super::{CallbackFn, EventCallback}; // 从 lib.rs 导入
use logging::{log_info,log_error};
use netlink::netlink::NlSockInfo; // 引入 NLPolicyType
use common::
    manager::boot::BootManager;
use std::pin::Pin;
use std::future::Future;
use reporter::file_audit::FileAuditHandler;
use zcopy_mgr::ZcopyMgr;


//use tokio::sync::mpsc;

// 枚举：NLPolicyType
#[derive(Eq, Hash, PartialEq, Debug)] // 自动实现 Debug 和 Hash, Eq, PartialEq
#[allow(non_camel_case_types)]
enum NLPolicyType {
    NL_POLICY_CMD_UNSPEC,
    NL_POLICY_CMD_ECHO = 1,
    NL_POLICY_SIMPLE_END,
    NL_POLICY_BOOL_END,
    NL_POLICY_CMD_REGISTER,
    NL_POLICY_CMD_ADD_SYMBOL,
    NL_POLICY_CMD_UNREGISTER,
    NL_POLICY_MD5RULE_END,
    NL_POLICY_DEFENSE_UNSPEC = 0x100,
    NL_POLICY_DEFENSE_SWITCHER,
    NL_POLICY_DEFENSE_ADD_WHITE_EXE,
    NL_POLICY_SELF_SWITCHER,
    NL_POLICY_GLOBAL_DIR,
    NL_POLICY_EXIPORT_RULE,
    NL_POLICY_PROTECT_RULE,
    NL_POLICY_DEFENSE_FILE_PROCESS_POLICY,
    NL_POLICY_NETWORK_UNSPEC = 0x700,
    NL_POLICY_NETWORK_POLICY,
    NL_POLICY_NETSYSLOG_POLICY,
    NL_POLICY_NETWORK_SERVERIP_POLICY,
    NL_POLICY_NETWORK_NETBLOCK,
    NL_POLICY_NETWORK_BUSINESS_PORT_POLICY,
    NL_POLICY_NETWORK_CLOSE,
    NL_MAX_CLASSIC_INDEX,
    NL_POLICY_CMD_NOTIFY = 0x503,
    NL_POLICY_CMD_REGISTERED_NOTIFY,
    NL_POLICY_AV_PROCESS_EXEC_NOTIFY,
    NL_POLICY_AV_PROCESS_EXEC_ZCOPY_NOTIFY,
    NL_POLICY_AV_FILE_CHANGE_NOTIFY,
    NL_POLICY_AV_FILE_RENAME_NOTIFY,
    NL_POLICY_AV_FILE_AUDIT_ZCOPY_NOTIFY,
    NL_POLICY_AV_SELF_PROTECTION_NOTIFY,
    NL_POLICY_NET_PORT_NOTIFY,
    NL_POLICY_NET_PORT_ZCOPY_NOTIFY,
    NL_POLICY_NET_CONNECT_PORT_IN_NOTIFY,
    NL_POLICY_NET_CONNECT_PORT_OUT_NOTIFY,
    NL_POLICY_NET_CONNECT_PORT_NOTIFY,
    NL_POLICY_NET_DNS_PORT_NOTIFY,
    NL_POLICY_NET_DNS_PORT_ZCOPY_NOTIFY,
    NL_POLICY_INFO_KERN_TO_APP_NOTIFY,
    NL_POLICY_UPDATE_PROCESS_RULE_NOTIFY,
    NL_MAX_INDEX = 0x1000, // 4096
}

impl NLPolicyType {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(NLPolicyType::NL_POLICY_CMD_UNSPEC),
            1 => Some(NLPolicyType::NL_POLICY_CMD_ECHO),
            2 => Some(NLPolicyType::NL_POLICY_SIMPLE_END),
            3 => Some(NLPolicyType::NL_POLICY_BOOL_END),
            4 => Some(NLPolicyType::NL_POLICY_CMD_REGISTER),
            5 => Some(NLPolicyType::NL_POLICY_CMD_ADD_SYMBOL),
            6 => Some(NLPolicyType::NL_POLICY_CMD_UNREGISTER),
            7 => Some(NLPolicyType::NL_POLICY_MD5RULE_END),
            0x100 => Some(NLPolicyType::NL_POLICY_DEFENSE_UNSPEC),
            0x101 => Some(NLPolicyType::NL_POLICY_DEFENSE_SWITCHER),
            0x102 => Some(NLPolicyType::NL_POLICY_DEFENSE_ADD_WHITE_EXE),
            0x103 => Some(NLPolicyType::NL_POLICY_SELF_SWITCHER),
            0x104 => Some(NLPolicyType::NL_POLICY_GLOBAL_DIR),
            0x105 => Some(NLPolicyType::NL_POLICY_EXIPORT_RULE),
            0x106 => Some(NLPolicyType::NL_POLICY_PROTECT_RULE),
            0x107 => Some(NLPolicyType::NL_POLICY_DEFENSE_FILE_PROCESS_POLICY),
            0x700 => Some(NLPolicyType::NL_POLICY_NETWORK_UNSPEC),
            0x701 => Some(NLPolicyType::NL_POLICY_NETWORK_POLICY),
            0x702 => Some(NLPolicyType::NL_POLICY_NETSYSLOG_POLICY),
            0x703 => Some(NLPolicyType::NL_POLICY_NETWORK_SERVERIP_POLICY),
            0x704 => Some(NLPolicyType::NL_POLICY_NETWORK_NETBLOCK),
            0x705 => Some(NLPolicyType::NL_POLICY_NETWORK_BUSINESS_PORT_POLICY),
            0x706 => Some(NLPolicyType::NL_POLICY_NETWORK_CLOSE),
            0x800 => Some(NLPolicyType::NL_MAX_CLASSIC_INDEX),
            0x503 => Some(NLPolicyType::NL_POLICY_CMD_NOTIFY),
            0x504 => Some(NLPolicyType::NL_POLICY_CMD_REGISTERED_NOTIFY),
            0x505 => Some(NLPolicyType::NL_POLICY_AV_PROCESS_EXEC_NOTIFY),
            0x506 => Some(NLPolicyType::NL_POLICY_AV_PROCESS_EXEC_ZCOPY_NOTIFY),
            0x507 => Some(NLPolicyType::NL_POLICY_AV_FILE_CHANGE_NOTIFY),
            0x508 => Some(NLPolicyType::NL_POLICY_AV_FILE_RENAME_NOTIFY),
            0x509 => Some(NLPolicyType::NL_POLICY_AV_FILE_AUDIT_ZCOPY_NOTIFY),
            0x50A => Some(NLPolicyType::NL_POLICY_AV_SELF_PROTECTION_NOTIFY),
            0x50B => Some(NLPolicyType::NL_POLICY_NET_PORT_NOTIFY),
            0x50C => Some(NLPolicyType::NL_POLICY_NET_PORT_ZCOPY_NOTIFY),
            0x50D => Some(NLPolicyType::NL_POLICY_NET_CONNECT_PORT_IN_NOTIFY),
            0x50E => Some(NLPolicyType::NL_POLICY_NET_CONNECT_PORT_OUT_NOTIFY),
            0x50F => Some(NLPolicyType::NL_POLICY_NET_CONNECT_PORT_NOTIFY),
            0x510 => Some(NLPolicyType::NL_POLICY_NET_DNS_PORT_NOTIFY),
            0x511 => Some(NLPolicyType::NL_POLICY_NET_DNS_PORT_ZCOPY_NOTIFY),
            0x512 => Some(NLPolicyType::NL_POLICY_INFO_KERN_TO_APP_NOTIFY),
            0x513 => Some(NLPolicyType::NL_POLICY_UPDATE_PROCESS_RULE_NOTIFY),
            0x1000 => Some(NLPolicyType::NL_MAX_INDEX),
            _ => None,
        }
    }
}
// 实现 Display trait，便于以字符串形式输出 NLPolicyType
impl fmt::Display for NLPolicyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let result = match *self {
            NLPolicyType::NL_POLICY_CMD_UNSPEC => "NL_POLICY_CMD_UNSPEC",
            NLPolicyType::NL_POLICY_CMD_ECHO => "NL_POLICY_CMD_ECHO",
            NLPolicyType::NL_POLICY_SIMPLE_END => "NL_POLICY_SIMPLE_END",
            NLPolicyType::NL_POLICY_BOOL_END => "NL_POLICY_BOOL_END",
            NLPolicyType::NL_POLICY_CMD_REGISTER => "NL_POLICY_CMD_REGISTER",
            NLPolicyType::NL_POLICY_CMD_ADD_SYMBOL => "NL_POLICY_CMD_ADD_SYMBOL",
            NLPolicyType::NL_POLICY_CMD_UNREGISTER => "NL_POLICY_CMD_UNREGISTER",
            NLPolicyType::NL_POLICY_MD5RULE_END => "NL_POLICY_MD5RULE_END",
            NLPolicyType::NL_POLICY_DEFENSE_UNSPEC => "NL_POLICY_DEFENSE_UNSPEC",
            NLPolicyType::NL_POLICY_DEFENSE_SWITCHER => "NL_POLICY_DEFENSE_SWITCHER",
            NLPolicyType::NL_POLICY_DEFENSE_ADD_WHITE_EXE => "NL_POLICY_DEFENSE_ADD_WHITE_EXE",
            NLPolicyType::NL_POLICY_SELF_SWITCHER => "NL_POLICY_SELF_SWITCHER",
            NLPolicyType::NL_POLICY_GLOBAL_DIR => "NL_POLICY_GLOBAL_DIR",
            NLPolicyType::NL_POLICY_EXIPORT_RULE => "NL_POLICY_EXIPORT_RULE",
            NLPolicyType::NL_POLICY_PROTECT_RULE => "NL_POLICY_PROTECT_RULE",
            NLPolicyType::NL_POLICY_DEFENSE_FILE_PROCESS_POLICY => "NL_POLICY_DEFENSE_FILE_PROCESS_POLICY",
            NLPolicyType::NL_POLICY_NETWORK_UNSPEC => "NL_POLICY_NETWORK_UNSPEC",
            NLPolicyType::NL_POLICY_NETWORK_POLICY => "NL_POLICY_NETWORK_POLICY",
            NLPolicyType::NL_POLICY_NETSYSLOG_POLICY => "NL_POLICY_NETSYSLOG_POLICY",
            NLPolicyType::NL_POLICY_NETWORK_SERVERIP_POLICY => "NL_POLICY_NETWORK_SERVERIP_POLICY",
            NLPolicyType::NL_POLICY_NETWORK_NETBLOCK => "NL_POLICY_NETWORK_NETBLOCK",
            NLPolicyType::NL_POLICY_NETWORK_BUSINESS_PORT_POLICY => "NL_POLICY_NETWORK_BUSINESS_PORT_POLICY",
            NLPolicyType::NL_POLICY_NETWORK_CLOSE => "NL_POLICY_NETWORK_CLOSE",
            NLPolicyType::NL_MAX_CLASSIC_INDEX => "NL_MAX_CLASSIC_INDEX",
            NLPolicyType::NL_POLICY_CMD_NOTIFY => "NL_POLICY_CMD_NOTIFY",
            NLPolicyType::NL_POLICY_CMD_REGISTERED_NOTIFY => "NL_POLICY_CMD_REGISTERED_NOTIFY",
            NLPolicyType::NL_POLICY_AV_PROCESS_EXEC_NOTIFY => "NL_POLICY_AV_PROCESS_EXEC_NOTIFY",
            NLPolicyType::NL_POLICY_AV_PROCESS_EXEC_ZCOPY_NOTIFY => "NL_POLICY_AV_PROCESS_EXEC_ZCOPY_NOTIFY",
            NLPolicyType::NL_POLICY_AV_FILE_CHANGE_NOTIFY => "NL_POLICY_AV_FILE_CHANGE_NOTIFY",
            NLPolicyType::NL_POLICY_AV_FILE_RENAME_NOTIFY => "NL_POLICY_AV_FILE_RENAME_NOTIFY",
            NLPolicyType::NL_POLICY_AV_FILE_AUDIT_ZCOPY_NOTIFY => "NL_POLICY_AV_FILE_AUDIT_ZCOPY_NOTIFY",
            NLPolicyType::NL_POLICY_AV_SELF_PROTECTION_NOTIFY => "NL_POLICY_AV_SELF_PROTECTION_NOTIFY",
            NLPolicyType::NL_POLICY_NET_PORT_NOTIFY => "NL_POLICY_NET_PORT_NOTIFY",
            NLPolicyType::NL_POLICY_NET_PORT_ZCOPY_NOTIFY => "NL_POLICY_NET_PORT_ZCOPY_NOTIFY",
            NLPolicyType::NL_POLICY_NET_CONNECT_PORT_IN_NOTIFY => "NL_POLICY_NET_CONNECT_PORT_IN_NOTIFY",
            NLPolicyType::NL_POLICY_NET_CONNECT_PORT_OUT_NOTIFY => "NL_POLICY_NET_CONNECT_PORT_OUT_NOTIFY",
            NLPolicyType::NL_POLICY_NET_CONNECT_PORT_NOTIFY => "NL_POLICY_NET_CONNECT_PORT_NOTIFY",
            NLPolicyType::NL_POLICY_NET_DNS_PORT_NOTIFY => "NL_POLICY_NET_DNS_PORT_NOTIFY",
            NLPolicyType::NL_POLICY_NET_DNS_PORT_ZCOPY_NOTIFY => "NL_POLICY_NET_DNS_PORT_ZCOPY_NOTIFY",
            NLPolicyType::NL_POLICY_INFO_KERN_TO_APP_NOTIFY => "NL_POLICY_INFO_KERN_TO_APP_NOTIFY",
            NLPolicyType::NL_POLICY_UPDATE_PROCESS_RULE_NOTIFY => "NL_POLICY_UPDATE_PROCESS_RULE_NOTIFY",
            NLPolicyType::NL_MAX_INDEX => "NL_MAX_INDEX",
        };
        write!(f, "{}", result)
    }
}


pub struct EventHandler {
    callbacks: Arc<Mutex<HashMap<NLPolicyType, CallbackFn>>>,
}

impl EventHandler {
    pub fn new() -> Self {
        EventHandler {
            callbacks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // 注册事件回调
    pub async fn register_event_handler(&mut self, policy_type: NLPolicyType, callback: CallbackFn) {
        self.callbacks.lock().await.insert(policy_type, callback);
    }
    // 处理事件
    pub async fn handle_event(&self, data_type: u32, data: &[u8], data_len: u32) -> Result<(), String> {
        if let Some(policy_type) = NLPolicyType::from_u32(data_type) {
            log_info!("Handling event for policy type: {}", policy_type);
            if let Some(callback) = self.callbacks.lock().await.get(&policy_type) {
                callback(data, data_len)
            } else {
                Err(format!("No callback registered for policy type {:?}", policy_type))
            }
        } else {
            Err(format!("Unknown data type: {}", data_type))
        }
    }

}


// 定义 ECHO 命令的处理函数
fn handle_echo(data: &[u8], data_len: u32) -> Result<(), String> {
    let data_str = String::from_utf8_lossy(data); // 将字节数据转换为字符串
    println!("Handling ECHO data: {}", data_str);  // 打印字符串
    // 处理复杂逻辑
    Ok(())
}

// 定义 REGISTER 命令的处理函数
fn handle_register(data: &[u8], _data_len: u32) -> Result<(), String> {
    println!("Handling REGISTER data: {:?}", data);
    Ok(())
}
// 定义 ADD_SYMBOL 命令的处理函数
fn handle_add_symbol(data: &[u8], _data_len: u32) -> Result<(), String> {
    println!("Handling ADD_SYMBOL data: {:?}", data);
    Ok(())
}


// 定义 UNREGISTER 命令的处理函数
fn handle_unregister(data: &[u8], _data_len: u32) -> Result<(), String> {
    println!("Handling UNREGISTER data: {:?}", data);
    Ok(())
}



pub async fn register_default_event_handlers(event_handler: &Arc<Mutex<EventHandler>>) {
    async fn register<T: EventCallback>(
        event_handler: &Arc<Mutex<EventHandler>>,
        policy_type: NLPolicyType,
        handler: T,
    ) {
    log_info!("Starting to register default event handlers");
        let mut handler_guard = event_handler.lock().await;
        handler_guard
            .register_event_handler(
                policy_type,
                Box::new(move |data: &[u8], data_len: u32| handler.handle_event(data, data_len)),
            )
            .await;
    }

    register(event_handler, NLPolicyType::NL_POLICY_CMD_ECHO, handle_echo).await;
    register(event_handler, NLPolicyType::NL_POLICY_CMD_REGISTER, handle_register).await;
    register(event_handler, NLPolicyType::NL_POLICY_CMD_ADD_SYMBOL, handle_add_symbol).await;
    register(event_handler, NLPolicyType::NL_POLICY_CMD_UNREGISTER, handle_unregister).await;
}

pub async fn register_user_event_handlers(
    event_handler: &Arc<Mutex<EventHandler>>,
    file_audit_log_tx: mpsc::Sender<FileAuditLogInfo>,
) {
    log_info!("Starting to register user event handlers");

    let zcopy_mgr = match ZcopyMgr::new() {
        Ok(zcopy_mgr) => {
            log_info!("ZcopyMgr created successfully");
            Arc::new(zcopy_mgr)
        }
        Err(e) => {
            log_error!("Failed to create ZcopyMgr: {}, skipping ZcopyMgr-dependent registrations", e);
            return;
        }
    };

    async fn register<T: EventCallback>(
        event_handler: &Arc<Mutex<EventHandler>>,
        policy_type: NLPolicyType,
        handler: T,
    ) {
        log_info!("Registering callback for policy_type: {:?}", policy_type);
        let mut handler_guard = event_handler.lock().await;
        handler_guard
            .register_event_handler(
                policy_type,
                Box::new(move |data: &[u8], data_len: u32| handler.handle_event(data, data_len)),
            )
            .await;
        log_info!("Callback registered ===========");
    }

    let file_audit_handler = FileAuditHandler::new(zcopy_mgr.clone(), file_audit_log_tx);
    log_info!("Registering NL_POLICY_AV_FILE_AUDIT_ZCOPY_NOTIFY callback");
    register(
        event_handler,
        NLPolicyType::NL_POLICY_AV_FILE_AUDIT_ZCOPY_NOTIFY,
        move |data: &[u8], data_len: u32| file_audit_handler.handle_file_zcopy_oper(data, data_len),
    )
    .await;
    log_info!("NL_POLICY_AV_FILE_AUDIT_ZCOPY_NOTIFY callback registered");
}

pub trait StartKernelHandler {
    fn start_kernel_send_handler(
        &mut self,
        nl_sock: NlSockInfo,
        event_handler: Arc<Mutex<EventHandler>>,
        file_audit_log_tx: mpsc::Sender<FileAuditLogInfo>
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>;

    fn start_kernel_rcv_handler(
        &mut self,
        nl_sock: NlSockInfo,
        event_handler: Arc<Mutex<EventHandler>>
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>;
}

impl StartKernelHandler for BootManager {
    fn start_kernel_send_handler(
        &mut self,
        nl_sock: NlSockInfo,
        event_handler: Arc<Mutex<EventHandler>>,
        file_audit_log_tx: mpsc::Sender<FileAuditLogInfo>,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {

            register_default_event_handlers(&event_handler).await;
            register_user_event_handlers(&event_handler, file_audit_log_tx).await;
            send_data_to_kernel(&nl_sock).map_err(|e| e.to_string())?;
            Ok("=========后台任务已启动.".to_string())
        })
    }

    fn start_kernel_rcv_handler(
        &mut self,
        nl_sock: NlSockInfo,
        event_handler: Arc<Mutex<EventHandler>>,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                nl_sock
                    .receive_messages_loop(|data| {
                        let payload = &data[16..];
                        match KosecsMsgData::parse(&payload) {
                            Some(msg) => {
                                if msg.data_type == 1 {
                                    let data = msg.payload;
                                    let data_str = String::from_utf8_lossy(data);
                                    log_info!("Handling ECHO data: {}", data_str);
                                } else {
                                    log_info!(
                                        "Handling event for policy type: {},{:?}",
                                        msg.data_type,
                                        msg.payload
                                    );
                                    let event_handler = event_handler.clone();
                                    let payload_owned = msg.payload.to_vec();
                                    let data_type = msg.data_type;
                                    let data_len = msg.data_len;
                                    tokio::spawn(async move {
                                        if let Err(e) = event_handler
                                            .lock()
                                                .await
                                                .handle_event(data_type, &payload_owned, data_len)
                                                .await
                                        {
                                            log_error!("Failed to handle event: {}", e);
                                        }
                                    });
                                }
                            }
                            None => {
                                log_error!("无法解析内核消息，格式错误或长度不足: {:x?}", data);
                            }
                        }
                    })
                .map_err(|e| e.to_string())
            })
            .await
                .unwrap()?;
            Ok("=========后台任务已启动.".to_string())
        })
    }

}


use std::net::Ipv4Addr;
pub fn send_data_to_kernel(nl_sock: &NlSockInfo) -> Result<String, String> {
    // 这里是所有与内核交互的逻辑
    // 发送消息到内核（消息类型、数据等完全隐藏在这里）

    if let Err(e) = nl_sock.send_message(1, b"set portid") {
        return Err(format!("Failed to send set portid message: {}", e));
    }

    let ip = Ipv4Addr::new(192, 168, 0, 1);
    let ip_bytes = ip.octets();
    if let Err(e) = nl_sock.send_message(1, &ip_bytes) {
        return Err(format!("Failed to send IP address: {}", e));
    }

    let data: Vec<u8> = vec![1, 2, 3, 4, 5];
    if let Err(e) = nl_sock.send_message(1, &data) {
        return Err(format!("Failed to send custom data: {}", e));
    }

    Ok("Data sent successfully".to_string())
}


