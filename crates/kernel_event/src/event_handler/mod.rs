// crates/kernel_event/src/event_handler/mod.rs

#![allow(dead_code)]
use std::collections::HashMap;
use std::sync::Arc;
use std::fmt;
use std::pin::Pin;
use std::future::Future;

use tokio::sync::{Mutex, mpsc};

use reporter::AuditLogInfo;
use crate::msg_handler::KosecsMsgData;
use super::{CallbackFn}; // 删除 EventCallback
use logging::{log_info, log_error};
use netlink::netlink::NlSockInfo; // 引入 NLPolicyType
use common::manager::boot::BootManager;
use reporter::file_audit::FileAuditHandler;
use reporter::process_audit::ProcessAuditHandler;
use hostinfo::net_app::handler::NetAppHandler;
use zcopy_mgr::ZcopyMgr;

#[derive(Eq, Hash, PartialEq, Debug)]
#[allow(non_camel_case_types)]
pub enum NLPolicyType {
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
    NL_POLICY_SERVER_LISTEN_NOTIFY,
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
            0x514 => Some(NLPolicyType::NL_POLICY_SERVER_LISTEN_NOTIFY),
            0x1000 => Some(NLPolicyType::NL_MAX_INDEX),
            _ => None,
        }
    }
}

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
            NLPolicyType::NL_POLICY_SERVER_LISTEN_NOTIFY => "NL_POLICY_SERVER_LISTEN_NOTIFY",
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

    pub async fn register_event_handler<F, Fut>(&mut self, policy_type: NLPolicyType, callback: F)
    where
        F: Fn(&[u8], u32) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        let boxed_callback: CallbackFn = Box::new(move |data, len| {
            Box::pin(callback(data, len)) as Pin<Box<dyn Future<Output = Result<(), String>> + Send>>
        });
        self.callbacks.lock().await.insert(policy_type, boxed_callback);
    }

    pub async fn handle_event(
        &self,
        data_type: u32,
         data:&[u8],
        data_len: u32,
    ) -> Result<(), String> {
        if let Some(policy_type) = NLPolicyType::from_u32(data_type) {
            log_info!("Handling event for policy type: {}", policy_type);
            if let Some(callback) = self.callbacks.lock().await.get(&policy_type) {
                callback(data, data_len).await
            } else {
                Err(format!(
                    "No callback registered for policy type {:?}",
                    policy_type
                ))
            }
        } else {
            Err(format!("Unknown data type: {}", data_type))
        }
    }
}

async fn handle_echo(data: &[u8], data_len: u32) -> Result<(), String> {
    let data_str = String::from_utf8_lossy(data);
    println!("Handling ECHO data: {}", data_str);
    Ok(())
}

async fn handle_register(data: &[u8], _data_len: u32) -> Result<(), String> {
    println!("Handling REGISTER data: {:?}", data);
    Ok(())
}

async fn handle_add_symbol(data: &[u8], _data_len: u32) -> Result<(), String> {
    println!("Handling ADD_SYMBOL data: {:?}", data);
    Ok(())
}

async fn handle_unregister(data: &[u8], _data_len: u32) -> Result<(), String> {
    println!("Handling UNREGISTER data: {:?}", data);
    Ok(())
}


pub async fn register_default_event_handlers(event_handler: &Arc<Mutex<EventHandler>>) {
    log_info!("Starting to register default event handlers");
    let mut handler = event_handler.lock().await;

    // 注册 ECHO handler
    handler
        .register_event_handler(
            NLPolicyType::NL_POLICY_CMD_ECHO,
            move |data, len| {
                let data = data.to_vec();
                Box::pin(async move { handle_echo(&data, len).await })
            },
        )
        .await;

    // 注册 REGISTER handler
    handler
        .register_event_handler(
            NLPolicyType::NL_POLICY_CMD_REGISTER,
            move |data, len| {
                let data = data.to_vec();
                Box::pin(async move { handle_register(&data, len).await })
            },
        )
        .await;

    // 注册 ADD_SYMBOL handler
    handler
        .register_event_handler(
            NLPolicyType::NL_POLICY_CMD_ADD_SYMBOL,
            move |data, len| {
                let data = data.to_vec();
                Box::pin(async move { handle_add_symbol(&data, len).await })
            },
        )
        .await;

    // 注册 UNREGISTER handler
    handler
        .register_event_handler(
            NLPolicyType::NL_POLICY_CMD_UNREGISTER,
            move |data, len| {
                let data = data.to_vec();
                Box::pin(async move { handle_unregister(&data, len).await })
            },
        )
        .await;
}


pub async fn register_user_event_handlers(
    event_handler: &Arc<Mutex<EventHandler>>,
    file_audit_log_tx: mpsc::Sender<AuditLogInfo>,
    boot_manager: Arc<BootManager>,
) {
    log_info!("Starting to register user event handlers");

    let zcopy_mgr = match ZcopyMgr::new() {
        Ok(mgr) => Arc::new(mgr),
        Err(e) => {
            log_error!("Failed to create ZcopyMgr: {}", e);
            return;
        }
    };

    let file_audit_handler = FileAuditHandler::new(zcopy_mgr.clone(), file_audit_log_tx);
    let process_audit_handler = ProcessAuditHandler::new(zcopy_mgr, boot_manager);
    let net_app_handler = NetAppHandler::new();

    let mut handler = event_handler.lock().await;
    handler
        .register_event_handler(
            NLPolicyType::NL_POLICY_AV_FILE_AUDIT_ZCOPY_NOTIFY,
            move |data, len| {
                let handler = file_audit_handler.clone();
            let data = data.to_vec(); // 拷贝数据
                Box::pin(async move {
                    handler.handle_file_zcopy_oper(&data, len).await
                })
            },
        )
        .await;
    handler
    .register_event_handler(
        NLPolicyType::NL_POLICY_AV_PROCESS_EXEC_ZCOPY_NOTIFY,
        move |data, len| {
            let handler = process_audit_handler.clone();
            let data = data.to_vec(); 
            Box::pin(async move {
                handler.handle_process_zcopy_oper(&data, len).await
            })
        },
    )
    .await;
    handler
    .register_event_handler(
        NLPolicyType::NL_POLICY_SERVER_LISTEN_NOTIFY,
        move |data, len| {
            let handler = net_app_handler.clone();
            let data = data.to_vec(); 
            Box::pin(async move {
                handler.get_net_app_handler(&data, len).await
            })
        },
    )
    .await;

}

pub trait StartKernelHandler {
    fn start_kernel_send_handler(
        &mut self,
        nl_sock: NlSockInfo,
        event_handler: Arc<Mutex<EventHandler>>,
        file_audit_log_tx: mpsc::Sender<AuditLogInfo>,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>;

    fn start_kernel_rcv_handler(
        &mut self,
        nl_sock: NlSockInfo,
        event_handler: Arc<Mutex<EventHandler>>,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>;
}

impl StartKernelHandler for BootManager {
    fn start_kernel_send_handler(
        &mut self,
        nl_sock: NlSockInfo,
        event_handler: Arc<Mutex<EventHandler>>,
        file_audit_log_tx: mpsc::Sender<AuditLogInfo>,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {
            register_default_event_handlers(&event_handler).await;
            let boot_manager_arc = Arc::new(self.clone());
            register_user_event_handlers(&event_handler, file_audit_log_tx, boot_manager_arc).await;
            send_data_to_kernel(&nl_sock).map_err(|e| e.to_string())?;
            Ok("后台任务已启动".to_string())
        })
    }

    fn start_kernel_rcv_handler(
        &mut self,
        nl_sock: NlSockInfo,
        event_handler: Arc<Mutex<EventHandler>>,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                nl_sock.receive_messages_loop(|data| {
                    let payload = &data[16..];
                    match KosecsMsgData::parse(payload) {
                        Some(msg) => {
                            if msg.data_type == 1 {
                                let data_str = String::from_utf8_lossy(msg.payload);
                                log_info!("Handling ECHO data: {}", data_str);
                            } else {
                                log_info!(
                                    "Handling event for policy type: {}, {:?}",
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
            Ok("后台任务已启动".to_string())
        })
    }
}

use std::net::Ipv4Addr;

pub fn send_data_to_kernel(nl_sock: &NlSockInfo) -> Result<String, String> {
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
