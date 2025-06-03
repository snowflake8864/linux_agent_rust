//crates/kernel_event/src/event_handler/mod.rs
#![allow(dead_code)]
use std::io::{self, Write};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::fmt;
use crate::msg_handler::KosecsMsgData;
use logging::{log_info,log_error};
use netlink::netlink::NlSockInfo; // 引入 NLPolicyType
//use std::time::Duration;
use common::
    manager::boot::BootManager;
use std::pin::Pin;
use std::future::Future;
//use tokio::sync::mpsc;


// nl_policy.rs
pub struct KernelEventConnect {
   pub nl_sock: NlSockInfo,
   pub event_handler: EventHandler,

}
impl KernelEventConnect {
     pub fn new() -> io::Result<Self> {
        let nl_sock = NlSockInfo::create_socket()?;
        let event_handler = EventHandler::new();
        Ok(KernelEventConnect { nl_sock, event_handler, })
    }
}
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
    // 从 u32 转换为 NLPolicyType
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(NLPolicyType::NL_POLICY_CMD_ECHO),
            2 => Some(NLPolicyType::NL_POLICY_CMD_REGISTER),
            3 => Some(NLPolicyType::NL_POLICY_CMD_ADD_SYMBOL),
            0x100 => Some(NLPolicyType::NL_POLICY_DEFENSE_UNSPEC),
            0x700 => Some(NLPolicyType::NL_POLICY_NETWORK_UNSPEC),
            0x503 => Some(NLPolicyType::NL_POLICY_CMD_NOTIFY),
            _ => None, // 如果没有匹配项，返回 None
        }
    }

    // 你也可以通过其他方式扩展此方法来支持更多的转换逻辑
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

type CallbackFn = Box<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync>;

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
    pub fn register_event_handler(&mut self, policy_type: NLPolicyType, callback: CallbackFn) {
        self.callbacks.lock().unwrap().insert(policy_type, callback);
    }

    // 处理事件
    pub fn handle_event(&self, data_type: u32, data: &[u8]) -> Result<(), String> {
        if let Some(policy_type) = NLPolicyType::from_u32(data_type) {
            if let Some(callback) = self.callbacks.lock().unwrap().get(&policy_type) {
                callback(data)
            } else {
                Err(format!("No callback registered for policy type {:?}", policy_type))
            }
        } else {
            Err(format!("Unknown data type: {}", data_type))
        }
    }
}


// 定义 ECHO 命令的处理函数
fn handle_echo(data: &[u8]) -> Result<(), String> {
    let data_str = String::from_utf8_lossy(data); // 将字节数据转换为字符串
    println!("Handling ECHO data: {}", data_str);  // 打印字符串
    // 处理复杂逻辑
    Ok(())
}

// 定义 REGISTER 命令的处理函数
fn handle_register(data: &[u8]) -> Result<(), String> {
    println!("Handling REGISTER data: {:?}", data);
    Ok(())
}

// 定义 ADD_SYMBOL 命令的处理函数
fn handle_add_symbol(data: &[u8]) -> Result<(), String> {
    println!("Handling ADD_SYMBOL data: {:?}", data);
    Ok(())
}

// 定义 UNREGISTER 命令的处理函数
fn handle_unregister(data: &[u8]) -> Result<(), String> {
    println!("Handling UNREGISTER data: {:?}", data);
    Ok(())
}



// 默认事件回调函数注册
pub fn register_default_event_handlers(event_handler: &mut EventHandler) {
    // 注册 ECHO 命令的回调
    /*
    event_handler.register_event_handler(NLPolicyType::NL_POLICY_CMD_ECHO, Box::new(|data| {
        println!("Handling ECHO data: {:?}", data);
        Ok(())
    }));
    */
    println!("=============================111111111111111111111");
    event_handler.register_event_handler(NLPolicyType::NL_POLICY_CMD_ECHO, Box::new(handle_echo));


    // 注册 REGISTER 命令的回调
    event_handler.register_event_handler(NLPolicyType::NL_POLICY_CMD_REGISTER, Box::new(|data| {
        println!("Handling REGISTER data: {:?}", data);
        Ok(())
    }));

    // 注册其他命令的回调（可以根据需要添加）
    event_handler.register_event_handler(NLPolicyType::NL_POLICY_CMD_ADD_SYMBOL, Box::new(|data| {
        println!("Handling ADD_SYMBOL data: {:?}", data);
        Ok(())
    }));

    event_handler.register_event_handler(NLPolicyType::NL_POLICY_CMD_UNREGISTER, Box::new(|data| {
        println!("Handling UNREGISTER data: {:?}", data);
        Ok(())
    }));
}


pub trait StartKernelHandler {
    fn start_kernel_handler(&mut self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send  + '_>>; 
}


impl StartKernelHandler for BootManager {
    fn start_kernel_handler(&mut self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send  + '_>> {
        Box::pin(async move {
            //let kernel_event_connect = KernelEventConnect::new();
            //let nl_sock = NlSockInfo::create_socket();
            let nl_sock = match NlSockInfo::create_socket() {
                Ok(sock) => sock,
                Err(e) => return Err(format!("Failed to create socket: {}", e)),
            };

            let mut event_handler = EventHandler::new();
            register_default_event_handlers(&mut event_handler);
            //send_data_to_kernel(&nl_sock)?;
            send_data_to_kernel(&nl_sock).map_err(|e| e.to_string())?;
            // 循环阻塞接收内核消息
            /*
            if let Err(e) = nl_sock.receive_messages_loop() {
                println!("Error during message receive loop: {}", e);
                return Err(format!("Receive loop failed: {}", e));
            }
            */
            nl_sock.receive_messages_loop(|data| {

                let payload = &data[16..]; // 跳过 netlink header
                match KosecsMsgData::parse(&payload) {
                    Some(msg) => {
                        log_info!(
                            "收到事件 type: {:#x}, 长度: {}, 数据: {:x?}",
                            msg.data_type, msg.data_len, msg.payload
                        );
                        if msg.data_type == 1 {
                            //let data = msg.payload;
                            let data = msg.payload;
                            let data_str = String::from_utf8_lossy(data);
                            log_info!("Handling ECHO data: {}", data_str);
                        } else {
                            println!("Unknown data type: {}", msg.data_type);
                        }
                    }
                    None => {
                        eprintln!("无法解析内核消息，格式错误或长度不足: {:x?}", data);
                    }
                }                }).map_err(|e| e.to_string())?;            
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

    // 示例：发送 IP 地址数据
    let ip = Ipv4Addr::new(192, 168, 0, 1);
    let ip_bytes = ip.octets();
    if let Err(e) = nl_sock.send_message(1, &ip_bytes) {
        return Err(format!("Failed to send IP address: {}", e));
    }

    // 示例：发送自定义数据
    let data: Vec<u8> = vec![1, 2, 3, 4, 5];
    if let Err(e) = nl_sock.send_message(1, &data) {
        return Err(format!("Failed to send custom data: {}", e));
    }

    Ok("Data sent successfully".to_string())
}


