//crates/host_info/src/net_app/models.rs
use serde::{Serialize, ser};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;

use std::sync::Mutex;
use once_cell::sync::Lazy;

// Assuming logging crate is defined elsewhere
use logging::log_info;

static LAST_PORTS: Lazy<Mutex<Vec<u16>>> = Lazy::new(|| Mutex::new(Vec::new()));
#[derive(Debug, Clone, Serialize)]
pub struct PortBusinessInfo {
    pub time: i64,
    pub protocol: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: String,
    pub status: String,
    pub pid: i32,
    pub process_path: String,
}

impl fmt::Display for PortBusinessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PortBusinessInfo {{ local_port: {}, protocol: {}, local_ip: {}, remote_ip: {}, status: {}, pid: {}, process_path: {} }}", 
               self.local_port, self.protocol, self.local_ip, self.remote_ip, self.status, self.pid, self.process_path)
    }
}

#[derive(Default, Debug)]
pub struct NetAppState {
    pub port_map: HashMap<u16, PortBusinessInfo>,
    pub port_str_map: HashMap<String, PortBusinessInfo>,
}

#[derive(Serialize)]
struct ServiceJson {
    service: Vec<PortBusinessInfoJson>,
}

#[derive(Serialize)]
struct PortBusinessInfoJson {
    #[serde(rename = "type")]
    protocol: String,
    ip: String,
    port: String,
    process: String,
}

impl NetAppState {
    // Print the contents of NetAppState
    pub fn print_contents(&self) {
        log_info!("=== NetAppState Contents ===");
        for (port, info) in &self.port_map {
            log_info!("  {}: {}", port, info);
        }
        
        for (key, info) in &self.port_str_map {
            log_info!("  {}: {}", key, info);
        }
    }
    
    // Get string representation of contents
    pub fn get_contents_string(&self) -> String {
        let mut result = String::new();
        result.push_str(&format!("=== NetAppState Contents ===\n"));
        result.push_str(&format!("port_map ({} entries):\n", self.port_map.len()));
        for (port, info) in &self.port_map {
            result.push_str(&format!("  {}: {}\n", port, info));
        }
        
        result.push_str(&format!("port_str_map ({} entries):\n", self.port_str_map.len()));
        for (key, info) in &self.port_str_map {
            result.push_str(&format!("  {}: {}\n", key, info));
        }
        result.push_str(&format!("==========================\n"));
        result
    }
    
    // Get port info by port number
    pub fn get_port_info(&self, port: u16) -> Option<&PortBusinessInfo> {
        self.port_map.get(&port)
    }
    
    // Get all port info
    pub fn get_all_port_info(&self) -> Vec<&PortBusinessInfo> {
        self.port_map.values().collect()
    }
    
    // Add port info to both maps
    pub fn add_port_info(&mut self, port: u16, info: PortBusinessInfo) {
        self.port_map.insert(port, info.clone());
        self.port_str_map.insert(format!("{}:{}", info.local_ip, port), info);
    }
    
    // Clear all data
    pub fn clear(&mut self) {
        self.port_map.clear();
        self.port_str_map.clear();
    }
    
    // Convert port_str_map to JSON
     pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let service_data: Vec<PortBusinessInfoJson> = self.port_str_map.values().map(|info| {
            log_info!("port[{}], prot[{}], process[{}]", info.local_port, info.protocol, info.process_path);
            PortBusinessInfoJson {
                protocol: info.protocol.clone(),
                ip: info.local_ip.clone(),
                port: info.local_port.to_string(),
                process: info.process_path.clone(),
            }
        }).collect();

        if service_data.is_empty() {
            log_info!("No valid port entries to add to JSON.");
            return Err(serde_json::Error::from(ser::Error::custom("No valid port entries")));
        }

        // Serialize the service_data array to a JSON string
        let service_array_str = serde_json::to_string(&service_data)?;

        // Create a new JSON object with the service array as a string
        let service_json = serde_json::json!({
            "service": service_array_str
        });

        serde_json::to_string(&service_json)
    }

}

pub type SharedState = Arc<RwLock<NetAppState>>;

lazy_static::lazy_static! {
    pub static ref NETAPP_STATE: SharedState = Arc::new(RwLock::new(NetAppState::default()));
}

pub trait NetAppStateExt {
    fn print_state(&self);
    fn get_state_string(&self) -> String;
    fn add_port_info_to_state(&self, port: u16, info: PortBusinessInfo);
    fn get_port_info_from_state(&self, port: u16) -> Option<PortBusinessInfo>;
    fn clear_state(&self);
    fn to_json_from_state(&self) -> Result<String, serde_json::Error>;
}

impl NetAppStateExt for SharedState {
    fn print_state(&self) {
        if let Ok(state) = self.read() {
            state.print_contents();
        } else {
            log_info!("Failed to read NETAPP_STATE");
        }
    }
    
    fn get_state_string(&self) -> String {
        match self.read() {
            Ok(state) => state.get_contents_string(),
            Err(_) => "Failed to read NETAPP_STATE".to_string(),
        }
    }
    
    fn add_port_info_to_state(&self, port: u16, info: PortBusinessInfo) {
        if let Ok(mut state) = self.write() {
            state.add_port_info(port, info);
        }
    }
    
    fn get_port_info_from_state(&self, port: u16) -> Option<PortBusinessInfo> {
        match self.read() {
            Ok(state) => state.get_port_info(port).cloned(),
            Err(_) => None,
        }
    }
    
    fn clear_state(&self) {
        if let Ok(mut state) = self.write() {
            state.clear();
        }
    }
    
    fn to_json_from_state(&self) -> Result<String, serde_json::Error> {
        match self.read() {
            Ok(state) => state.to_json(),
            Err(_) => Err(serde_json::Error::from(ser::Error::custom("Failed to read NETAPP_STATE"))),
        }
    }

}

pub fn write_business_ports_to_proc() {
    let state_guard = NETAPP_STATE.read();
    let state = match state_guard {
        Ok(s) => s,
        Err(_) => {
            log_info!("Failed to read NETAPP_STATE in write_business_ports_to_proc");
            return;
        }
    };

    // 当前端口集合（按升序去重）
    let mut ports: Vec<u16> = state.port_map.keys().cloned().collect();
    ports.sort_unstable();
    ports.dedup();

    // 比较与上次是否一样
    let mut last_ports = LAST_PORTS.lock().unwrap();
    if *last_ports == ports {
       // log_info!("Ports unchanged, skip writing to /proc/osec/business_ports");
        return;
    }

    let port_string = ports.iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let file_path = "/proc/osec/business_ports";
    match OpenOptions::new().write(true).truncate(true).open(file_path) {
        Ok(mut file) => {
            if let Err(e) = write!(file, "{}", port_string) {
                log_info!("Failed to write to {}: {}", file_path, e);
            } else {
                log_info!("Updated business ports to {}: [{}]", file_path, port_string);
                *last_ports = ports;
            }
        }
        Err(e) => {
            //log_info!("Failed to open {}: {}", file_path, e);
        }
    }
}
pub fn print_netapp_state() {
    NETAPP_STATE.print_state();
}

pub fn add_port_to_state(port: u16, info: PortBusinessInfo) {
    NETAPP_STATE.add_port_info_to_state(port, info);
}

pub fn get_port_from_state(port: u16) -> Option<PortBusinessInfo> {
    NETAPP_STATE.get_port_info_from_state(port)
}

pub fn get_netapp_json() -> Result<String, serde_json::Error> {
    NETAPP_STATE.to_json_from_state()
}
