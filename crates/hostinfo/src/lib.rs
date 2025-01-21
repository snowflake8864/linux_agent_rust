pub mod ip_mac;
pub mod system_info;
pub mod agent_uid;
use configparser::ini::Ini;
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct HostInfo {
    pub uid: String,  
    pub macid: String,  
    pub ip: String,  
    pub ver: String,  
    //pub _type: u32,  
    pub os: String,  
    pub memsize: String,  
    pub cpu: String,  
    pub hdsize: String,  
    pub auth: String,  
    pub userid: String,  
    pub host_name: String,  
    pub server_ip_port: String,  
    pub server_ip: String,  
}

impl HostInfo {
    /// 生成 `hostinfo.ini` 文件，包含主机信息
    pub fn generate_host_info_file(file_path: &str) {
        // 如果文件已存在，直接退出
       /* if Path::new(file_path).exists() {
            println!("Host info file already exists at {}", file_path);
            return;
        }
        */

        // 获取 IP 和 MAC 地址
        let ip = ip_mac::get_ip().unwrap_or_else(|| "Unknown".to_string());
        let mac = ip_mac::get_mac().unwrap_or_else(|| "Unknown".to_string());

        // 获取系统信息
        let computer_name = system_info::SystemInfo::get_computer_name().unwrap_or_else(|_| "Unknown".to_string());
        let computer_version = system_info::SystemInfo::get_computer_version().unwrap_or_else(|_| "Unknown".to_string());
        // 获取硬件参数（disk、mem、CPU,uid）
        let disk = system_info::SystemInfo::get_disk_size().unwrap_or_else(|_| "Unknown".to_string());
        let mem = system_info::SystemInfo::get_memory_size().unwrap_or_else(|_| "Unknown".to_string());
        let cpu = system_info::SystemInfo::get_cpu_cores().unwrap_or_else(|_| "Unknown".to_string());
        let uid = agent_uid::ensure_and_get_mgs_guid(".vedasystem").unwrap_or_else(|_| "Unknown".to_string());

        // 创建 INI 配置
        let mut ini = Ini::new();
        ini.set("Network", "IP", Some(ip));
        ini.set("Network", "MAC", Some(mac));
        ini.set("System", "host_name", Some(computer_name));
        ini.set("System", "os", Some(computer_version));
        ini.set("System", "hdsize", Some(disk));
        ini.set("System", "memsize", Some(mem));
        ini.set("System", "cpu", Some(cpu));
        ini.set("System", "uid", Some(uid));
        ini.set("System", "userid", Some("1".to_string()));
        ini.set("System", "ver", Some("3.0.1_T2_B2".to_string()));
        ini.set("System", "auth", Some("123123".to_string()));
        ini.set("ServerInfo", "server_ip_port", Some("https://192.168.135.88:443".to_string()));
        ini.set("ServerInfo", "server_ip", Some("192.168.135.88".to_string()));

        // 写入到文件
        match ini.write(file_path) {
            Ok(_) => println!("Host info file generated at {}", file_path),
            Err(e) => eprintln!("Failed to write host info to file: {}", e),
        }
    }
    // 从 ini 文件中读取配置并返回一个 NetInfoConfig 实例
    pub fn from_ini() -> Self {
        let mut config_path = std::env::var("HOST_INFO_PATH").ok();
        if config_path.is_none() {
            config_path = Some("/opt/osec/hostinfo.ini".to_string());
        }
        let mut ini = Ini::new();
        if let Some(path) = config_path {
            ini.load(path.clone()).unwrap_or_else(|_| {
                eprintln!("Failed to load configuration file from '{}'", path);
                std::process::exit(1);
            });
        }

        let mut host_info = HostInfo::default();
        if let Some(uid) = ini.get("system", "uid") {
            host_info.uid = uid; 
        }
        if let Some(ip) = ini.get("network", "ip") {
            host_info.ip = ip; 
        }

        if let Some(mac) = ini.get("network", "mac") {
            host_info.macid = mac; 
        }
        if let Some(ver) = ini.get("system", "ver") {
            host_info.ver = ver; 
        }
        if let Some(os) = ini.get("system", "os") {
            host_info.os = os; 
        }
        if let Some(memsize) = ini.get("system", "memsize") {
            host_info.memsize = memsize; 
        }
        if let Some(cpu) = ini.get("system", "cpu") {
            host_info.cpu = cpu; 
        }
        if let Some(hdsize) = ini.get("system", "hdsize") {
            host_info.hdsize = hdsize; 
        }
        if let Some(userid) = ini.get("system", "userid") {
            host_info.userid = userid; 
        }
        if let Some(host_name) = ini.get("system", "host_name") {
            host_info.host_name = host_name; 
        }
        if let Some(auth) = ini.get("system", "auth") {
            host_info.auth = auth; 
        }
        if let Some(server_ip_port) = ini.get("ServerInfo", "server_ip_port") {
            host_info.server_ip_port = server_ip_port; 
        }
        if let Some(server_ip) = ini.get("ServerInfo", "server_ip") {
            host_info.server_ip = server_ip; 
        }
        host_info
    }
}

