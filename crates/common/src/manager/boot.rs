//crates/common/src/manager/boot.rs
use std::sync::{Arc, Mutex};
use arc_swap::ArcSwap;
use configparser::ini::Ini;
use crate::{Core, Inner};
use crate::NetClient;  // Import NetClient from the common module
use pattern::pattern_rules_mgr;
use tokio::sync;
use config::net_info::NETINFO_CONFIG;
//use tokio::sync::mpsc;

#[derive(Clone)]
pub struct BootManager {
    pub inner: Arc<Inner>,
    token: Arc<sync::Mutex<Option<String>>>,
}

const HELP: &str = concat!(
    "Stalwart Mail Server v",
    env!("CARGO_PKG_VERSION"),
    r#"

Usage: stalwart-mail [OPTIONS]

Options:
  -c, --config <PATH>              Start server with the specified configuration file
  -I, --init <PATH>                Initialize a new server at a specific path
  -h, --help                       Print help
  -V, --version                    Print version
"#
);

impl BootManager {
    pub async fn init() -> Self {
        let mut config_path = std::env::var("CONFIG_PATH").ok();

        if config_path.is_none() {
            let mut args = std::env::args().skip(1);

            while let Some(arg) = args.next().and_then(|arg| {
                arg.strip_prefix("--")
                    .or_else(|| arg.strip_prefix('-'))
                    .map(|arg| arg.to_string())
            }) {
                let (key, value) = if let Some((key, value)) = arg.split_once('=') {
                    (key.to_string(), Some(value.trim().to_string()))
                } else {
                    (arg, args.next())
                };

                match (key.as_str(), value) {
                    ("help" | "h", _) => {
                        eprintln!("{HELP}");
                        std::process::exit(0);
                    }
                    ("version" | "V", _) => {
                        println!("{}", env!("CARGO_PKG_VERSION"));
                        std::process::exit(0);
                    }
                    ("config" | "c", Some(value)) => {
                        config_path = Some(value);
                    }
                    (_, None) => {
                        eprintln!("Unrecognized command '{key}', try '--help'.");
                        std::process::exit(1);
                    }
                    (_, Some(_)) => {
                        eprintln!("Missing value for argument '{key}', try '--help'.");
                        std::process::exit(1);
                    }
                }
            }

            if config_path.is_none() {
                config_path = Some("/opt/osec/".to_string());
                eprintln!("Missing '--config' argument. Using default config path: {}", config_path.as_ref().unwrap());
            }
        }

        let config_path_clone = config_path.clone();
        // Load the INI file using the configparser crate
        let mut ini = Ini::new();

        if let Some(path) = config_path {
            let config_file = format!("{}/net_info.ini", path);
            ini.load(config_file).unwrap_or_else(|_| {
                eprintln!("Failed to load configuration file from '{}/net_info.ini'", path);
                std::process::exit(1);
            });
        }


        // Retrieve the configuration values from the INI file and parse into NetInfoConfig
        let mut netinfocfg = NETINFO_CONFIG.lock().unwrap(); // 这里使用 from_ini 解析配置
        netinfocfg.app_path = config_path_clone.unwrap_or_else(|| "/opt/osec/".to_string());
        let _ =  netinfocfg.acquire_host_info();

        //println!("1===={:?}", netinfocfg);
 // Initialize the NetClient with token and base_url from environment variables or config
        let netclient = NetClient {
            token: std::env::var("NETCLIENT_TOKEN").ok(),
            //base_url: std::env::var("NETCLIENT_BASE_URL").unwrap_or_else(|_| "http://default.url".to_string()), // Default URL if not provided
            base_url: netinfocfg.server_ip_port.clone(), 
        };
        println!("=={:?}", netclient);
        let core = Core {
            netclient,
            is_online:false,
            pattern_mgr: Arc::new(Mutex::new(pattern_rules_mgr::PatternRulesMgr::new())),
        };

        let inner = Arc::new(Inner {
            shared_core: ArcSwap::from_pointee(core),
        });

        BootManager {
        inner,
        token: Arc::new(sync::Mutex::new(None)),
        }
    }

    pub fn get_base_url(&self) -> String {
        let netinfocfg = NETINFO_CONFIG.lock().unwrap(); // 这里使用 from_ini 解析配置
        netinfocfg.server_ip_port.clone() // 返回克隆的值
    }


    pub fn get_crontime(&self) -> u32 {
        let netinfocfg = NETINFO_CONFIG.lock().unwrap(); 
        netinfocfg.cron_time
    }
    pub fn get_baseline_info(&self) -> (bool,u32) {
        let netinfocfg = NETINFO_CONFIG.lock().unwrap(); 
        (netinfocfg.baseline_switch, netinfocfg.baseline_time)
    }

    pub fn get_hardware_info(&self) -> (bool,u32) {
        let netinfocfg = NETINFO_CONFIG.lock().unwrap(); 
        (netinfocfg.hardware_switch, netinfocfg.hardware_time)
    }

    pub fn get_outreach_info(&self) -> (bool,u32) {
        let netinfocfg = NETINFO_CONFIG.lock().unwrap(); 
        (netinfocfg.outreach_switch, netinfocfg.outreach_time)
        //(netinfocfg.outreach_switch, 60)
    }

    pub fn get_ssh_login_info(&self) -> bool {
        let netinfocfg = NETINFO_CONFIG.lock().unwrap();
        netinfocfg.syslog_login_switch
    }

    pub fn host_is_online(&self) -> bool {
        let core = self.inner.shared_core.load();
        core.is_online == true // 返回克隆的值
    }

    pub async fn set_token(&mut self, token: String) {
        let mut guard = self.token.lock().await;
        *guard = Some(token);
    }

    pub async fn get_token(&self) -> Option<String> {
        let guard = self.token.lock().await;
        guard.clone()
    }
    pub fn pattern_mgr(&self) -> Arc<Mutex<pattern_rules_mgr::PatternRulesMgr>> {
        Arc::clone(&self.inner.shared_core.load().pattern_mgr)
    }

    pub fn with_pattern_mgr<F>(&self, f: F)
    where
        F: FnOnce(&mut pattern_rules_mgr::PatternRulesMgr),
        {
            let pattern_mgr = self.inner.shared_core.load().pattern_mgr.clone();
            let mut guard = pattern_mgr.lock().unwrap();
            f(&mut guard);
        }
}

