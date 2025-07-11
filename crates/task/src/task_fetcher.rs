// task_fetcher.rs
use std::fs;
use config::net_info::NETINFO_CONFIG;
use std::pin::Pin;
use std::future::Future;
use serde_json::Value;
use net_client::core::NetClient;
use std::time::Duration;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use tokio::io::AsyncWriteExt; // 
use std::sync::{Arc, Mutex};
use tokio::fs::OpenOptions;
use logging::{log_info,log_error};
use common::manager::boot::BootManager;
use crate::virtual_port_rule::VirtualPortRule;
use crate::get_process_task::process_all_dirs;
use pattern::pattern_rules_mgr;
use tokio::sync::mpsc;
use process_mgr::POLICY_MANAGER;
use netlink::netlink::NlSockInfo; // 引入 NLPolicyType
                                  //
fn get_u32(map: &serde_json::Map<String, Value>, key: &str) -> Result<u32, String> {
    map.get(key)
        .and_then(|v| v.as_number().and_then(|n| n.as_u64()))
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| format!("Missing or invalid field: {}", key))
}

fn get_bool(map: &serde_json::Map<String, Value>, key: &str) -> Result<bool, String> {
    map.get(key)
        .and_then(|v| v.as_number().and_then(|n| n.as_u64()))
        .map(|n| n != 0)         
        .ok_or_else(|| format!("Missing or invalid field: {}", key))
}
pub struct TaskFetcher {
    base_url: String,
    token: Option<String>,  // 'a 表示 token 的生命周期与 TaskFetcher 的生命周期相同
    api_interface: HashMap<String, String>,
    pattern_mgr: Arc<Mutex<pattern_rules_mgr::PatternRulesMgr>>,
    prev_defense_switch: Option<u32>,
    prev_open_port_switch: bool,
    prev_file_switch: bool,
    prev_extortion_switch:bool,
    prev_proc_switch:bool,
    prev_syslog_process_switch:bool,
    nl_sock: Option<NlSockInfo>,
}
use num_derive::FromPrimitive; // 支持从整数到枚举的转换
use num_traits::FromPrimitive;
#[derive(Debug, FromPrimitive)]
enum TaskTypeEnum {
    TaskUploadProcess = 0,
    TaskUpdate = 1,
    TaskUploadDir = 2,
    TaskDownWhite = 3,
    TaskDownDirPolicy = 4,
    TaskUploadConf = 5, // no use
    TaskDownConf = 6,
    TaskDownBlack = 7,
    TaskDownFileTtap = 8,
    TaskUploadPort = 9,
    TaskDownVirtualPort = 10,
    TaskAutoDownNetBlockPolicy = 11, // no use
    TaskAutoUploadNetBlockPolicyy = 12, // no use
    TaskDownNetBlockPolicy = 13,
    TaskDownWhiteIpPolicy = 14, // no use
    TaskDownBlackIpPolicy = 15,
    TaskDownUsbUpload = 16,
    TaskDownUsbDown = 17, // no use
    TaskDownExtort = 19,
    TaskUploadProcessModule = 21,
    TaskUploadAllProcessModule = 22,
    TaskUploadProcessWhiteModule = 23,
    TaskUploadProcessBlackModule = 24,
    TaskUninstall = 25,
    TaskGetWhitePeripherals = 26,
    TaskGetBlackPeripherals = 27,
    TaskUploadSample = 28,
    TaskSyslogEnable = 29, // no use
    TaskSyslogDisable = 30, // no use
    TaskGlobalProc = 31,
    TaskGlobalDir = 33,
    TaskUpdateUUI = 34,
    TaskOutReachDetect = 35,
}
#[allow(dead_code)]
enum NetRule<'a> {
    ServerIpV4(&'a str),
    ServerPort(u32),
    LogIpPort(&'a str),
    VirtualOpenPort(bool),
    DefenseSwitch(u32),
    SelfProtect(u32),
    NetLogPolicy((bool, bool)),
}
fn ip_str_to_u32(ip: &str) -> Result<u32, String> {
    let parsed = ip.parse::<Ipv4Addr>().map_err(|e| e.to_string())?;
    Ok(u32::from_be_bytes(parsed.octets()))
}
impl TaskFetcher {
    pub fn new(base_url: &str, token: Option<String>, pattern_mgr: Arc<Mutex<pattern_rules_mgr::PatternRulesMgr>>, nl_sock: Option<NlSockInfo>) -> Self 
    {
        let mut api_interface = HashMap::new();
        api_interface.insert("download_white".to_string(), "v1/getprocwl".to_string());
        api_interface.insert("download_black".to_string(), "v1/getprocbl".to_string());
        api_interface.insert("getconf".to_string(), "v1/getconf".to_string());
        api_interface.insert("getprotect".to_string(), "v1/getprotect".to_string());
        api_interface.insert("getdirpolicy".to_string(), "v1/getdirpolicy".to_string());
        api_interface.insert("upload_process".to_string(), "v1/uploadproc".to_string());
        api_interface.insert("gettrustdir".to_string(), "v1/gettrustdir".to_string());
        api_interface.insert("getvirtualport".to_string(), "v1/getvirtualport".to_string());
        api_interface.insert("upload_gloabal_process".to_string(), "v1/upload/suffix/exe".to_string());

        TaskFetcher {
              base_url: base_url.to_string(),
              token,
              api_interface,
              pattern_mgr,
              prev_defense_switch: None,
              prev_open_port_switch: false,
              prev_file_switch:false,
              prev_extortion_switch:false,
              prev_proc_switch:false,
              prev_syslog_process_switch:false,
              nl_sock,
        }
    }
    pub fn get_token(&self) -> Option<String> {
        self.token.clone()
    }
    fn write_net_rule(&self, rule: NetRule) -> Result<(), String> {
        match rule {
            NetRule::ServerIpV4(ip) => {
                let ip_u32 = ip_str_to_u32(ip)?;
                self.write_raw("server_ipv4 ", &ip_u32.to_string())
            }
            NetRule::ServerPort(port) => {
                self.write_raw("server_port ", &port.to_string())
            }
            NetRule::LogIpPort(log_ip_port) => {
                self.write_raw("log_ip_port ", log_ip_port)
            }
            NetRule::VirtualOpenPort(open_port_state) => {
               self.write_raw("vir_open_port_switch ", if open_port_state { "1" } else { "0" })
            }
            NetRule::DefenseSwitch(defense_state) => {
                self.write_defense_switch("defense_switch ", &defense_state.to_string())
            }
            NetRule::SelfProtect(self_protect_state) => {
                log::info!("=======================self_protect_state: {}", self_protect_state);
                self.nl_sock
                    .as_ref()
                    .ok_or("Netlink socket not initialized".to_string())?
                    .send_uint32(0x103, self_protect_state)
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            NetRule::NetLogPolicy((syslog_process_switch,proc_switch)) => {
                let buf = [
                    syslog_process_switch as u8,
                    proc_switch as u8,
                    0,
                    0,
                ];
                self.nl_sock
                    .as_ref()
                    .ok_or("Netlink socket not initialized".to_string())?
                    .send_message(0x702, &buf)
                    .map_err(|e| e.to_string())?;
                Ok(())
            } 
        }
    }
    fn write_raw(&self, rule_type: &str, value: &str) -> Result<(), String> {
        let content = format!("{} {}\n", rule_type, value);
        fs::write("/proc/osec/net_rules", content)
            .map_err(|e| format!("Failed to write to /proc/osec/net_rules: {}", e))
    }
     fn write_defense_switch(&self, rule_type: &str, value: &str) -> Result<(), String> {
        let content = format!("{} {}\n", rule_type, value);
        fs::write("/proc/osec/defense_switch", content)
            .map_err(|e| format!("Failed to write to /proc/osec/defense_switch: {}", e))
    }
     fn update_config_from_json(&mut self, conf: &serde_json::Map<String, Value>) -> Result<(), String> {

        let mut cfg = NETINFO_CONFIG.lock().unwrap(); // 这里使用 from_ini 解析配置
         // 提取 serveripport 字段，并尝试拆分为 ip 和 port
         if let Some(url) = conf.get("serveripport")
             .and_then(|v| v.as_str())
                 .map(|s| s.to_string()) 
         {

             // 分割协议和主体部分
             let (protocol, mut rest) = url.split_once("://")
                 .expect("Invalid URL format");

             // 移除路径部分（如果有）
             if let Some(path_idx) = rest.find('/') {
                 rest = &rest[..path_idx];
             }

             // 分割IP和端口
             let (ip_str, port_str) = rest.split_once(':')
                 .unwrap_or_else(|| (rest, ""));

             if cfg.server_ip != ip_str {
                 cfg.server_ip = ip_str.to_string();
                 self.write_net_rule(NetRule::ServerIpV4(ip_str))?;
             }
             // 转换端口
             cfg.server_port = if !port_str.is_empty() {
                 port_str.parse().expect("Invalid port number")
             } else {
                 match protocol.to_lowercase().as_str() {
                     "https" => 443,
                     "http" => 80,
                     _ => panic!("Unsupported protocol"),
                 }
             };

         }
         cfg.cron_time = get_u32(conf, "crontime")?;
         cfg.extortion_protect = get_bool(conf, "extortion_protect")?;
         cfg.extortion_switch = get_bool(conf, "extortion_switch")?;
         cfg.file_protect = get_bool(conf, "file_protect")?;
         cfg.file_switch = get_bool(conf, "file_switch")?;
         cfg.log_proto = get_u32(conf, "logproto")?;
         cfg.log_sent = get_u32(conf, "logsent")?;

         // logipport 可能是空字符串，转成 Option<String>
         cfg.log_ip_port = conf.get("logipport")
             .and_then(|v| v.as_str())
             .filter(|s| !s.is_empty())
             .map(|s| s.to_string());

         cfg.cli_port = get_u32(conf, "debug_switch")?;
         cfg.module_switch = get_u32(conf, "module_switch")?;
         let self_protect_switch = get_u32(conf, "self_protect_switch")?;
         if cfg.self_protect_switch != self_protect_switch {
             cfg.self_protect_switch = self_protect_switch;
            
             if !cfg.mod_ver.is_empty() {
                 let mut pattern_mgr = self.pattern_mgr.lock().map_err(|e| e.to_string())?;
                 pattern_mgr.add_file_pattern(cfg.self_protect_switch == 1);
                 self.write_net_rule(NetRule::SelfProtect(cfg.self_protect_switch))?;
             }
         }
         cfg.open_port_switch = get_bool(conf, "open_port_switch")?;
         if cfg.open_port_switch != self.prev_open_port_switch {
             self.prev_open_port_switch = cfg.open_port_switch;
             if !cfg.mod_ver.is_empty() {
                 self.write_net_rule(NetRule::VirtualOpenPort(cfg.open_port_switch))?;
             }
         }
         cfg.proc_protect = get_bool(conf, "proc_protect")?;
         cfg.proc_switch = get_bool(conf, "proc_switch")?;
         cfg.usb_protect = get_bool(conf, "usb_protect")?;
         cfg.usb_switch = get_bool(conf, "usb_switch")?;
         cfg.syslog_inner_switch = get_bool(conf, "syslog_inner_switch")?;
         cfg.syslog_outer_switch = get_bool(conf, "syslog_outer_switch")?;
         cfg.syslog_dns_switch = get_bool(conf, "syslog_dns_switch")?;
         cfg.internet_switch = get_bool(conf, "internet_switch")?;
         cfg.syslog_process_switch = get_bool(conf, "syslog_process_switch")?;

         let _ = cfg.to_ini("/opt/osec/net_info.ini");
         let file_flag_temp  = cfg.file_switch|cfg.extortion_switch;
         /*

         let mut enable_flag :u32 = 0;
            if ( file_flag_temp && self.cfg.proc_switch ) {
            enable_flag = 3; 
            }    
            if ( file_flag_temp  && !self.cfg.proc_switch ) {
            enable_flag = 2; 
            }    
            if ( !file_flag_temp  && self.cfg.proc_switch ) {
            enable_flag = 1; 
            }    
            if ( !file_flag_temp  && !self.cfg.proc_switch ) {
            enable_flag = 0; 
            } 
            */
         let enable_flag = (file_flag_temp as u32) * 2 + (cfg.proc_switch as u32);
         let mut defense_switch = [
             (cfg.open_port_switch, 14),
             (cfg.internet_switch, 13),
             (cfg.syslog_dns_switch, 12),
             (cfg.syslog_outer_switch, 11),
             (cfg.syslog_inner_switch, 10),
             (cfg.proc_switch, 9),
             (cfg.file_switch, 8),
             (cfg.extortion_switch, 7),
             (cfg.proc_protect, 6),
             (cfg.file_protect, 5),
             (cfg.extortion_protect, 4),
         ]
             .iter()
             .fold(0, |acc, &(flag, shift)| acc | ((flag as u32) << shift));
         defense_switch |= enable_flag;
         if self.prev_defense_switch != Some(defense_switch) {
             self.prev_defense_switch = Some(defense_switch);
             if !cfg.mod_ver.is_empty() {
                 self.write_net_rule(NetRule::DefenseSwitch(defense_switch))?;
             }
         }
         if self.prev_file_switch != cfg.file_switch {
             if !cfg.mod_ver.is_empty() {
                 if !cfg.file_switch {
                     let mut pattern_mgr = self.pattern_mgr.lock().map_err(|e| e.to_string())?;
                     pattern_mgr.clear_protect_dir();
                 }

             }
             self.prev_file_switch = cfg.file_switch;
         }
         if self.prev_extortion_switch !=cfg.extortion_protect {
             if !cfg.mod_ver.is_empty() {
                 if !cfg.extortion_protect {
                     let mut pattern_mgr = self.pattern_mgr.lock().map_err(|e| e.to_string())?;
                     pattern_mgr.clear_exiport_dir();
                 }
             }
         }
         if self.prev_proc_switch != cfg.proc_switch || self.prev_syslog_process_switch != cfg.syslog_process_switch {
             log_info!("===============================proc_switch:{},syslog_process_switch:{}",cfg.proc_switch,cfg.syslog_process_switch);
             self.write_net_rule(NetRule::NetLogPolicy((cfg.syslog_process_switch, cfg.proc_switch)))?;
             self.prev_syslog_process_switch = cfg.syslog_process_switch;
             self.prev_proc_switch = cfg.proc_switch;
         }         

         Ok(())
     }

    pub async fn run(net_client: &mut NetClient, token: Option<String>,pattern_mgr: Arc<Mutex<pattern_rules_mgr::PatternRulesMgr>>,nl_sock: Option<NlSockInfo>) -> Result<(), String> {
        let token_str = token.as_ref().map(|s| s.as_str());
        let mut task_fetcher = TaskFetcher::new(&net_client.base_url, token.clone(), pattern_mgr, nl_sock);

        loop {
            let url = format!("{}/v1/gettask", task_fetcher.base_url);
            match net_client.post_data_async(&url, "", Duration::from_secs(10), token_str).await {
                Ok(response) => {
                    let parsed: Value = match serde_json::from_str(&response) {
                        Ok(parsed) => parsed,
                            Err(e) => {
                                eprintln!("Failed to parse response: {}", e);
                                continue; // 解析失败后继续下一轮请求
                            }
                    };

                    if parsed["code"] == "000000" {
                        let task_list = parsed["data"]["tasklist"]
                            .as_array()
                            .unwrap_or(&vec![])
                            .iter()
                            .filter_map(|v| v.as_u64().map(|n| n as u32))
                            .collect::<Vec<u32>>();
                        
                        //println!("task list:{:?}", task_list);
                        for task_id in task_list {
                            if let Some(task_type) = TaskTypeEnum::from_u32(task_id) {
                                //println!("task ID: {}", task_id);
                                if let Err(e) = task_fetcher.handle_task(task_type).await {
                                    eprintln!("Failed to handle task {}: {}", task_id, e);
                                }
                            } else {
                                eprintln!("Unknown task ID: {}", task_id);
                            }
                        }
                    } else {
                        eprintln!("Invalid response code: {}", parsed["code"]);
                         return Err("无效响应码".to_string()); // 返回错误，通知主流程
                    }
                }
                Err(err) => {
                    eprintln!("Error fetching task: {}", err);
                    return Err("服务器离线或网络错误".to_string()); // 返回错误，通知主流程
                }
            }

            // 添加短暂休眠，避免频繁轮询
            tokio::time::sleep(Duration::from_secs(20)).await;
        }
    }


   /// 根据任务类型处理任务
    async fn handle_task(&mut self, task_type: TaskTypeEnum) -> Result<(), String> {
        match task_type {
            TaskTypeEnum::TaskUploadProcess => self.task_upload_process().await,
            TaskTypeEnum::TaskUpdate => self.task_update().await,
            TaskTypeEnum::TaskUploadDir => self.task_upload_dir().await,
            TaskTypeEnum::TaskDownWhite => self.task_down_white().await,
            TaskTypeEnum::TaskDownDirPolicy => self.task_down_dir_policy().await,
            TaskTypeEnum::TaskDownConf => self.task_down_conf().await,
            TaskTypeEnum::TaskDownBlack => self.task_down_black().await,
            TaskTypeEnum::TaskDownFileTtap => self.task_down_file_tt().await,
            TaskTypeEnum::TaskUploadPort => self.task_upload_port().await,
            TaskTypeEnum::TaskDownVirtualPort => self.task_down_virtual_port().await,
            TaskTypeEnum::TaskDownNetBlockPolicy => self.task_down_netblock_policy().await,
            TaskTypeEnum::TaskDownExtort => self.task_down_extort().await,
            TaskTypeEnum::TaskUploadProcessModule => self.task_upload_process_module().await,
            TaskTypeEnum::TaskUploadAllProcessModule => self.task_upload_all_process_module().await,
            TaskTypeEnum::TaskUploadProcessWhiteModule => self.task_upload_process_white_module().await,
            TaskTypeEnum::TaskUploadProcessBlackModule => self.task_upload_process_black_module().await,
            TaskTypeEnum::TaskUninstall => self.task_uninstall().await,
            TaskTypeEnum::TaskGetWhitePeripherals => self.task_get_white_peripherals().await,
            TaskTypeEnum::TaskGetBlackPeripherals => self.task_get_black_peripherals().await,
            TaskTypeEnum::TaskUploadSample => self.task_upload_sample().await,
            TaskTypeEnum::TaskGlobalProc => self.task_global_proc().await,
            TaskTypeEnum::TaskGlobalDir => self.task_global_dir().await,
            TaskTypeEnum::TaskUpdateUUI => self.task_update_uuid().await,
            TaskTypeEnum::TaskOutReachDetect => self.task_outreach_detect().await,
             _ => Err("Unknown task type".to_string()), // 未知任务类型处理
            //_ => Err(format!("Task not implemented: {:?}", task_type)),
        }
    }

    // 处理 TASK_UPLOAD_PROCESS 任务
    async fn task_upload_process(&self) -> Result<(), String> {
        println!("Processing TASK_UPLOAD_PROCESS...");
        // 实际上传逻辑代码
        Ok(())
    }

    // 处理 TASK_UPDATE 任务
    async fn task_update(&self) -> Result<(), String> {
        println!("Processing TASK_UPDATE...");
        // 实际更新逻辑代码
        Ok(())
    }

    // 处理 TASK_UPLOAD_DIR 任务
    async fn task_upload_dir(&self) -> Result<(), String> {
        println!("Processing TASK_UPLOAD_DIR...");
        // 上传目录的处理逻辑
        Ok(())
    }


    // 处理 TASK_DOWN_DIR_POLICY 任务
    async fn task_down_dir_policy(&self) -> Result<(), String> {
        // 获取 download_white 的 URL
        let download_url = match self.api_interface.get("getdirpolicy") {
            Some(url) => url,
                None => return Err("URL for download_white not found".to_string()),
        };

        let net_client = match NetClient::new(self.base_url.clone(), true) {
            Ok(client) => client,
                Err(e) => return Err(format!("Failed to create NetClient: {}", e)),
        };

        let url = format!("{}/{}", self.base_url, download_url);
        let token = self.get_token();
        let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>

        match net_client.post_data_async(&url, "", Duration::from_secs(10), token_str).await {
            Ok(response) => {
                // 解析 JSON 响应
                let parsed: Value = match serde_json::from_str(&response) {
                    Ok(parsed) => parsed,
                        Err(e) => {
                            eprintln!("Failed to parse response: {}", e);
                            return Err("Failed to parse response.".to_string());
                        }
                };

                if parsed["code"] == "000000" {
//                    log_info!("{}", parsed["data"]);
                    let rules = pattern_rules_mgr::PatternRulesMgr::parse_policy_from_json(&parsed["data"])?;
                    //if (rules.len() > 0) 
                    {
                        let mut pattern_mgr = self.pattern_mgr.lock().map_err(|e| e.to_string())?;
                        pattern_mgr.set_protect_dir(rules);
                    }
                } else {
                    eprintln!("Error: Invalid response code: {}", parsed["code"]);
                    return Err("Invalid response code.".to_string());
                }
            }
            Err(err) => {
                eprintln!("Error fetching task: {}", err);
                // 返回错误的 Result 类型
                return Err(err);
            }
        }
        // 下载目录策略的处理
        Ok(())
    }


    // 处理 TASK_DOWN_CONF 任务
    async fn task_down_conf(&mut self) -> Result<(), String> {
        let download_url = match self.api_interface.get("getconf") {
            Some(url) => url,
            None => return Err("URL for download_white not found".to_string()),
        };

        let net_client = match NetClient::new(self.base_url.clone(), true) {
            Ok(client) => client,
            Err(e) => return Err(format!("Failed to create NetClient: {}", e)),
        };
        let url = format!("{}/{}", self.base_url, download_url);

        //println!("Processing TASK_DOWN_CONF...{}", url);
        let token = self.get_token();
        let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>
        match net_client.post_data_async(&url, "", Duration::from_secs(10), token_str).await {
            Ok(response) => {
                // 解析 JSON 响应
                let parsed: Value = match serde_json::from_str(&response) {
                    Ok(parsed) => parsed,
                        Err(e) => {
                            eprintln!("Failed to parse response: {}", e);
                            return Err("Failed to parse response.".to_string());
                        }
                };

                if parsed["code"] == "000000" {
                    let conf = parsed["data"]["conf"]
                        .as_object()
                        .ok_or("Missing 'conf' object in response")?;
                    self.update_config_from_json(conf)?;                   

                } else {
                    eprintln!("Error: Invalid response code: {}", parsed["code"]);
                    // 返回错误的 Result 类型
                    return Err("Invalid response code.".to_string());
                }
            }
            Err(err) => {
                eprintln!("Error fetching task: {}", err);
                // 返回错误的 Result 类型
                return Err(err);
            }
        }


        // 下载配置的处理
        Ok(())
    }

    // 处理 TASK_DOWN_BLACK 任务
    async fn task_down_black(&self) -> Result<(), String> {
        // 获取 download_white 的 URL
        let download_url = match self.api_interface.get("download_black") {
            Some(url) => url,
            None => return Err("URL for download_white not found".to_string()),
        };
        let net_client = match NetClient::new(self.base_url.clone(), true) {
            Ok(client) => client,
            Err(e) => return Err(format!("Failed to create NetClient: {}", e)),
        };

        // 组合最终的 URL
        let url = format!("{}/{}", self.base_url, download_url);
        let token = self.get_token();
        let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>
        match net_client.post_data_async(&url, "", Duration::from_secs(10), token_str).await {
            Ok(response) => {

            // 解析 JSON 响应
            let parsed: Value = match serde_json::from_str(&response) {
                Ok(parsed) => parsed,
                    Err(e) => {
                        eprintln!("Failed to parse response: {}", e);
                        return Err("Failed to parse response.".to_string());
                    }
            };

            if parsed["code"] == "000000" {

                    let hash_list = parsed["data"]["proclist"]
                        .as_array()
                        .ok_or("Missing or invalid proclist in response")?
                        .iter()
                        .filter_map(|item| item["hash"].as_str().map(|s| s.to_string()))
                        .collect::<Vec<String>>();

                    if hash_list.is_empty() {
                        return Err("No hashes found in the response".to_string());
                    }

                    let mut mgr = POLICY_MANAGER.lock().unwrap();
                    mgr.set_policy_process(&hash_list, false);
                } else {
                    eprintln!("Error: Invalid response code: {}", parsed["code"]);
                    // 返回错误的 Result 类型
                    return Err("Invalid response code.".to_string());
                }
            }
            Err(err) => {
                eprintln!("Error fetching task: {}", err);
                // 返回错误的 Result 类型
                return Err(err);
            }
        }

        Ok(())
    }


    pub async fn task_down_white(&self) -> Result<(), String> {
        // 获取 download_white 的 URL
        let download_url = match self.api_interface.get("download_white") {
            Some(url) => url,
            None => return Err("URL for download_white not found".to_string()),
        };


        let net_client = match NetClient::new(self.base_url.clone(), true) {
            Ok(client) => client,
            Err(e) => return Err(format!("Failed to create NetClient: {}", e)),
        };

        let url = format!("{}/{}", self.base_url, download_url);

        let token = self.get_token();
        let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>
        match net_client.post_data_async(&url, "", Duration::from_secs(10), token_str).await {
            Ok(response) => {
                let parsed: Value = match serde_json::from_str(&response) {
                    Ok(parsed) => parsed,
                    Err(e) => {
                        eprintln!("Failed to parse response: {}", e);
                        return Err("Failed to parse response.".to_string());
                    }
                };

                if parsed["code"] == "000000" {
                    let hash_list = parsed["data"]["proclist"]
                        .as_array()
                        .ok_or("Missing or invalid proclist in response")?
                        .iter()
                        .filter_map(|item| item["hash"].as_str().map(|s| s.to_string()))
                        .collect::<Vec<String>>();

                    if hash_list.is_empty() {
                        return Err("No hashes found in the response".to_string());
                    }

                    let mut mgr = POLICY_MANAGER.lock().unwrap();
                    mgr.set_policy_process(&hash_list,true);
                    //println!("hash_list:{:?}",hash_list);
                }
            }
            Err(err) => {
                eprintln!("Error fetching task: {}", err);
                // 返回错误的 Result 类型
                return Err(err);
            }
        }


        Ok(())
    }

    // 处理 TASK_DOWN_FILE_TT 任务
    async fn task_down_file_tt(&self) -> Result<(), String> {
        println!("Processing TASK_DOWN_FILE_TT...");
        // 下载文件 TT 的处理
        Ok(())
    }

    // 处理 TASK_UPLOAD_PORT 任务
    async fn task_upload_port(&self) -> Result<(), String> {
        //println!("Processing TASK_UPLOAD_PORT...");
        // 端口上传处理
        Ok(())
    }

    pub async fn task_down_virtual_port(&self) -> Result<(), String> {
        let download_url = match self.api_interface.get("getvirtualport") {
            Some(url) => url,
            None => return Err("URL for getvirtualport not found".to_string()),
        };

        let net_client = NetClient::new(self.base_url.clone(), true)
            .map_err(|e| format!("Failed to create NetClient: {}", e))?;

        let url = format!("{}/{}", self.base_url, download_url);
        let token = self.get_token();
        let token_str = token.as_ref().map(|s| s.as_str());

        let response = net_client.post_data_async(&url, "", Duration::from_secs(10), token_str).await?;
        let parsed: Value = serde_json::from_str(&response)
            .map_err(|e| format!("Failed to parse response JSON: {}", e))?;

        if parsed["code"] != "000000" {
            return Err(format!("Invalid response code: {}", parsed["code"]));
        }

        let conf: Vec<VirtualPortRule> = parsed["data"]
            .as_array()
            .ok_or("Missing 'data' array in response")?
            .iter()
            .map(|item| {
                serde_json::from_value(item.clone())
                    .map_err(|e| format!("Failed to parse VirtualPortRule: {}", e))
            })
        .collect::<Result<Vec<VirtualPortRule>, _>>()?;

        let valid_rules: Vec<_> = conf.into_iter()
            .filter(|r| !r.source_ip.is_empty())
            .collect();

        let total = valid_rules.len();
        if total == 0 {
            log_error!("No valid rules to write to /proc/osec/net_rules");
            return Ok(());
        }

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open("/proc/osec/net_rules")
            .await
            .map_err(|e| format!("Failed to open /proc/osec/net_rules: {}", e))?;

        for (index, rule) in valid_rules.iter().enumerate() {
            // protocol 转数字: tcp=1, udp=2, 其他=0
            let protocol_num = match rule.protocol.to_lowercase().as_str() {
                "tcp" => 1,
                "udp" => 2,
                _ => 0,
            };

            let is_ipv4 = if rule.dest_ip.contains(':') { 0u8 } else { 1u8 }; // ':' 表示 IPv6
                                                                              // if

            let addr_type = (rule.alarm_level & 0x1f) as u8;

            let rule_str = format!(
                "VIR_OPEN_PORT index={} total={} id={} protocol={} type={} is_ipv4={} source_ip={} start_port={} end_port={}  dest_ip={} dest_port_type={} redirectPort={} addr_type={}\n",
                index,
                total,
                rule.id,
                protocol_num,
                rule.r#type,
                is_ipv4,
                rule.source_ip,
                rule.source_port_range.0,
                rule.source_port_range.1,
                if rule.dest_ip.trim().is_empty() {
                    "\"\""
                } else {
                    &rule.dest_ip
                },
                rule.dest_port_type,
                if rule.dest_port_type == 0 {
                    rule.dest_port.parse::<u16>().unwrap_or(0)
                } else {
                    0
                },
                addr_type,
            );

            log_info!("{}", rule_str);

            file.write_all(rule_str.as_bytes())
                .await
                .map_err(|e| format!("Failed to write rule: {}", e))?;
            }

        file.flush()
            .await
            .map_err(|e| format!("Failed to flush /proc/osec/net_rules: {}", e))?;

        log_info!("Successfully wrote {} rules to /proc/osec/net_rules", total);

        Ok(())
    }
    // 处理 TASK_DOWN_NETBLOCK_POLICY 任务
    async fn task_down_netblock_policy(&self) -> Result<(), String> {
        println!("Processing TASK_DOWN_NETBLOCK_POLICY...");
        // 下载网络阻塞策略
        Ok(())
    }

    async fn task_down_extort(&self) -> Result<(), String> {
        // 获取 download_white 的 URL
        let download_url = match self.api_interface.get("getprotect") {
            Some(url) => url,
            None => return Err("URL for download_white not found".to_string()),
        };
        let net_client = match NetClient::new(self.base_url.clone(), true) {
            Ok(client) => client,
            Err(e) => return Err(format!("Failed to create NetClient: {}", e)),
        };
        
        let url = format!("{}/{}", self.base_url, download_url);
        let token = self.get_token();
        let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>
        match net_client.post_data_async(&url, "", Duration::from_secs(10), token_str).await {
            Ok(response) => {

            // 解析 JSON 响应
            let parsed: Value = match serde_json::from_str(&response) {
                Ok(parsed) => parsed,
                    Err(e) => {
                        eprintln!("Failed to parse response: {}", e);
                        return Err("Failed to parse response.".to_string());
                    }
            };

            if parsed["code"] == "000000" {
                let rules = pattern_rules_mgr::PatternRulesMgr::parse_exipor_policy_from_json(&parsed["data"])?;
                let mut pattern_mgr = self.pattern_mgr.lock().map_err(|e| e.to_string())?;
                pattern_mgr.set_exiport_dir(rules);

                } else {
                    eprintln!("Error: Invalid response code: {}", parsed["code"]);
                    // 返回错误的 Result 类型
                    return Err("Invalid response code.".to_string());
                }
            }
            Err(err) => {
                eprintln!("Error fetching task: {}", err);
                // 返回错误的 Result 类型
                return Err(err);
            }
        }

       // println!("Extracted hashes: {:?}", hash_list);

        Ok(())
    }



    // 处理 TASK_UPLOAD_PROCESS_MODULE 任务
    async fn task_upload_process_module(&self) -> Result<(), String> {
        println!("Processing TASK_UPLOAD_PROCESS_MODULE...");
        // 上传进程模块的处理
        Ok(())
    }

    // 处理 TASK_UPLOAD_ALL_PROCESS_MODULE 任务
    async fn task_upload_all_process_module(&self) -> Result<(), String> {
        println!("Processing TASK_UPLOAD_ALL_PROCESS_MODULE...");
        // 上传所有进程模块的处理
        Ok(())
    }

    // 处理 TASK_UPLOAD_PROCESS_WHITE_MODULE 任务
    async fn task_upload_process_white_module(&self) -> Result<(), String> {
        println!("Processing TASK_UPLOAD_PROCESS_WHITE_MODULE...");
        // 上传白名单进程模块的处理
        Ok(())
    }

    // 处理 TASK_UPLOAD_PROCESS_BLACK_MODULE 任务
    async fn task_upload_process_black_module(&self) -> Result<(), String> {
        println!("Processing TASK_UPLOAD_PROCESS_BLACK_MODULE...");
        // 上传黑名单进程模块的处理
        Ok(())
    }

    // 处理 TASK_UNINSTALL 任务
    async fn task_uninstall(&self) -> Result<(), String> {
        println!("Processing TASK_UNINSTALL...");
        // 卸载任务处理
        Ok(())
    }

    // 处理 TASK_getwhiteperipherals 任务
    async fn task_get_white_peripherals(&self) -> Result<(), String> {
        println!("Processing TASK_getwhiteperipherals...");
        // 获取白名单外设的处理
        Ok(())
    }

    // 处理 TASK_getblackperipherals 任务
    async fn task_get_black_peripherals(&self) -> Result<(), String> {
        println!("Processing TASK_getblackperipherals...");
        // 获取黑名单外设的处理
        Ok(())
    }

    // 处理 TASK_UPLOADSAMPLE 任务
    async fn task_upload_sample(&self) -> Result<(), String> {
        println!("Processing TASK_UPLOADSAMPLE...");
        // 上传样本的处理
        Ok(())
    }


    // 处理 TASK_GLOBAL_PROC 任务
    async fn task_global_proc(&self) -> Result<(), String> {
        let upload_url = match self.api_interface.get("upload_gloabal_process") {
            Some(url) => url,
            None => return Err("URL for upload_gloabal_process not found".to_string()),
        };

        let net_client = match NetClient::new(self.base_url.clone(), true) {
            Ok(client) => client,
            Err(e) => return Err(format!("Failed to create NetClient: {}", e)),
        };

        // 组合最终的 URL
        let url = format!("{}/{}", self.base_url, upload_url);
        let token = self.get_token();
        let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>
        process_all_dirs(net_client, &url, token_str).await?;

        Ok(())
    }

    // 处理 TASK_GLOBAL_DIR 任务
    async fn task_global_dir(&self) -> Result<(), String> {
        // 获取 download_white 的 URL
        let download_url = match self.api_interface.get("gettrustdir") {
            Some(url) => url,
            None => return Err("URL for download_white not found".to_string()),
        };
        let net_client = match NetClient::new(self.base_url.clone(), true) {
            Ok(client) => client,
            Err(e) => return Err(format!("Failed to create NetClient: {}", e)),
        };

        // 组合最终的 URL
        let url = format!("{}/{}", self.base_url, download_url);
        println!("=================={}",url);
        let token = self.get_token();
        let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>
        match net_client.post_data_async(&url, "", Duration::from_secs(10), token_str).await {
            Ok(response) => {
            println!("======={}", response);
            // 解析 JSON 响应
            let parsed: Value = match serde_json::from_str(&response) {
                Ok(parsed) => parsed,
                    Err(e) => {
                        eprintln!("Failed to parse response: {}", e);
                        return Err("Failed to parse response.".to_string());
                    }
            };

            if parsed["code"] == "000000" {
            
                let data_list = parsed["data"]
                    .as_array()
                    .ok_or("Missing task list in response")?
                    .iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u32))
                    .collect::<Vec<u32>>();

                    println!("======={}======={:?}", url, data_list);

                    // 如果成功，返回 Ok(())，因为返回类型是 Result<(), String>
                } else {
                    eprintln!("Error: Invalid response code: {}", parsed["code"]);
                    // 返回错误的 Result 类型
                    return Err("Invalid response code.".to_string());
                }
            }
            Err(err) => {
                eprintln!("Error fetching task: {}", err);
                // 返回错误的 Result 类型
                return Err(err);
            }
        }

 
        // 全局目录的处理
        Ok(())
    }

    // 处理 TASK_UPDATE_UUID 任务
    async fn task_update_uuid(&self) -> Result<(), String> {
        println!("Processing TASK_UPDATE_UUID...");
        // 更新 UUID 处理
        Ok(())
    }

    // 处理 TASK_OutreachDetect 任务
    async fn task_outreach_detect(&self) -> Result<(), String> {
        println!("Processing TASK_OutreachDetect...");
        // 外围探测任务处理
        Ok(())
    }

}
// 定义返回类型为 `impl Future`，并显式添加 `Send` trait bound
pub trait TaskService {
    fn task_fetcher(&mut self, host_is_offline_tx: mpsc::Sender<bool>, token_rx: mpsc::Receiver<String>, nl_sock: Option<NlSockInfo>) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>; 
}
impl TaskService for BootManager {
    fn task_fetcher(
        &mut self,
        host_is_offline_tx: mpsc::Sender<bool>,
        token_rx: mpsc::Receiver<String>,
    nl_sock: Option<NlSockInfo>,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {
            let mut token_rx = token_rx;
            loop {
                let base_url = self.get_base_url();

                let mut net_client = match NetClient::new(base_url, true) {
                    Ok(client) => client,
                    Err(err) => {
                        eprintln!("创建 NetClient 失败: {}", err);
                        return Err("创建 NetClient 失败".to_string());
                    }
                };
                println!("等待接收 token...");
                // 阻塞，等待接收到新的 token
                if let Some(token) = token_rx.recv().await {
                    let token_option = Some(token); // 接收到的 token

                    println!("收到 token，开始任务处理...");
                    let nl_sock = nl_sock.clone(); 
                    // 调用 TaskFetcher::run，处理任务
                    match TaskFetcher::run(&mut net_client, token_option, self.pattern_mgr(),nl_sock).await {
                        Ok(()) => {
                            println!("任务处理成功，继续监听 token...");
                        }
                        Err(err) => {
                            eprintln!("任务处理失败或服务器离线: {}", err);

                            // 发送离线信号，通知重新获取 token
                            if let Err(e) = host_is_offline_tx.send(true).await {
                                eprintln!("发送离线信号失败: {}", e);
                            }

                            // 跳出当前循环，重新等待 token
                            continue;
                        }
                    }
                } else {
                    eprintln!("Token 通道已关闭，退出任务...");
                    break;
                }
            }

            Ok("后台任务已启动.".to_string())
        })
    }
}


