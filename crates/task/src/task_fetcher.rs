// task_fetcher.rs
use std::pin::Pin;
use std::future::Future;
use serde_json::Value;
use net_client::core::NetClient;
use std::time::Duration;
use std::collections::HashMap;
use std::io;  // 引入 io 模块
use common::{
    manager::boot::{BootManager},
};
use tokio::task::JoinHandle;
//use hostinfo::HostInfo;

use tokio::sync::mpsc;

pub struct TaskFetcher {
    base_url: String,
    token: Option<String>,  // 'a 表示 token 的生命周期与 TaskFetcher 的生命周期相同
    api_interface: HashMap<String, String>,
}
use num_derive::FromPrimitive; // 支持从整数到枚举的转换
use num_traits::FromPrimitive;

#[derive(Debug, FromPrimitive)]
enum TASK_TYPE {
    TASK_UPLOAD_PROCESS = 0,
    TASK_UPDATE = 1,
    TASK_UPLOAD_DIR = 2,
    TASK_DOWN_WHITE = 3,
    TASK_DOWN_DIR_POLICY = 4,
    TASK_UPLOAD_CONF = 5, // no use
    TASK_DOWN_CONF = 6,
    TASK_DOWN_BLACK = 7,
    TASK_DOWN_FILE_TTAP = 8,
    TASK_UPLOAD_PORT = 9,
    TASK_DOWN_VIRTUAL_PORT = 10,
    TASK_AUTODOWN_NETBLOACK_POLICY = 11, // no use
    TASK_AUTOUPLOAD_NETBLOACK_POLICY = 12, // no use
    TASK_DOWN_NETBLOACK_POLICY = 13,
    TASK_DOWN_WHITE_IP_POLICY = 14, // no use
    TASK_DOWN_BLACK_IP_POLICY = 15,
    TASK_DOWN_USB_UPLOAD = 16,
    TASK_DOWN_USB_DOWN = 17, // no use
    TASK_DOWN_EXTORT = 19,
    TASK_UPLOAD_PROCESS_MODULE = 21,
    TASK_UPLOAD_ALL_PROCESS_MODULE = 22,
    TASK_UPLOAD_PROCESS_WHITE_MODULE = 23,
    TASK_UPLOAD_PROCESS_BLACK_MODULE = 24,
    TASK_UNINSTALL = 25,
    TASK_getwhiteperipherals = 26,
    TASK_getblackperipherals = 27,
    TASK_UPLOADSAMPLE = 28,
    TASK_SYSLOG_ENABLE = 29, // no use
    TASK_SYSLOG_DISABLE = 30, // no use
    TASK_GLOBAL_PROC = 31,
    TASK_GLOBAL_DIR = 33,
    TASK_UPDATE_UUID = 34,
    TASK_OutreachDetect = 35,
}


impl TaskFetcher {
    pub fn new(base_url: &str, token: Option<String>) -> Self 
    {
        let mut api_interface = HashMap::new();
        api_interface.insert("download_white".to_string(), "v1/getprocwl".to_string());
        api_interface.insert("download_black".to_string(), "v1/getprocbl".to_string());
        api_interface.insert("getconf".to_string(), "v1/getconf".to_string());
        api_interface.insert("getprotect".to_string(), "v1/getprotect".to_string());
        api_interface.insert("getdirpolicy".to_string(), "v1/getdirpolicy".to_string());
        api_interface.insert("upload_process".to_string(), "v1/uploadproc".to_string());
        api_interface.insert("gettrustdir".to_string(), "v1/gettrustdir".to_string());

        TaskFetcher {
              base_url: base_url.to_string(),
              token,
              api_interface,
        }
    }
    pub fn get_token(&self) -> Option<String> {
        self.token.clone()
    }
    pub async fn run(net_client: &mut NetClient, token: Option<String>) -> Result<(), String> {
        let token_str = token.as_ref().map(|s| s.as_str());
        let mut task_fetcher = TaskFetcher::new(&net_client.base_url, token.clone());

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
                        
                        println!("task list:{:?}", task_list);
                        for task_id in task_list {
                            if let Some(task_type) = TASK_TYPE::from_u32(task_id) {
                                println!("task ID: {}", task_id);
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
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }


   /// 根据任务类型处理任务
    async fn handle_task(&self, task_type: TASK_TYPE) -> Result<(), String> {
        match task_type {
            TASK_TYPE::TASK_UPLOAD_PROCESS => self.task_upload_process().await,
            TASK_TYPE::TASK_UPDATE => self.task_update().await,
            TASK_TYPE::TASK_UPLOAD_DIR => self.task_upload_dir().await,
            TASK_TYPE::TASK_DOWN_WHITE => self.task_down_white().await,
            TASK_TYPE::TASK_DOWN_DIR_POLICY => self.task_down_dir_policy().await,
            TASK_TYPE::TASK_DOWN_CONF => self.task_down_conf().await,
            TASK_TYPE::TASK_DOWN_BLACK => self.task_down_black().await,
            TASK_TYPE::TASK_DOWN_FILE_TTAP => self.task_down_file_tt().await,
            TASK_TYPE::TASK_UPLOAD_PORT => self.task_upload_port().await,
            TASK_TYPE::TASK_DOWN_VIRTUAL_PORT => self.task_down_virtual_port().await,
            TASK_TYPE::TASK_DOWN_NETBLOACK_POLICY => self.task_down_netblock_policy().await,
            TASK_TYPE::TASK_DOWN_EXTORT => self.task_down_extort().await,
            TASK_TYPE::TASK_UPLOAD_PROCESS_MODULE => self.task_upload_process_module().await,
            TASK_TYPE::TASK_UPLOAD_ALL_PROCESS_MODULE => self.task_upload_all_process_module().await,
            TASK_TYPE::TASK_UPLOAD_PROCESS_WHITE_MODULE => self.task_upload_process_white_module().await,
            TASK_TYPE::TASK_UPLOAD_PROCESS_BLACK_MODULE => self.task_upload_process_black_module().await,
            TASK_TYPE::TASK_UNINSTALL => self.task_uninstall().await,
            TASK_TYPE::TASK_getwhiteperipherals => self.task_get_white_peripherals().await,
            TASK_TYPE::TASK_getblackperipherals => self.task_get_black_peripherals().await,
            TASK_TYPE::TASK_UPLOADSAMPLE => self.task_upload_sample().await,
            TASK_TYPE::TASK_GLOBAL_PROC => self.task_global_proc().await,
            TASK_TYPE::TASK_GLOBAL_DIR => self.task_global_dir().await,
            TASK_TYPE::TASK_UPDATE_UUID => self.task_update_uuid().await,
            TASK_TYPE::TASK_OutreachDetect => self.task_outreach_detect().await,
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

        let mut net_client = match NetClient::new(self.base_url.clone(), true) {
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
                    // 提取 tasklist
                    let data_list = parsed["data"]
                        .as_array()
                        .ok_or("Missing task list in response")?
                        .iter()
                        .filter_map(|v| v.as_u64().map(|n| n as u32))
                        .collect::<Vec<u32>>();

                    println!("======={}======={:?}", url, data_list);

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
        println!("====================================");
        // 下载目录策略的处理
        Ok(())
    }


    // 处理 TASK_DOWN_CONF 任务
    async fn task_down_conf(&self) -> Result<(), String> {
        // 获取 download_white 的 URL
        let download_url = match self.api_interface.get("getconf") {
            Some(url) => url,
            None => return Err("URL for download_white not found".to_string()),
        };

        let mut net_client = match NetClient::new(self.base_url.clone(), true) {
            Ok(client) => client,
            Err(e) => return Err(format!("Failed to create NetClient: {}", e)),
        };
        // 组合最终的 URL
        let url = format!("{}/{}", self.base_url, download_url);

        //println!("Processing TASK_DOWN_CONF...{}", url);
        let token = self.get_token();
        let token_str = token.as_ref().map(|s| s.as_str()); // 转换为 Option<&str>
        match net_client.post_data_async(&url, "", Duration::from_secs(10), token_str).await {
            Ok(response) => {
                    //println!("2===={:?}", response);
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

                    // 打印 "conf" 的内容
                   // for (key, value) in conf {
                   //     println!("{}: {}", key, value);
                   // }

                    //println!("===={:?}", conf);

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
        let mut net_client = match NetClient::new(self.base_url.clone(), true) {
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
            
                let data_list = parsed["data"]["proclist"]
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
        // 打印或处理 hash 列表
       // println!("Extracted hashes: {:?}", hash_list);

        println!("Processing TASK_DOWN_BLACK...");
        Ok(())
    }


// 处理下载白名单任务
    pub async fn task_down_white(&self) -> Result<(), String> {
        // 获取 download_white 的 URL
        let download_url = match self.api_interface.get("download_white") {
            Some(url) => url,
            None => return Err("URL for download_white not found".to_string()),
        };


        let mut net_client = match NetClient::new(self.base_url.clone(), true) {
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
           
                        // 获取 hash 列表
                    let hash_list = parsed["data"]["proclist"]
                        .as_array()
                        .ok_or("Missing or invalid proclist in response")?
                        .iter()
                        .filter_map(|item| item["hash"].as_str().map(|s| s.to_string()))
                        .collect::<Vec<String>>();

                    if hash_list.is_empty() {
                        return Err("No hashes found in the response".to_string());
                    }

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
        println!("Processing TASK_UPLOAD_PORT...");
        // 端口上传处理
        Ok(())
    }

    // 处理 TASK_DOWN_VIRTUAL_PORT 任务
    async fn task_down_virtual_port(&self) -> Result<(), String> {
        println!("Processing TASK_DOWN_VIRTUAL_PORT...");
        // 虚拟端口下载处理
        Ok(())
    }

    // 处理 TASK_DOWN_NETBLOCK_POLICY 任务
    async fn task_down_netblock_policy(&self) -> Result<(), String> {
        println!("Processing TASK_DOWN_NETBLOCK_POLICY...");
        // 下载网络阻塞策略
        Ok(())
    }

    // 处理 TASK_DOWN_BLACK 任务
    async fn task_down_extort(&self) -> Result<(), String> {
        // 获取 download_white 的 URL
        let download_url = match self.api_interface.get("getprotect") {
            Some(url) => url,
            None => return Err("URL for download_white not found".to_string()),
        };
        let mut net_client = match NetClient::new(self.base_url.clone(), true) {
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
        println!("Processing TASK_GLOBAL_PROC...");
        // 全局进程的处理
        Ok(())
    }

    // 处理 TASK_GLOBAL_DIR 任务
    async fn task_global_dir(&self) -> Result<(), String> {
        // 获取 download_white 的 URL
        let download_url = match self.api_interface.get("gettrustdir") {
            Some(url) => url,
            None => return Err("URL for download_white not found".to_string()),
        };
        let mut net_client = match NetClient::new(self.base_url.clone(), true) {
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
    fn task_fetcher(&mut self, host_is_offline_tx: mpsc::Sender<bool>, token_rx: mpsc::Receiver<String>) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>; 
}

impl TaskService for BootManager {
    fn task_fetcher(
        &mut self,
        host_is_offline_tx: mpsc::Sender<bool>,
        token_rx: mpsc::Receiver<String>,
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {
            let mut token_rx = token_rx;
            let mut host_is_offline_tx = host_is_offline_tx;

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
                    // 调用 TaskFetcher::run，处理任务
                    match TaskFetcher::run(&mut net_client, token_option).await {
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

