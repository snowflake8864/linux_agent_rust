use reqwest::{Client, Proxy};
use std::time::Duration;
use serde::Deserialize;
use std::env;
use std::fs;
use std::io::Write;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use logging::log_info;

use tokio::sync::Mutex;  
use once_cell::sync::Lazy;

static FILE_CACHE: Lazy<Mutex<HashMap<String, (String, u128)>>> = 
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Deserialize)]
struct ResponseData {
    code: String,
    data: Data,
    msg: String,
}

#[derive(Deserialize)]
struct Data {
    token: String,
}

pub struct NetClient {
    client: Option<Client>, // 仅在线模式有 client
    pub base_url: String,
    pub offline: bool,      // true = 离线模式, false = 在线模式
    pub app_path: Option<String>
}

pub enum WriteMode {
    Overwrite,
    Append,
}
impl NetClient {
    pub fn new(base_url: String, disable_ssl: bool, offline: bool, app_path: Option<String>) -> Result<Self, String> {
        if offline {
            // 离线模式：不需要 client
            Ok(NetClient {
                client: None,
                base_url,
                offline,
                app_path,
            })
        } else {
            // 在线模式：初始化 reqwest client
            let mut client_builder = Client::builder()
                .timeout(Duration::from_secs(10));

            if disable_ssl {
                client_builder = client_builder.danger_accept_invalid_certs(true);
            }

            if let Ok(proxy_url) = env::var("HTTP_PROXY") {
                let proxy = Proxy::http(&proxy_url)
                    .map_err(|e| format!("Failed to set proxy: {}", e))?;
                client_builder = client_builder.proxy(proxy);
                println!("Using proxy: {}", proxy_url);
            } else {
                println!("No proxy is set.");
            }

            let client = client_builder
                .build()
                .map_err(|e| format!("Failed to create client: {}", e))?;

            Ok(NetClient {
                client: Some(client),
                base_url,
                offline,
                app_path,
            })
        }
    }

    pub async fn post_data_async(
        &self,
        url: &str,
        json_data: &str,
        timeout: Duration,
        token: Option<&str>,
        offline_file: Option<&str>,
    ) -> Result<String, String> {
        if self.offline {
            let file = offline_file.ok_or("Offline mode requires a json file path")?;
            let full_path = self.build_responds_path(file);
            fs::read_to_string(&full_path).map_err(|e| format!("Failed to read offline file: {}", e))
        } else {
            let client = self.client.as_ref().ok_or("Client not initialized")?;
            let mut request = client
                .post(url)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .timeout(timeout)
                .body(json_data.to_string());

            if let Some(token_str) = token {
                request = request.header("Authorization", format!("{}", token_str));
            }

            let response = request.send().await;
            match response {
                Ok(r) => {
                    let status_code = r.status();
                    let response_text = r.text().await
                        .map_err(|e| format!("Failed to read response text: {}", e))?;
                    if status_code.is_success() {
                        Ok(response_text)
                    } else {
                        Err(format!(
                            "POST request failed with status: {} - {}",
                            status_code, response_text
                        ))
                    }
                }
                Err(e) => Err(format!("Failed to send POST request: {}", e)),
            }
        }
    }
  pub async fn post_data_write_async(
        &self,
        url: &str,
        json_data: &str,
        timeout: Duration,
        token: Option<&str>,
        offline_file: Option<&str>,
        write_mode: Option<WriteMode>, // 离线写入模式
  ) -> Result<String, String> {
      if self.offline {
          let file = offline_file.ok_or("Offline mode requires a file path")?;
          let full_path = self.build_save_path(file);
          let mode = write_mode.unwrap_or(WriteMode::Overwrite);
          if let Some(parent) = std::path::Path::new(&full_path).parent() {
              fs::create_dir_all(parent)
                  .map_err(|e| format!("Failed to create directories: {}", e))?;
          }
          match mode {
              WriteMode::Overwrite => {
                  fs::write(&full_path, json_data)
                      .map_err(|e| format!("Failed to overwrite offline file: {}", e))?;
                  }
              WriteMode::Append => {
                  let mut f = fs::OpenOptions::new()
                      .create(true)
                      .append(true)
                      .open(&full_path)
                      .map_err(|e| format!("Failed to open file for append: {}", e))?;
                  writeln!(f, "{}", json_data)
                      .map_err(|e| format!("Failed to append to file: {}", e))?;
                  }
          }
        Ok(r#"{"code":"000000","data":"","msg":"OK"}"#.to_string())
        //Ok(json_data.to_string())
      } else {
          let client = self.client.as_ref().ok_or("Client not initialized")?;
          let mut request = client
              .post(url)
              .header("Content-Type", "application/json")
              .header("Accept", "application/json")
              .timeout(timeout)
              .body(json_data.to_string());

          if let Some(token_str) = token {
              request = request.header("Authorization", format!("{}", token_str));
          }

          let response = request.send().await;
          match response {
              Ok(r) => {
                  let status_code = r.status();
                  let response_text = r
                      .text()
                      .await
                      .map_err(|e| format!("Failed to read response text: {}", e))?;
                  if status_code.is_success() {
                      Ok(response_text)
                  } else {
                      Err(format!(
                              "POST request failed with status: {} - {}",
                              status_code, response_text
                      ))
                  }
              }
              Err(e) => Err(format!("Failed to send POST request: {}", e)),
          }
      }
  }
    pub async fn get_data_async(
        &self,
        url: &str,
        timeout: Duration,
        token: Option<&str>,
        offline_file: Option<&str>,
    ) -> Result<String, String> {
        if self.offline {
            let file = offline_file.ok_or("Offline mode requires a json file path")?;
            fs::read_to_string(file).map_err(|e| format!("Failed to read offline file: {}", e))
        } else {
            let client = self.client.as_ref().ok_or("Client not initialized")?;
            let mut req = client.get(url)
                .header("Accept", "application/json")
                .timeout(timeout);

            if let Some(t) = token {
                req = req.header("Authorization", format!("{}", t));
            }

            let resp = req.send().await;
            match resp {
                Ok(r) => {
                    let status = r.status();
                    let text = r.text().await
                        .map_err(|e| format!("Failed to read response: {}", e))?;
                    if status.is_success() {
                        Ok(text)
                    } else {
                        Err(format!("GET failed {}: {}", status, text))
                    }
                }
                Err(e) => Err(format!("Request failed: {}", e)),
            }
        }
    }

    pub async fn post_data_async_with_cache(
        &self,
        url: &str,
        json_data: &str,
        timeout: Duration,
        token: Option<&str>,
        offline_file: Option<&str>,
        default_response_file: Option<&str>,
    ) -> Result<String, String> {
        if self.offline {
            let file = offline_file.ok_or("Offline mode requires a json file path")?;
            let full_path = self.build_responds_path(file);

            // 获取文件修改时间
            let metadata = fs::metadata(&full_path)
                .map_err(|e| format!("Failed to get file metadata: {}", e))?;

            let modified_time = metadata.modified()
                .map_err(|e| format!("Failed to get modified time: {}", e))?
                .duration_since(UNIX_EPOCH)
                .map_err(|e| format!("Time error: {}", e))?
                .as_millis();

            // 使用异步锁
            let mut cache = FILE_CACHE.lock().await;
            let cache_key = full_path.clone();

            if let Some((cached_content, cached_time)) = cache.get(&cache_key) {
                if *cached_time == modified_time {
                    return self.get_default_response(default_response_file).await;
                }
            }

            // 读取文件内容
            let content = fs::read_to_string(&full_path)
                .map_err(|e| format!("Failed to read offline file: {}", e))?;

            cache.insert(cache_key, (content.clone(), modified_time));
            Ok(content)
        } else {
            let client = self.client.as_ref().ok_or("Client not initialized")?;
            let mut request = client
                .post(url)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .timeout(timeout)
                .body(json_data.to_string());

            if let Some(token_str) = token {
                request = request.header("Authorization", format!("{}", token_str));
            }

            let response = request.send().await;
            match response {
                Ok(r) => {
                    let status_code = r.status();
                    let response_text = r.text().await
                        .map_err(|e| format!("Failed to read response text: {}", e))?;
                    if status_code.is_success() {
                        Ok(response_text)
                    } else {
                        Err(format!(
                                "POST request failed with status: {} - {}",
                                status_code, response_text
                        ))
                    }
                }
                Err(e) => Err(format!("Failed to send POST request: {}", e)),
            }
        }
    }

    async fn get_default_response(&self, default_response_file: Option<&str>) -> Result<String, String> {
        match default_response_file {
            Some(file_path) => {
                let full_path = self.build_responds_path(file_path);
                fs::read_to_string(&full_path)
                    .map_err(|e| format!("Failed to read default response file: {}", e))
            }
            None => {
                Ok(r#"{"code":"000000","data":{"tasklist":[]},"msg":"OK"}"#.to_string())
            }
        }
    }

     fn build_save_path(&self, relative_path: &str) -> String {
        if let Some(ref app_path) = self.app_path {
            //format!("{}/offline_save/{}", app_path, relative_path)
            format!("/opt/offline_osec/offline_save/{}", relative_path)
        } else {
            relative_path.to_string()
        }
    }
     fn build_responds_path(&self, relative_path: &str) -> String {
        if let Some(ref app_path) = self.app_path {
            //format!("{}/offline_responds/{}", app_path, relative_path)
            format!("/opt/offline_osec/offline_responds/{}", relative_path)
        } else {
            relative_path.to_string()
        }
    }

}

