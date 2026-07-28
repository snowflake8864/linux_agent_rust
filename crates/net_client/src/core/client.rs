use reqwest::{Client, Proxy};
use std::time::Duration;
use serde::{Deserialize};
use std::env;
use tokio::net::lookup_host;
use url::Url;

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
    client: Client,
    pub base_url: Option<String>,
}
#[derive(Debug)]
pub struct GetDataWithIpResponse {
    pub body: String,          // HTTP 返回内容
    pub domain_ips: Vec<String>, // URL 域名对应 IP 列表
}
#[derive(Debug)]
pub struct PostDataWithIpResponse {
    pub body: String,          // POST 返回内容
    pub domain_ips: Vec<String>, // 域名解析的 IP 列表
}

impl NetClient {
     pub fn new(base_url: Option<String>, disable_ssl: bool) -> Result<Self, String> {
        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(30)); // 设置请求超时时间

        // 如果禁用 SSL 证书验证，则设置相应的选项
        if disable_ssl {
            client_builder = client_builder.danger_accept_invalid_certs(true); // 禁用 SSL 证书验证
        }

        if let Ok(proxy_url) = env::var("HTTP_PROXY") {
            let proxy = Proxy::http(&proxy_url)
                .map_err(|e| format!("Failed to set proxy: {}", e))?;
            client_builder = client_builder.proxy(proxy);
            println!("Using proxy: {}", proxy_url);
        } else {
            println!("No proxy is set.");
        }

        // 使用客户端构建器来构建最终的 Client
        let client = client_builder
            .build()
            .map_err(|e| format!("Failed to create client: {}", e))?;

        Ok(NetClient {
            client,
            base_url,
        })
    }

    
    // 异步版本的 POST 请求
    pub async fn post_data_async(
        &self,
        url: &str,
        json_data: &str,
        timeout: Duration,
        token: Option<&str>, // 添加 token 参数
    ) -> Result<String, String> {
        let mut request = self
            .client
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
                let response_text = r.text().await.map_err(|e| format!("Failed to read response text: {}", e))?;
                if status_code.is_success() {
                    Ok(response_text)
                } else if status_code.is_client_error() {
                    Ok(response_text)
                } 
                else {
                    Err(format!("POST request failed with status: {} - {}", status_code, response_text))
                }
            }
            Err(e) => Err(format!("Failed to send POST request: {}", e)),
        }
    }

   pub async fn get_data_async(
        &self,
        url: &str,
        timeout: Duration,
        token: Option<&str>,
    ) -> Result<String, String> {
        let mut req = self.client.get(url)
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
   pub async fn get_data_with_ip_async(
       &self,
       url: &str,
       timeout: Duration,
       token: Option<&str>,
   ) -> Result<GetDataWithIpResponse, String> {

       let parsed = Url::parse(url)
           .map_err(|e| format!("URL 解析失败: {}", e))?;

       let domain = parsed.host_str()
           .ok_or_else(|| "URL 中没有域名".to_string())?;

       let port = parsed.port().unwrap_or(80);
       let host_port = format!("{}:{}", domain, port);

       let domain_ips: Vec<String> = lookup_host(host_port)
           .await
           .map_err(|e| format!("DNS 解析失败: {}", e))?
           .map(|addr| addr.ip().to_string())
           .collect();

       let mut req = self.client.get(url)
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
                   Ok(GetDataWithIpResponse {
                       body: text,
                       domain_ips,
                   })
               } else {
                   Err(format!("GET failed {}: {}", status, text))
               }
           }
           Err(e) => Err(format!("Request failed: {}", e)),
       }
   }
    /// 异步下载文件内容（返回字节数组）
    pub async fn download_file_async(
        &self,
        url: &str,
        timeout: Duration,
        token: Option<&str>,
    ) -> Result<Vec<u8>, String> {
        let mut request = self
            .client
            .get(url)
            .timeout(timeout);

        // 如果有 token，加入 Header
        if let Some(token_str) = token {
            request = request.header("Authorization", format!("{}", token_str));
        }

        // 发送请求
        let response = request.send().await.map_err(|e| format!("请求失败: {}", e))?;

        // 检查状态码
        let status = response.status();
        if !status.is_success() {
            let err_text = response
                .text()
                .await
                .unwrap_or_else(|_| "<无法读取错误信息>".to_string());
            return Err(format!("下载失败 (HTTP {}): {}", status, err_text));
        }

        // 读取整个文件内容
        let bytes = response
            .bytes()
            .await
            .map_err(|e| format!("读取响应数据失败: {}", e))?;

        Ok(bytes.to_vec())
    }

pub async fn post_data_with_ip_async(
        &self,
        url: &str,
        json_data: &str,
        timeout: Duration,
        token: Option<&str>,
    ) -> Result<PostDataWithIpResponse, String> {

        // ----------- 新增：获取域名对应 IP -----------------
        let parsed = Url::parse(url)
            .map_err(|e| format!("URL 解析失败: {}", e))?;

        let domain = parsed.host_str()
            .ok_or_else(|| "URL 中没有域名".to_string())?;

        let port = parsed.port().unwrap_or(80);
        let host_port = format!("{}:{}", domain, port);

        let domain_ips: Vec<String> = lookup_host(host_port)
            .await
            .map_err(|e| format!("DNS 解析失败: {}", e))?
            .map(|addr| addr.ip().to_string())
            .collect();
        // ----------------------------------------------------

        // ---------------- 原本的 POST 请求逻辑 ----------------
        let mut request = self.client
            .post(url)
            .timeout(timeout)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(json_data.to_string());

        if let Some(token_str) = token {
            request = request.header("Authorization", token_str);
        }

        let resp = request.send().await;
        match resp {
            Ok(r) => {
                let status = r.status();
                let text = r.text()
                    .await
                    .map_err(|e| format!("Failed to read response: {}", e))?;

                if status.is_success() || status.is_client_error() {
                    Ok(PostDataWithIpResponse {
                        body: text,
                        domain_ips,
                    })
                } else {
                    Err(format!("POST failed {}: {}", status, text))
                }
            }
            Err(e) => Err(format!("Request failed: {}", e)),
        }
    }
    /// 上传文件（multipart/form-data），附带 hash 字段
    /// 对应 C++ 的 PostDataFile(uploaddraw, zip_file, hash)
    pub async fn post_file_async(
        &self,
        url: &str,
        file_path: &str,
        hash: &str,
        timeout: Duration,
        token: Option<&str>,
    ) -> Result<String, String> {
        use reqwest::multipart;

        let file_name = std::path::Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("sample.zip");

        // 在 blocking 线程中读取文件（zip 文件通常不大）
        let file_path_owned = file_path.to_string();
        let file_bytes = tokio::task::spawn_blocking(move || {
            std::fs::read(&file_path_owned)
        }).await
            .map_err(|e| format!("spawn_blocking error: {}", e))?
            .map_err(|e| format!("Cannot read file {}: {}", file_path, e))?;

        let part = multipart::Part::bytes(file_bytes)
            .file_name(file_name.to_string())
            .mime_str("application/zip")
            .map_err(|e| format!("Invalid MIME: {}", e))?;

        let form = multipart::Form::new()
            .text("hash", hash.to_string())
            .part("file", part);

        let mut request = self
            .client
            .post(url)
            .multipart(form)
            .timeout(timeout);

        if let Some(token_str) = token {
            request = request.header("Authorization", token_str);
        }

        let response = request.send().await;
        match response {
            Ok(r) => {
                let status = r.status();
                let text = r.text().await
                    .map_err(|e| format!("Failed to read response: {}", e))?;
                if status.is_success() {
                    Ok(text)
                } else {
                    Err(format!("File upload failed {}: {}", status, text))
                }
            }
            Err(e) => Err(format!("Failed to upload file: {}", e)),
        }
    }

    pub fn get_base_url(&self) -> Option<&str> {
        self.base_url.as_deref()
    }
}

