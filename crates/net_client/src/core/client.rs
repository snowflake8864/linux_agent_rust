use reqwest::{Client, Response, Proxy};
use std::time::Duration;
use serde::{Deserialize};
use std::env;

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


impl NetClient {
     pub fn new(base_url: Option<String>, disable_ssl: bool) -> Result<Self, String> {
        let mut client_builder = Client::builder()
            .timeout(Duration::from_secs(10)); // 设置请求超时时间

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
                } else {
                    Err(format!("POST request failed with status: {} - {}", status_code, response_text))
                }
            }
            Err(e) => Err(format!("Failed to send POST request: {}", e)),
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


    pub fn get_base_url(&self) -> Option<&str> {
        self.base_url.as_deref()
    }
}

