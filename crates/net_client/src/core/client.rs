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
    pub base_url: String,
}

impl NetClient {
    // 初始化客户端（异步版本）
    /*
    pub fn new(base_url: String, disable_ssl: bool) -> Result<Self, String> {
        let client_builder = Client::builder()
            .timeout(Duration::from_secs(10)); // 设置请求超时时间

        // 如果禁用 SSL 证书验证，则设置相应的选项
        let client = if disable_ssl {
            client_builder
                .danger_accept_invalid_certs(true) // 禁用 SSL 证书验证
                .build()
                .map_err(|e| format!("Failed to create client with SSL disabled: {}", e))?
        } else {
            client_builder
                .build()
                .map_err(|e| format!("Failed to create client: {}", e))?
        };

        Ok(NetClient {
                client,
                base_url,
        })
    }
    */
     pub fn new(base_url: String, disable_ssl: bool) -> Result<Self, String> {
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
}

