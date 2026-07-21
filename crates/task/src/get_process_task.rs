use std::fs::read_dir;
use std::time::Duration;
use process_mgr::get_md5_global;
use net_client::core::NetClient;
use serde::Serialize;
use serde_json::{json, to_string};
use logging::{log_info,log_error};
#[derive(Serialize)]
struct LinuxDirProc {
    dir: String,
    hash: String,
    introduce: String,
    copyright: String,
}

const DIRS: &[&str] = &[
    "/bin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/usr/lib/systemd/",
];

fn build_linux_dir_json(vec_info: &Vec<LinuxDirProc>) -> String {
    // 把数组 vec_info 转成 JSON 字符串
    let list_str = to_string(vec_info).unwrap(); // 结果是字符串形式的数组，如 "[{...},{...}]"
    
    // 外层对象，把字符串作为 "list" 字段的值
    let json_obj = json!({
        "list": list_str
    });

    json_obj.to_string()
}
pub async fn process_all_dirs(
    net_client: NetClient,
        url: &str,
        token: Option<&str> 
) -> Result<(), String> {

    let mut vec_info: Vec<LinuxDirProc> = Vec::new();
    for &path in DIRS {
        let entries = read_dir(path).map_err(|e| format!("打开目录失败 {}: {}", path, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("读取目录项失败: {}", e))?;
            let path_buf = entry.path();

            if path_buf.is_dir() || path_buf.is_symlink() {
                continue;
            }

            let path_str = match path_buf.to_str() {
                Some(s) => s,
                None => continue,
            };

            let md5 = match get_md5_global(path_str) {
                Ok(m) => m,
                Err(e) => {
                    log_error!("计算 MD5 失败 {}: {}", path_str, e);
                    continue;
                }
            };

            let item = LinuxDirProc {
                dir: path_str.to_string(),
                hash: md5,
                introduce: "linux".to_string(),
                copyright: "linux_gnu".to_string(),
            };

            vec_info.push(item);

            if vec_info.len() >= 200 {
                let json_str = build_linux_dir_json(&vec_info);
                //log_info!("准备上传进程数据, 数量: {}, 数据前200字符: {}", vec_info.len(), &json_str[..json_str.len().min(200)]);
                match net_client.post_data_async(&url, &json_str, Duration::from_secs(10), token).await {
                    Ok(response) => log_info!("服务器响应: {}", response),
                    Err(err) => log_error!("发送指标失败: {}", err),
                }
                vec_info.clear();
            }
        }
    }

    if !vec_info.is_empty() {
        let json_str = build_linux_dir_json(&vec_info);
        //log_info!("准备上传进程数据(最后一批), 数量: {}, 数据前200字符: {}", vec_info.len(), &json_str[..json_str.len().min(200)]);
        match net_client.post_data_async(&url, &json_str, Duration::from_secs(10), token).await {
            Ok(response) => log_info!("服务器响应: {}", response),
            Err(err) => log_error!("发送指标失败: {}", err),
        }
    }

    Ok(())
}


