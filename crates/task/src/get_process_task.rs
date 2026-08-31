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

/// 容器 overlay rootfs 下需要扫描的子目录（与 scan_container_overlays 保持一致）
const OVERLAY_SUBDIRS: &[&str] = &["bin", "sbin", "usr/bin", "usr/sbin", "usr/local/bin"];

fn build_linux_dir_json(vec_info: &Vec<LinuxDirProc>) -> String {
    // 服务器 AllPut.list 字段是 string 类型，需要先序列化为 JSON 字符串再作为值
    let list_str = to_string(vec_info).unwrap();
    let json_obj = json!({
        "list": list_str
    });
    json_obj.to_string()
}

/// 扫描单个目录下的可执行文件，计算 MD5 并追加到 vec_info
fn scan_one_dir(path: &str, vec_info: &mut Vec<LinuxDirProc>) {
    let entries = match read_dir(path) {
        Ok(e) => e,
        Err(e) => {
            log_error!("打开目录失败 {}: {}", path, e);
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                log_error!("读取目录项失败: {}", e);
                continue;
            }
        };
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

        vec_info.push(LinuxDirProc {
            dir: path_str.to_string(),
            hash: md5,
            introduce: "linux".to_string(),
            copyright: "linux_gnu".to_string(),
        });
    }
}

/// 批量上报 vec_info 到服务器，满 200 条或调用时 flush
async fn flush_to_server(vec_info: &mut Vec<LinuxDirProc>, net_client: &NetClient, url: &str, token: Option<&str>) {
    if vec_info.is_empty() {
        return;
    }
    let json_str = build_linux_dir_json(vec_info);
    match net_client.post_data_async(url, &json_str, Duration::from_secs(10), token).await {
        Ok(response) => log_info!("服务器响应: {}", response),
        Err(err) => log_error!("发送指标失败: {}", err),
    }
    vec_info.clear();
}

pub async fn process_all_dirs(
    net_client: NetClient,
        url: &str,
        token: Option<&str> 
) -> Result<(), String> {

    let mut vec_info: Vec<LinuxDirProc> = Vec::new();

    // 1. 扫描宿主机标准目录
    for &path in DIRS {
        scan_one_dir(path, &mut vec_info);
        if vec_info.len() >= 200 {
            flush_to_server(&mut vec_info, &net_client, url, token).await;
        }
    }

    // 2. eBPF 模式：扫描容器 overlay rootfs 下的可执行文件
    if let Some(overlay_roots) = common::backend::with_backend(|b| Ok(b.get_executable_overlay_roots())).ok() {
        if !overlay_roots.is_empty() {
            log_info!("task_global_proc: 发现 {} 个容器 overlay rootfs，开始扫描", overlay_roots.len());
            for root in &overlay_roots {
                for subdir in OVERLAY_SUBDIRS {
                    let scan_dir = format!("{}/{}", root, subdir);
                    if !std::path::Path::new(&scan_dir).is_dir() {
                        continue;
                    }
                    scan_one_dir(&scan_dir, &mut vec_info);
                    if vec_info.len() >= 200 {
                        flush_to_server(&mut vec_info, &net_client, url, token).await;
                    }
                }
            }
            // 扫完后触发 overlay 补扫，把容器可执行文件写入 eBPF 的 md5_map，
            // 后续容器进程 exec 能直接命中 BPF 缓存
            let _ = common::backend::with_backend(|b| { b.trigger_overlay_rescan(); Ok(()) });
        }
    }

    // flush 剩余
    flush_to_server(&mut vec_info, &net_client, url, token).await;

    Ok(())
}


