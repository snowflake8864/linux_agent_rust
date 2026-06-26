use std::sync::Arc;
use std::collections::HashSet;
use tonic::{Request, Response, Status};
use grpc_gateway::common::Empty;
use grpc_gateway::data_query::{
    data_query_service_server::DataQueryService, ProcessFilter, ProcessInfo, ProcessList,
    PortInfo, PortList, UsbDeviceList,
    ExecutableInfo, ExecutableList, PolicyStatus,
};
use grpc_gateway::peripheral_policy::UsbDevice;
use crate::data_hub::AgentDataHub;

const DEFAULT_SCAN_DIRS: &[&str] = &[
    "/bin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/usr/lib/systemd/",
];

pub struct DataQueryServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl DataQueryService for DataQueryServiceImpl {
    async fn get_process_list(
        &self,
        request: Request<ProcessFilter>,
    ) -> Result<Response<ProcessList>, Status> {
        let filter = request.into_inner();
        let processes = self
            .data_hub
            .get_process_list()
            .map_err(|e| Status::internal(e.to_string()))?;

        let mut infos: Vec<ProcessInfo> = processes
            .into_iter()
            .map(|p| ProcessInfo {
                pid: p.pid as i32,
                name: p.name.clone(),
                exe_path: p.exe_path.clone(),
                hash: p.hash.clone(),
                cpu_usage: String::new(),
                mem_usage: format!("{} KB", p.memory_rss_kb),
                user: p.user.clone(),
            })
            .collect();

        // 默认按 pid 排序；sort_by 为空或显式传 "pid" 均走此分支
        if filter.sort_by.is_empty() || filter.sort_by == "pid" {
            infos.sort_by(|a, b| a.pid.cmp(&b.pid));
        }
        if filter.limit > 0 && (filter.limit as usize) < infos.len() {
            infos.truncate(filter.limit as usize);
        }

        Ok(Response::new(ProcessList { processes: infos }))
    }

    async fn get_port_list(&self, _: Request<Empty>) -> Result<Response<PortList>, Status> {
        let json_str =
            hostinfo::net_app::model::get_netapp_json().map_err(|e| Status::internal(e.to_string()))?;
        let ports: Vec<PortInfo> = serde_json::from_str::<Vec<serde_json::Value>>(&json_str)
            .unwrap_or_default()
            .into_iter()
            .map(|v| PortInfo {
                protocol: v["protocol"].as_str().unwrap_or("").into(),
                port: v["local_port"].as_u64().unwrap_or(0) as u32,
                process_name: v["process_path"].as_str().unwrap_or("").into(),
                pid: v["pid"].as_i64().unwrap_or(0) as i32,
            })
            .collect();
        Ok(Response::new(PortList { ports }))
    }

    async fn get_usb_device_list(
        &self,
        _: Request<Empty>,
    ) -> Result<Response<UsbDeviceList>, Status> {
        let devices: Vec<UsbDevice> = self
            .data_hub
            .get_peripheral_policy(true)
            .into_iter()
            .map(|d| UsbDevice {
                peripheral_eid: d.perpheral_eid,
                peripheral_name: d.perpheral_name,
                intro: d.intro,
                r#type: d.type_,
                allow: d.allow,
            })
            .collect();
        Ok(Response::new(UsbDeviceList { devices }))
    }

    async fn get_executable_list(
        &self,
        _: Request<Empty>,
    ) -> Result<Response<ExecutableList>, Status> {
        // 固定扫描目录，与上报服务器的 process_all_dirs 一致
        let scan_dirs: Vec<&str> = DEFAULT_SCAN_DIRS.to_vec();

        // 读取黑白名单 hash 集合，用于后续标注策略状态
        let white_set: HashSet<String> = self
            .data_hub
            .get_process_policy(true)
            .into_iter()
            .collect();
        let black_set: HashSet<String> = self
            .data_hub
            .get_process_policy(false)
            .into_iter()
            .collect();

        let mut executables: Vec<ExecutableInfo> = Vec::new();
        let mut seen_hashes: HashSet<String> = HashSet::new(); // MD5 去重集合
        let mut total_count: i32 = 0;

        for dir in scan_dirs.iter() {
            let entries = match std::fs::read_dir(dir) {
                Ok(e) => e,
                Err(_) => continue, // 目录不存在则跳过
            };
            for entry in entries.flatten() {
                let path_buf = entry.path();
                // 跳过子目录和符号链接
                if path_buf.is_dir() || path_buf.is_symlink() {
                    continue;
                }
                let path_str = match path_buf.to_str() {
                    Some(s) => s.to_string(),
                    None => continue,
                };
                // 计算 MD5
                let hash = match process_mgr::get_md5_global(&path_str) {
                    Ok(h) => h,
                    Err(_) => continue,
                };

                total_count += 1;

                // MD5 去重：同一 hash 的文件只保留第一条
                if seen_hashes.contains(&hash) {
                    continue;
                }
                seen_hashes.insert(hash.clone());

                // 标注策略状态
                let policy_status = if white_set.contains(&hash) {
                    PolicyStatus::PolicyWhitelist as i32
                } else if black_set.contains(&hash) {
                    PolicyStatus::PolicyBlacklist as i32
                } else {
                    PolicyStatus::PolicyNone as i32
                };

                executables.push(ExecutableInfo {
                    path: path_str,
                    hash,
                    policy_status,
                });
            }
        }

        let unique = executables.len() as i32;
        Ok(Response::new(ExecutableList {
            executables,
            total: total_count,
            unique,
        }))
    }
}
