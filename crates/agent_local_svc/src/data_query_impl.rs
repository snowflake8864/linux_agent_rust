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
use config::net_info::NETINFO_CONFIG;

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

        // 读取黑白名单 hash 集合，用于标注策略状态
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

        let mut infos: Vec<ProcessInfo> = processes
            .into_iter()
            .map(|p| {
                let policy_status = if white_set.contains(&p.hash) {
                    PolicyStatus::PolicyWhitelist as i32
                } else if black_set.contains(&p.hash) {
                    PolicyStatus::PolicyBlacklist as i32
                } else {
                    PolicyStatus::PolicyNone as i32
                };
                ProcessInfo {
                    pid: p.pid as i32,
                    name: p.name.clone(),
                    exe_path: p.exe_path.clone(),
                    hash: p.hash.clone(),
                    cpu_usage: String::new(),
                    mem_usage: format!("{} KB", p.memory_rss_kb),
                    user: p.user.clone(),
                    policy_status,
                }
            })
            .collect();

        // 按策略状态过滤: 0=全部, 1=白名单, 2=黑名单, 3=未知
        if filter.filter_status > 0 {
            let target = if filter.filter_status == 3 { 0 } else { filter.filter_status };
            infos.retain(|p| p.policy_status == target);
        }

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
        request: Request<ProcessFilter>,
    ) -> Result<Response<UsbDeviceList>, Status> {
        let filter = request.into_inner();

        // usb_switch 关闭时直接返回空，不扫描硬件也不查策略
        let usb_switch = NETINFO_CONFIG.lock().map(|c| c.usb_switch).unwrap_or(false);
        if !usb_switch {
            return Ok(Response::new(UsbDeviceList { devices: vec![] }));
        }

        // 从硬件扫描获取所有当前插入的 USB 设备
        let scanned = udisk::monitor::get_all_local_usb_devices();

        // 获取策略列表（白名单/黑名单），用于标记 policy_status
        let white_devices = self.data_hub.get_peripheral_policy(true);
        let black_devices = self.data_hub.get_peripheral_policy(false);

        let white_set: HashSet<String> = white_devices.iter().map(|d| d.perpheral_eid.clone()).collect();
        let black_set: HashSet<String> = black_devices.iter().map(|d| d.perpheral_eid.clone()).collect();

        // 用硬件扫描结果 + 策略设备合并，以 eid 去重
        // 策略中的设备即使已被禁用也能显示
        let mut seen: HashSet<String> = HashSet::new();
        let mut devices: Vec<UsbDevice> = Vec::new();

        // 先从硬件扫描结果构建
        for d in &scanned {
            let policy_status = if white_set.contains(&d.perpheral_eid) {
                1i32 // whitelist
            } else if black_set.contains(&d.perpheral_eid) {
                2i32 // blacklist
            } else {
                0i32 // none
            };
            devices.push(UsbDevice {
                peripheral_eid: d.perpheral_eid.clone(),
                peripheral_name: d.perpheral_name.clone(),
                intro: d.intro.clone(),
                r#type: d.type_.clone(),
                allow: d.allow,
                policy_status,
            });
            seen.insert(d.perpheral_eid.clone());
        }

        // 补上策略中有但硬件扫描不到的（如被禁用设备），policy_status 来自策略
        for d in white_devices.iter().chain(black_devices.iter()) {
            if seen.contains(&d.perpheral_eid) {
                continue;
            }
            let policy_status = if white_set.contains(&d.perpheral_eid) {
                1i32
            } else {
                2i32
            };
            devices.push(UsbDevice {
                peripheral_eid: d.perpheral_eid.clone(),
                peripheral_name: d.perpheral_name.clone(),
                intro: d.intro.clone(),
                r#type: d.type_.clone(),
                allow: d.allow,
                policy_status,
            });
        }

        // filter_status 过滤接口保持可用（0=全部, 1=白名单, 2=黑名单, 3=无策略）
        if filter.filter_status > 0 {
            let target = if filter.filter_status == 3 { 0 } else { filter.filter_status };
            devices.retain(|d| d.policy_status == target);
        }

        Ok(Response::new(UsbDeviceList { devices }))
    }

    async fn get_executable_list(
        &self,
        request: Request<ProcessFilter>,
    ) -> Result<Response<ExecutableList>, Status> {
        let filter = request.into_inner();
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

                // 按过滤条件提前筛掉不匹配的条目，减少最终结果集
                if filter.filter_status > 0 {
                    let target = if filter.filter_status == 3 { 0 } else { filter.filter_status };
                    if policy_status != target {
                        continue;
                    }
                }

                executables.push(ExecutableInfo {
                    path: path_str,
                    hash,
                    policy_status,
                });
            }
        }

        // 补充 known_executables.db 中的非标准路径条目
        if let Ok(db_entries) = local_store::known_executables::load_all() {
            for (hash, path, _db_status) in db_entries {
                // MD5 去重：标准目录扫描结果优先
                if seen_hashes.contains(&hash) {
                    continue;
                }
                seen_hashes.insert(hash.clone());

                // 从 ProcessPolicy 实时计算策略状态（不使用 DB 里的缓存值）
                let policy_status = if white_set.contains(&hash) {
                    PolicyStatus::PolicyWhitelist as i32
                } else if black_set.contains(&hash) {
                    PolicyStatus::PolicyBlacklist as i32
                } else {
                    PolicyStatus::PolicyNone as i32
                };

                if filter.filter_status > 0 {
                    let target = if filter.filter_status == 3 { 0 } else { filter.filter_status };
                    if policy_status != target {
                        continue;
                    }
                }

                executables.push(ExecutableInfo {
                    path,
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
