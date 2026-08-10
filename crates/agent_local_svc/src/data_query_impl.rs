use std::collections::HashSet;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use grpc_gateway::common::Empty;
use grpc_gateway::data_query::{
    data_query_service_server::DataQueryService, ProcessFilter, ProcessInfo, ProcessList,
    PortInfo, PortList, UsbDeviceList, ExecutableInfo, ExecutableList,
    PolicyStatus,
};
use grpc_gateway::peripheral_policy::UsbDevice;
use crate::data_hub::AgentDataHub;
use config::net_info::NETINFO_CONFIG;

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

        // Fetch current policy sets to compute policy_status
        let white_hashes: std::collections::HashSet<String> =
            self.data_hub.get_process_policy(true).into_iter().collect();
        let black_hashes: std::collections::HashSet<String> =
            self.data_hub.get_process_policy(false).into_iter().collect();

        let mut infos: Vec<ProcessInfo> = processes
            .into_iter()
            .map(|p| {
                let policy_status = if black_hashes.contains(&p.hash) {
                    PolicyStatus::PolicyBlacklist
                } else if white_hashes.contains(&p.hash) {
                    PolicyStatus::PolicyWhitelist
                } else {
                    PolicyStatus::PolicyNone
                };
                ProcessInfo {
                    pid: p.pid as i32,
                    name: p.name.clone(),
                    exe_path: p.exe_path.clone(),
                    hash: p.hash.clone(),
                    cpu_usage: String::new(),
                    mem_usage: format!("{} KB", p.memory_rss_kb),
                    user: p.user.clone(),
                    policy_status: policy_status as i32,
                }
            })
            .collect();

        // Apply filter_status: 0=all, 1=whitelist, 2=blacklist, 3=unknown
        if filter.filter_status > 0 && filter.filter_status <= 3 {
            let target = filter.filter_status;
            infos.retain(|p| p.policy_status == target);
        }

        if filter.sort_by == "pid" {
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
                PolicyStatus::PolicyWhitelist as i32
            } else if black_set.contains(&d.perpheral_eid) {
                PolicyStatus::PolicyBlacklist as i32
            } else {
                PolicyStatus::PolicyNone as i32
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
                PolicyStatus::PolicyWhitelist as i32
            } else {
                PolicyStatus::PolicyBlacklist as i32
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
        _request: Request<ProcessFilter>,
    ) -> Result<Response<ExecutableList>, Status> {
        let processes = self
            .data_hub
            .get_process_list()
            .map_err(|e| Status::internal(e.to_string()))?;

        let white_hashes: std::collections::HashSet<String> =
            self.data_hub.get_process_policy(true).into_iter().collect();
        let black_hashes: std::collections::HashSet<String> =
            self.data_hub.get_process_policy(false).into_iter().collect();

        let mut executables: Vec<ExecutableInfo> = processes
            .into_iter()
            .map(|p| {
                let policy_status = if black_hashes.contains(&p.hash) {
                    PolicyStatus::PolicyBlacklist
                } else if white_hashes.contains(&p.hash) {
                    PolicyStatus::PolicyWhitelist
                } else {
                    PolicyStatus::PolicyNone
                };
                ExecutableInfo {
                    path: p.exe_path,
                    hash: p.hash,
                    policy_status: policy_status as i32,
                }
            })
            .collect();

        // Deduplicate by path (keep first occurrence)
        let mut seen = std::collections::HashSet::new();
        executables.retain(|e| seen.insert(e.path.clone()));

        Ok(Response::new(ExecutableList { executables, total: 0, unique: 0 }))
    }
}
