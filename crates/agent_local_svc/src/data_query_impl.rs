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
        _request: Request<ProcessFilter>,
    ) -> Result<Response<UsbDeviceList>, Status> {
        // Get combined devices from both whitelist and blacklist with policy_status
        let combined = self.data_hub.get_combined_peripheral_policy();

        let devices: Vec<UsbDevice> = combined
            .into_iter()
            .map(|(d, status)| UsbDevice {
                peripheral_eid: d.perpheral_eid,
                peripheral_name: d.perpheral_name,
                intro: d.intro,
                r#type: d.type_,
                allow: d.allow,
                policy_status: status as i32,
            })
            .collect();

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
