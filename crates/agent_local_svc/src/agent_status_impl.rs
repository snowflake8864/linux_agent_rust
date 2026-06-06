use std::sync::Arc;
use tonic::{Request, Response, Status};

use grpc_gateway::agent_status::{
    agent_status_service_server::AgentStatusService, AgentStatus, CpuMemInfo, ModuleStatus,
};
use crate::data_hub::{AgentDataHub, AGENT_MODE, AgentMode};

pub struct AgentStatusServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl AgentStatusService for AgentStatusServiceImpl {
    async fn get_agent_status(
        &self,
        _: Request<grpc_gateway::common::Empty>,
    ) -> Result<Response<AgentStatus>, Status> {
        let is_online = AGENT_MODE.load(std::sync::atomic::Ordering::Relaxed) == AgentMode::Online as u8;
        let cfg = self.data_hub.get_config();

        let modules = vec![
            ModuleStatus { name: "file_protect".into(), enabled: cfg.file_switch, status: if cfg.file_switch { "运行中".into() } else { "未启用".into() } },
            ModuleStatus { name: "proc_protect".into(), enabled: cfg.proc_switch, status: if cfg.proc_switch { "运行中".into() } else { "未启用".into() } },
            ModuleStatus { name: "usb_protect".into(), enabled: cfg.usb_switch, status: if cfg.usb_switch { "运行中".into() } else { "未启用".into() } },
            ModuleStatus { name: "extortion_protect".into(), enabled: cfg.extortion_switch, status: if cfg.extortion_switch { "运行中".into() } else { "未启用".into() } },
            ModuleStatus { name: "self_protect".into(), enabled: cfg.self_protect_switch, status: if cfg.self_protect_switch { "运行中".into() } else { "未启用".into() } },
        ];

        Ok(Response::new(AgentStatus {
            is_online,
            agent_version: cfg.ver,
            os_info: cfg.os,
            protection_days: 0,
            cpu_mem: Some(CpuMemInfo {
                cpu_usage: String::new(),
                mem_usage: String::new(),
                disk_usage: String::new(),
            }),
            modules,
            device_uid: cfg.dev_uid,
            host_name: cfg.host_name,
        }))
    }
}
