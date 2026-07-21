use std::sync::Arc;
use tonic::{Request, Response, Status};

use grpc_gateway::common::SimpleResponse;
use grpc_gateway::protection_mode::{
    process_defense_service_server::ProcessDefenseService,
    peripheral_defense_service_server::PeripheralDefenseService,
    DefenseMode, ProcessDefenseMode, PeripheralDefenseMode,
};
use crate::data_hub::{require_offline, AgentDataHub};

// ========================= ProcessDefenseService =========================

pub struct ProcessDefenseServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl ProcessDefenseService for ProcessDefenseServiceImpl {
    async fn get_process_defense_mode(
        &self,
        _: Request<grpc_gateway::common::Empty>,
    ) -> Result<Response<ProcessDefenseMode>, Status> {
        let cfg = self.data_hub.get_config();
        let mode = match (cfg.proc_switch, cfg.proc_protect) {
            (false, false) => DefenseMode::Off,
            (true, false) => DefenseMode::Monitor,
            (_, true) => DefenseMode::Protect,
        };
        Ok(Response::new(ProcessDefenseMode { mode: mode.into() }))
    }

    async fn update_process_defense_mode(
        &self,
        req: Request<ProcessDefenseMode>,
    ) -> Result<Response<SimpleResponse>, Status> {
        require_offline()?;
        let mode = req.into_inner().mode();
        let (proc_switch, proc_protect) = match mode {
            DefenseMode::Off => (false, false),
            DefenseMode::Monitor => (true, false),
            DefenseMode::Protect => (true, true),
        };

        self.data_hub.update_config_fields_protection("proc_switch", proc_switch, "proc_protect", proc_protect)
            .map_err(|e| Status::internal(e))?;

        Ok(Response::new(SimpleResponse {
            success: true,
            message: format!("进程防护模式已设置为: {:?}", mode),
        }))
    }
}

// ========================= PeripheralDefenseService =========================

pub struct PeripheralDefenseServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl PeripheralDefenseService for PeripheralDefenseServiceImpl {
    async fn get_peripheral_defense_mode(
        &self,
        _: Request<grpc_gateway::common::Empty>,
    ) -> Result<Response<PeripheralDefenseMode>, Status> {
        let cfg = self.data_hub.get_config();
        let mode = match (cfg.usb_switch, cfg.usb_protect) {
            (false, false) => DefenseMode::Off,
            (true, false) => DefenseMode::Monitor,
            (_, true) => DefenseMode::Protect,
        };
        Ok(Response::new(PeripheralDefenseMode { mode: mode.into() }))
    }

    async fn update_peripheral_defense_mode(
        &self,
        req: Request<PeripheralDefenseMode>,
    ) -> Result<Response<SimpleResponse>, Status> {
        require_offline()?;
        let mode = req.into_inner().mode();
        let (usb_switch, usb_protect) = match mode {
            DefenseMode::Off => (false, false),
            DefenseMode::Monitor => (true, false),
            DefenseMode::Protect => (true, true),
        };

        self.data_hub.update_config_fields_protection("usb_switch", usb_switch, "usb_protect", usb_protect)
            .map_err(|e| Status::internal(e))?;

        Ok(Response::new(SimpleResponse {
            success: true,
            message: format!("外设防护模式已设置为: {:?}", mode),
        }))
    }
}
