use std::sync::Arc;
use tonic::{Request, Response, Status};

use grpc_gateway::config::{
    config_service_server::ConfigService, ConfigData, ConfigResponse,
};
use crate::data_hub::{require_offline, AgentDataHub};

pub struct ConfigServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl ConfigService for ConfigServiceImpl {
    async fn get_config(
        &self,
        _: Request<grpc_gateway::common::Empty>,
    ) -> Result<Response<ConfigData>, Status> {
        let cfg = self.data_hub.get_config();
        Ok(Response::new(ConfigData {
            crontime: cfg.cron_time,
            file_switch: cfg.file_switch,
            proc_switch: cfg.proc_switch,
            extortion_protect: cfg.extortion_protect,
            extortion_switch: cfg.extortion_switch,
            file_protect: cfg.file_protect,
            self_protect_switch: cfg.self_protect_switch,
            open_port_switch: cfg.open_port_switch,
            dynamic_switch: cfg.dynamic_switch,
            proc_protect: cfg.proc_protect,
            usb_protect: cfg.usb_protect,
            usb_switch: cfg.usb_switch,
            syslog_inner_switch: cfg.syslog_inner_switch,
            syslog_outer_switch: cfg.syslog_outer_switch,
            syslog_dns_switch: cfg.syslog_dns_switch,
            internet_switch: cfg.internet_switch,
            syslog_process_switch: cfg.syslog_process_switch,
            syslog_login_switch: cfg.syslog_login_switch,
            outreach_switch: cfg.outreach_switch,
            baseline_switch: cfg.baseline_switch,
            hardware_switch: cfg.hardware_switch,
            logproto: cfg.log_proto,
            logsent: cfg.log_sent,
            debug_switch: cfg.cli_port,
            module_switch: cfg.module_switch,
            outreach_time: cfg.outreach_time,
            baseline_time: cfg.baseline_time,
            hardware_time: cfg.hardware_time,
            logipport: cfg.log_ip_port.clone().unwrap_or_default(),
        }))
    }

    async fn update_config(
        &self,
        request: Request<ConfigData>,
    ) -> Result<Response<ConfigResponse>, Status> {
        require_offline()?;
        let updates = request.into_inner();
        self.data_hub.update_config(&updates).map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ConfigResponse {
            success: true,
            message: "配置已更新".into(),
        }))
    }
}
