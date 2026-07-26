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
            crontime:              Some(cfg.cron_time),
            file_switch:           Some(cfg.file_switch),
            proc_switch:           Some(cfg.proc_switch),
            extortion_protect:     Some(cfg.extortion_protect),
            extortion_switch:      Some(cfg.extortion_switch),
            file_protect:          Some(cfg.file_protect),
            self_protect_switch:   Some(cfg.self_protect_switch),
            open_port_switch:      Some(cfg.open_port_switch),
            dynamic_switch:        Some(cfg.dynamic_switch),
            proc_protect:          Some(cfg.proc_protect),
            usb_protect:           Some(cfg.usb_protect),
            usb_switch:            Some(cfg.usb_switch),
            syslog_inner_switch:   Some(cfg.syslog_inner_switch),
            syslog_outer_switch:   Some(cfg.syslog_outer_switch),
            syslog_dns_switch:     Some(cfg.syslog_dns_switch),
            internet_switch:       Some(cfg.internet_switch),
            syslog_process_switch: Some(cfg.syslog_process_switch),
            syslog_login_switch:   Some(cfg.syslog_login_switch),
            outreach_switch:       Some(cfg.outreach_switch),
            baseline_switch:       Some(cfg.baseline_switch),
            hardware_switch:       Some(cfg.hardware_switch),
            logproto:              Some(cfg.log_proto),
            logsent:               Some(cfg.log_sent),
            debug_switch:          Some(cfg.cli_port),
            module_switch:         Some(cfg.module_switch),
            outreach_time:         Some(cfg.outreach_time),
            baseline_time:         Some(cfg.baseline_time),
            hardware_time:         Some(cfg.hardware_time),
            logipport:             Some(cfg.log_ip_port.clone().unwrap_or_default()),
            alert_push:            Some(cfg.grpc_alert_push),
        }))
    }

    async fn update_config(
        &self,
        request: Request<ConfigData>,
    ) -> Result<Response<ConfigResponse>, Status> {
        // 检查 INI 开关：ALLOW_CONFIG_WRITE_ONLINE=1 时允许在线写入
        let allow_online = {
            config::net_info::NETINFO_CONFIG.lock().unwrap().grpc_allow_config_write_online
        };
        if !allow_online {
            require_offline()?;
        }
        let updates = request.into_inner();
        self.data_hub.update_config(&updates).map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(ConfigResponse {
            success: true,
            message: "配置已更新".into(),
        }))
    }
}
