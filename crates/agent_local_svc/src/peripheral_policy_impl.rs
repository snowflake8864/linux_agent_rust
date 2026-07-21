use std::sync::Arc;
use tonic::{Request, Response, Status};
use grpc_gateway::common::SimpleResponse;
use grpc_gateway::peripheral_policy::{
    peripheral_policy_service_server::PeripheralPolicyService, PeripheralPolicy,
    PeripheralPolicyFilter, UsbDevice,
};
use crate::data_hub::{require_offline, AgentDataHub};

pub struct PeripheralPolicyServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl PeripheralPolicyService for PeripheralPolicyServiceImpl {
    async fn get_peripheral_policy(
        &self,
        request: Request<PeripheralPolicyFilter>,
    ) -> Result<Response<PeripheralPolicy>, Status> {
        let is_white = request.into_inner().is_white;
        let devices: Vec<UsbDevice> = self
            .data_hub
            .get_peripheral_policy(is_white != 0)
            .into_iter()
            .map(|d| UsbDevice {
                peripheral_eid: d.perpheral_eid,
                peripheral_name: d.perpheral_name,
                intro: d.intro,
                r#type: d.type_,
                allow: d.allow,
                policy_status: if is_white != 0 { 1 } else { 2 },
            })
            .collect();
        Ok(Response::new(PeripheralPolicy { devices, action: is_white }))
    }

    async fn update_peripheral_policy(
        &self,
        request: Request<PeripheralPolicy>,
    ) -> Result<Response<SimpleResponse>, Status> {
        require_offline()?;
        let policy = request.into_inner();
        let usb_infos: Vec<udisk::device::UsbInfo> = policy
            .devices
            .into_iter()
            .map(|d| udisk::device::UsbInfo {
                perpheral_eid: d.peripheral_eid,
                perpheral_name: d.peripheral_name,
                intro: d.intro,
                type_: d.r#type,
                allow: d.allow,
            })
            .collect();
        self.data_hub
            .update_peripheral_policy(&usb_infos, policy.action)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(SimpleResponse { success: true, message: "外设策略已更新".into() }))
    }
}
