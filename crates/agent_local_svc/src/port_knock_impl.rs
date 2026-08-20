use std::sync::Arc;
use tonic::{Request, Response, Status};

use grpc_gateway::port_knock::{
    port_knock_service_server::PortKnockService, PortKnockRequest, PortKnockResponse,
};
use crate::data_hub::AgentDataHub;

/// 单包敲门（SPA）中继服务：接收第三方敲门请求，转发到服务器 /v1/portknock，
/// 并把服务器响应原样透传回来。受 [GRPC] PORT_KNOCK 开关控制（默认关）。
pub struct PortKnockServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl PortKnockService for PortKnockServiceImpl {
    async fn port_knock(
        &self,
        request: Request<PortKnockRequest>,
    ) -> Result<Response<PortKnockResponse>, Status> {
        let req = request.into_inner();
        let (success, http_status, response) = self
            .data_hub
            .port_knock(&req.user_id, &req.signed_random)
            .await;
        Ok(Response::new(PortKnockResponse {
            success,
            http_status,
            response,
        }))
    }
}
