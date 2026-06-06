use std::sync::Arc;
use tonic::{Request, Response, Status};

use grpc_gateway::process_policy::{
    process_policy_service_server::ProcessPolicyService, ProcessPolicy,
};
use grpc_gateway::common::SimpleResponse;
use crate::data_hub::{require_offline, AgentDataHub};

pub struct ProcessPolicyServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl ProcessPolicyService for ProcessPolicyServiceImpl {
    async fn get_process_policy(
        &self,
        _: Request<grpc_gateway::common::Empty>,
    ) -> Result<Response<ProcessPolicy>, Status> {
        let is_white = true; // always return whitelist by default
        let hashes = self.data_hub.get_process_policy(is_white);
        Ok(Response::new(ProcessPolicy {
            hash_list: hashes,
            is_white,
        }))
    }

    async fn update_process_policy(
        &self,
        request: Request<ProcessPolicy>,
    ) -> Result<Response<SimpleResponse>, Status> {
        require_offline()?;
        let policy = request.into_inner();
        self.data_hub
            .update_process_policy(&policy.hash_list, policy.is_white)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(SimpleResponse {
            success: true,
            message: "进程策略已更新".into(),
        }))
    }
}
