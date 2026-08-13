use std::sync::Arc;
use tonic::{Request, Response, Status};

use grpc_gateway::common::Empty;
use grpc_gateway::policy_query::{
    policy_query_service_server::PolicyQueryService, PolicyDump,
};
use crate::data_hub::AgentDataHub;

pub struct PolicyQueryServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl PolicyQueryService for PolicyQueryServiceImpl {
    async fn get_all_policies(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<PolicyDump>, Status> {
        let all = crate::policy_file_writer::dump_all_policies();
        let json_str = serde_json::to_string_pretty(&all)
            .unwrap_or_else(|e| format!(r#"{{"error": "序列化失败: {}"}}"#, e));
        Ok(Response::new(PolicyDump { json: json_str }))
    }
}
