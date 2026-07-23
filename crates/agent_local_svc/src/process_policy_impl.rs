use std::sync::Arc;
use tonic::{Request, Response, Status};

use grpc_gateway::process_policy::{
    process_policy_service_server::ProcessPolicyService, ProcessPolicy, ProcessPolicyFilter,
};
use grpc_gateway::common::SimpleResponse;
use crate::data_hub::AgentDataHub;

pub struct ProcessPolicyServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl ProcessPolicyService for ProcessPolicyServiceImpl {
    async fn get_process_policy(
        &self,
        request: Request<ProcessPolicyFilter>,
    ) -> Result<Response<ProcessPolicy>, Status> {
        let is_white = request.into_inner().is_white;
        let hashes = self.data_hub.get_process_policy(is_white != 0);
        // 查询每个 hash 对应的文件路径（从 md5_map 获取）
        let paths: Vec<String> = hashes.iter()
            .flat_map(|h| common::backend::with_backend(|b| Ok(b.lookup_hash_paths(h))).unwrap_or_default())
            .collect();
        Ok(Response::new(ProcessPolicy {
            hash_list: hashes,
            path_list: paths,
            action: is_white,
        }))
    }

    async fn update_process_policy(
        &self,
        request: Request<ProcessPolicy>,
    ) -> Result<Response<SimpleResponse>, Status> {
        // eBPF 模式下允许在线更新进程策略（便于测试验证），不再强制离线
        let policy = request.into_inner();
        self.data_hub
            .update_process_policy(&policy.hash_list, policy.action)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(SimpleResponse {
            success: true,
            message: "进程策略已更新".into(),
        }))
    }
}
