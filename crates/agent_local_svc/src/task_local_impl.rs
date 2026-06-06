use std::sync::Arc;
use tonic::{Request, Response, Status};

use grpc_gateway::task_local::{
    local_task_service_server::LocalTaskService, SubmitTaskRequest, SubmitTaskResponse, TaskResult,
};
use crate::data_hub::{require_offline, AgentDataHub};

pub struct LocalTaskServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl LocalTaskService for LocalTaskServiceImpl {
    async fn submit_task(
        &self,
        request: Request<SubmitTaskRequest>,
    ) -> Result<Response<SubmitTaskResponse>, Status> {
        require_offline()?;
        let req = request.into_inner();
        let results: Vec<TaskResult> = req
            .task_ids
            .iter()
            .map(|&id| TaskResult {
                task_id: id,
                success: false,
                message: format!("Task #{} — not yet wired to task_fetcher", id),
            })
            .collect();
        // TODO: wire to TaskFetcher::handle_task()
        Ok(Response::new(SubmitTaskResponse {
            success: results.iter().all(|r| r.success),
            results,
        }))
    }
}
