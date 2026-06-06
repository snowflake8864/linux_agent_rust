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

        let mut results = Vec::new();
        for task_id in req.task_ids {
            if grpc_gateway::notify::submit_local_task(task_id) {
                results.push(TaskResult {
                    task_id,
                    success: true,
                    message: "任务已提交".into(),
                });
            } else {
                results.push(TaskResult {
                    task_id,
                    success: false,
                    message: "任务通道未就绪（Agent 未完全启动）".into(),
                });
            }
        }

        Ok(Response::new(SubmitTaskResponse {
            success: results.iter().all(|r| r.success),
            results,
        }))
    }
}
