use std::sync::Arc;
use tonic::{Request, Response, Status};

use grpc_gateway::backend::{
    backend_service_server::BackendService, BackendModeRequest, BackendModeResponse,
    BackendModeStatus,
};
use crate::data_hub::AgentDataHub;

pub struct BackendServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl BackendService for BackendServiceImpl {
    async fn get_backend_mode(
        &self,
        _: Request<grpc_gateway::backend::Empty>,
    ) -> Result<Response<BackendModeStatus>, Status> {
        let (mode, effective, interface) = self.data_hub.get_backend_mode();
        let need_restart = mode != effective;
        Ok(Response::new(BackendModeStatus {
            mode,
            effective,
            need_restart,
            interface,
        }))
    }

    async fn update_backend_mode(
        &self,
        request: Request<BackendModeRequest>,
    ) -> Result<Response<BackendModeResponse>, Status> {
        let req = request.into_inner();
        let new_mode = req.mode.to_lowercase();
        if new_mode != "ebpf" && new_mode != "driver" {
            return Ok(Response::new(BackendModeResponse {
                success: false,
                message: format!("无效的模式: {}, 只支持 ebpf 或 driver", req.mode),
            }));
        }

        match self.data_hub.update_backend_mode(&new_mode) {
            Ok(need_restart) => {
                let msg = if need_restart {
                    format!("模式已设置为 {}, 重启后生效", new_mode)
                } else {
                    format!("模式已设置为 {}", new_mode)
                };
                Ok(Response::new(BackendModeResponse {
                    success: true,
                    message: msg,
                }))
            }
            Err(e) => Ok(Response::new(BackendModeResponse {
                success: false,
                message: e,
            })),
        }
    }
}
