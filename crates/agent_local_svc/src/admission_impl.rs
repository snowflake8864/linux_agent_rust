use std::sync::Arc;
use tonic::{Request, Response, Status};

use grpc_gateway::admission::{
    admission_service_server::AdmissionService,
    Empty, AdmissionMode, AdmissionSwitchStatus, AdmissionSwitchRequest, AdmissionSwitchResponse,
};
use crate::data_hub::{AgentDataHub, ADMISSION_MODE, ADMISSION_EFFECTIVE, ADMISSION_DETECTING, ADMISSION_NETWORK_ANOMALY};

pub struct AdmissionServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl AdmissionService for AdmissionServiceImpl {
    /// 查询准入开关状态
    async fn get_admission_switch(
        &self,
        _: Request<Empty>,
    ) -> Result<Response<AdmissionSwitchStatus>, Status> {
        let cfg = self.data_hub.get_config();
        let enabled = cfg.admission.enabled;
        let mode = ADMISSION_MODE.load(std::sync::atomic::Ordering::Relaxed);
        let effective = ADMISSION_EFFECTIVE.load(std::sync::atomic::Ordering::Relaxed);
        let detecting = ADMISSION_DETECTING.load(std::sync::atomic::Ordering::Relaxed);
        let network_anomaly = ADMISSION_NETWORK_ANOMALY.load(std::sync::atomic::Ordering::Relaxed);

        let message = if !enabled {
            "准入功能未启用".to_string()
        } else if detecting {
            "正在自动检测中".to_string()
        } else if network_anomaly {
            "网络异常，等待重试".to_string()
        } else {
            match mode {
                0 => "准入关闭".to_string(),
                1 => "准入开启".to_string(),
                2 => if effective == 1 { "自动检测(当前:准入开启)".to_string() } else { "自动检测(当前:准入关闭)".to_string() },
                _ => "未知".to_string(),
            }
        };

        // effective: OFF模式→false, ON模式→true, AUTO模式→看EFFECTIVE全局值
        let effective = match mode {
            0 => false,
            1 => true,
            2 => effective == 1,
            _ => false,
        };

        Ok(Response::new(AdmissionSwitchStatus {
            mode: mode as i32,
            effective,
            detecting,
            network_anomaly,
            message,
            enabled,
        }))
    }

    /// 设置准入模式
    async fn update_admission_switch(
        &self,
        req: Request<AdmissionSwitchRequest>,
    ) -> Result<Response<AdmissionSwitchResponse>, Status> {
        let mode = req.into_inner().mode();

        self.data_hub.update_admission_mode(mode as u8)
            .map_err(|e| Status::internal(e))?;

        Ok(Response::new(AdmissionSwitchResponse {
            success: true,
            message: format!("准入模式已设置为: {:?}", mode),
        }))
    }
}
