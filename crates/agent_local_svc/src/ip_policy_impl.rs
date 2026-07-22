use std::sync::Arc;
use tonic::{Request, Response, Status};

use grpc_gateway::ip_policy::{
    ip_policy_service_server::IpPolicyService, IpBlockPolicy, IpPolicyItem,
};
use grpc_gateway::common::SimpleResponse;
use crate::data_hub::{require_offline, AgentDataHub};

pub struct IpPolicyServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl IpPolicyService for IpPolicyServiceImpl {
    async fn get_ip_block_policy(
        &self,
        _: Request<grpc_gateway::common::Empty>,
    ) -> Result<Response<IpBlockPolicy>, Status> {
        let items: Vec<IpPolicyItem> = self
            .data_hub
            .get_ip_block_policy()
            .await
            .into_iter()
            .map(|p| IpPolicyItem {
                ip: p.ip,
                direction: p.direction,
                duration: p.duration,
                is_ipv6: p.is_ipv6,
            })
            .collect();
        Ok(Response::new(IpBlockPolicy { items }))
    }

    async fn update_ip_block_policy(
        &self,
        request: Request<IpBlockPolicy>,
    ) -> Result<Response<SimpleResponse>, Status> {
        require_offline()?;
        let policy = request.into_inner();
        let items: Vec<netblock::ip_policy::IpPolicy> = policy
            .items
            .into_iter()
            .map(|i| netblock::ip_policy::IpPolicy {
                ip: i.ip,
                direction: i.direction,
                duration: i.duration,
                is_ipv6: i.is_ipv6,
                source: 2,
            })
            .collect();
        self.data_hub
            .update_ip_block_policy(&items)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(SimpleResponse {
            success: true,
            message: "IP阻断策略已更新".into(),
        }))
    }

    async fn get_ip_black_policy(
        &self,
        _: Request<grpc_gateway::common::Empty>,
    ) -> Result<Response<IpBlockPolicy>, Status> {
        let items: Vec<IpPolicyItem> = self
            .data_hub
            .get_ip_black_policy()
            .await
            .into_iter()
            .map(|p| IpPolicyItem {
                ip: p.ip,
                direction: p.direction,
                duration: p.duration,
                is_ipv6: p.is_ipv6,
            })
            .collect();
        Ok(Response::new(IpBlockPolicy { items }))
    }

    async fn update_ip_black_policy(
        &self,
        request: Request<IpBlockPolicy>,
    ) -> Result<Response<SimpleResponse>, Status> {
        require_offline()?;
        let policy = request.into_inner();
        let items: Vec<netblock::ip_policy::IpPolicy> = policy
            .items
            .into_iter()
            .map(|i| netblock::ip_policy::IpPolicy {
                ip: i.ip,
                direction: i.direction,
                duration: i.duration,
                is_ipv6: i.is_ipv6,
                source: 2,
            })
            .collect();
        self.data_hub
            .update_ip_block_policy(&items)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(SimpleResponse {
            success: true,
            message: "IP黑名单已更新".into(),
        }))
    }
}
