use std::sync::Arc;
use tonic::{Request, Response, Status};

use grpc_gateway::outreach_detect::{
    outreach_detect_service_server::OutreachDetectService, OutreachDetectRule, OutreachRules,
};
use grpc_gateway::common::SimpleResponse;
use crate::data_hub::{require_offline, AgentDataHub};

pub struct OutreachDetectServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl OutreachDetectService for OutreachDetectServiceImpl {
    async fn get_outreach_rules(
        &self,
        _: Request<grpc_gateway::common::Empty>,
    ) -> Result<Response<OutreachRules>, Status> {
        let rules: Vec<OutreachDetectRule> = self
            .data_hub
            .get_outreach_rules()
            .into_iter()
            .map(|r| OutreachDetectRule {
                addr: r.addr,
                method: r.method,
                r#type: r.r#type,
            })
            .collect();
        Ok(Response::new(OutreachRules { rules }))
    }

    async fn update_outreach_rules(
        &self,
        request: Request<OutreachRules>,
    ) -> Result<Response<SimpleResponse>, Status> {
        require_offline()?;
        let rules = request.into_inner().rules;
        let items: Vec<task::net_reach_rule::OutreachDetectRule> = rules
            .into_iter()
            .map(|r| task::net_reach_rule::OutreachDetectRule {
                addr: r.addr,
                method: r.method,
                r#type: r.r#type,
            })
            .collect();
        self.data_hub
            .update_outreach_rules(items)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(SimpleResponse {
            success: true,
            message: "外联检测规则已更新".into(),
        }))
    }
}
