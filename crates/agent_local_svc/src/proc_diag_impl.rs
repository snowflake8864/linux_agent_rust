use tonic::{Request, Response, Status};

use grpc_gateway::proc_diag::{
    proc_diag_service_server::ProcDiagService, ProcessRuleQuery, ProcessRuleResult,
};

/// 进程规则诊断服务：查询进程（路径或 dev/inode）是否命中 eBPF proc_rules 白/黑名单表。
/// 独立于 ProcessPolicyService，避免改动已对第三方开放的接口。
pub struct ProcDiagServiceImpl;

#[tonic::async_trait]
impl ProcDiagService for ProcDiagServiceImpl {
    async fn query_process_rule(
        &self,
        request: Request<ProcessRuleQuery>,
    ) -> Result<Response<ProcessRuleResult>, Status> {
        let q = request.into_inner();
        let r = common::backend::with_backend(|b| b.query_process_rule(&q.path, q.dev, q.inode))
            .map_err(|e| Status::internal(e))?;
        Ok(Response::new(ProcessRuleResult {
            found: r.found,
            action: r.action,
            mode: r.mode,
            dev: r.dev,
            inode: r.inode,
            resolved_path: r.resolved_path,
            message: r.message,
        }))
    }
}
