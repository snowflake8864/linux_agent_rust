//! Stub implementations for gRPC services that require deeper integration
//! with pattern_mgr (via BootManager), snapman, jump managers, etc.
//! These return "not yet implemented" for now.

use std::sync::Arc;
use tonic::{Request, Response, Status};

use grpc_gateway::common::SimpleResponse;
use grpc_gateway::dir_policy::{
    dir_policy_service_server::DirPolicyService, DirPolicy,
};
use grpc_gateway::extort_policy::{
    extort_policy_service_server::ExtortPolicyService, ExtortPolicy,
};
use grpc_gateway::jump::{
    jump_service_server::JumpService, JumpStatus, IpJumpRequest, IpJumpResponse,
    PwJumpRequest, PwJumpResponse,
};
use grpc_gateway::backup::{
    backup_service_server::BackupService, BackupList, CreateBackupRequest,
    CreateBackupResponse, RestoreBackupRequest, RestoreBackupResponse,
};
use grpc_gateway::trust_dir::{
    trust_dir_service_server::TrustDirService, TrustDirList,
};
use grpc_gateway::virtual_port::{
    virtual_port_service_server::VirtualPortService, VirtualPortList,
};
use crate::data_hub::{require_offline, AgentDataHub};

// ========================= DirPolicy =========================

pub struct DirPolicyServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl DirPolicyService for DirPolicyServiceImpl {
    async fn get_dir_policy(&self, _: Request<grpc_gateway::common::Empty>) -> Result<Response<DirPolicy>, Status> {
        Ok(Response::new(DirPolicy { rules: vec![] }))
    }
    async fn update_dir_policy(&self, _: Request<DirPolicy>) -> Result<Response<SimpleResponse>, Status> {
        require_offline()?;
        Err(Status::unimplemented("dir_policy requires pattern_mgr (BootManager)"))
    }
}

// ========================= ExtortPolicy =========================

pub struct ExtortPolicyServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl ExtortPolicyService for ExtortPolicyServiceImpl {
    async fn get_extort_policy(&self, _: Request<grpc_gateway::common::Empty>) -> Result<Response<ExtortPolicy>, Status> {
        Ok(Response::new(ExtortPolicy { rules: vec![] }))
    }
    async fn update_extort_policy(&self, _: Request<ExtortPolicy>) -> Result<Response<SimpleResponse>, Status> {
        require_offline()?;
        Err(Status::unimplemented("extort_policy requires pattern_mgr (BootManager)"))
    }
}

// ========================= Jump =========================

pub struct JumpServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl JumpService for JumpServiceImpl {
    async fn get_jump_status(&self, _: Request<grpc_gateway::common::Empty>) -> Result<Response<JumpStatus>, Status> {
        // TODO: track last jump time in a global
        Ok(Response::new(JumpStatus::default()))
    }

    async fn execute_ip_jump(&self, req: Request<IpJumpRequest>) -> Result<Response<IpJumpResponse>, Status> {
        require_offline()?;
        let r = req.into_inner();
        let (source_ip, target_ip, gateway, status, reason) = self
            .data_hub
            .execute_ip_jump(&r.gateway, &r.source_ip, &r.target_ip, r.mode)
            .await
            .map_err(|e| Status::internal(e))?;
        Ok(Response::new(IpJumpResponse {
            success: status == 1,
            source_ip,
            target_ip,
            gateway,
            agent_ip: String::new(),
            status: status as u32,
            reason,
        }))
    }

    async fn execute_pw_jump(&self, req: Request<PwJumpRequest>) -> Result<Response<PwJumpResponse>, Status> {
        require_offline()?;
        let r = req.into_inner();
        let (status, reason) = self
            .data_hub
            .execute_pw_jump(&r.new_password)
            .await
            .map_err(|e| Status::internal(e))?;
        Ok(Response::new(PwJumpResponse {
            success: status == 1,
            status: status as u32,
            reason,
        }))
    }
}

// ========================= Backup =========================

pub struct BackupServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl BackupService for BackupServiceImpl {
    async fn get_backup_list(&self, _: Request<grpc_gateway::common::Empty>) -> Result<Response<BackupList>, Status> {
        Ok(Response::new(BackupList { backups: vec![] }))
    }
    async fn create_backup(&self, req: Request<CreateBackupRequest>) -> Result<Response<CreateBackupResponse>, Status> {
        require_offline()?;
        let name = req.into_inner().name;
        let id = self.data_hub.create_backup(&name)
            .map_err(|e| Status::internal(e))?;
        Ok(Response::new(CreateBackupResponse { success: true, backup_id: id, message: "备份已创建".into() }))
    }
    async fn restore_backup(&self, req: Request<RestoreBackupRequest>) -> Result<Response<RestoreBackupResponse>, Status> {
        require_offline()?;
        let id = req.into_inner().backup_id;
        self.data_hub.restore_backup(&id)
            .map_err(|e| Status::internal(e))?;
        Ok(Response::new(RestoreBackupResponse { success: true, message: "还原已执行".into() }))
    }
}

// ========================= TrustDir =========================

pub struct TrustDirServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl TrustDirService for TrustDirServiceImpl {
    async fn get_trust_dir(&self, _: Request<grpc_gateway::common::Empty>) -> Result<Response<TrustDirList>, Status> {
        let dirs = self.data_hub.get_trust_dir();
        let items = dirs.into_iter().map(|d| grpc_gateway::trust_dir::GlobalTrustDir {
            dir: d.dir, r#type: d.typ as u32, is_extend: d.is_extend as u32,
        }).collect();
        Ok(Response::new(TrustDirList { dirs: items }))
    }
    async fn update_trust_dir(&self, req: Request<TrustDirList>) -> Result<Response<SimpleResponse>, Status> {
        require_offline()?;
        let dirs: Vec<pattern::GlobalTrustDir> = req.into_inner().dirs.into_iter().map(|d| pattern::GlobalTrustDir {
            dir: d.dir, typ: d.r#type as u8, is_extend: d.is_extend as u8,
        }).collect();
        self.data_hub.update_trust_dir(dirs).map_err(|e| Status::internal(e))?;
        Ok(Response::new(SimpleResponse { success: true, message: "信任目录已更新".into() }))
    }
}

// ========================= VirtualPort =========================

pub struct VirtualPortServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl VirtualPortService for VirtualPortServiceImpl {
    async fn get_virtual_port(&self, _: Request<grpc_gateway::common::Empty>) -> Result<Response<VirtualPortList>, Status> {
        Ok(Response::new(VirtualPortList { rules: vec![] }))
    }
    async fn update_virtual_port(&self, req: Request<VirtualPortList>) -> Result<Response<SimpleResponse>, Status> {
        require_offline()?;
        let rules: Vec<task::virtual_port_rule::VirtualPortRule> = req.into_inner().rules.into_iter().map(|r| {
            task::virtual_port_rule::VirtualPortRule {
                alarm_level: r.alarm_level,
                dest_ip: r.dest_ip,
                dest_port: r.dest_port,
                dest_port_type: r.dest_port_type,
                id: r.id,
                protocol: r.protocol,
                source_ip: r.source_ip,
                source_port_range: (r.source_port_start as u16, r.source_port_end as u16),
                r#type: r.r#type,
            }
        }).collect();
        self.data_hub.update_virtual_port(rules).await
            .map_err(|e| Status::internal(e))?;
        Ok(Response::new(SimpleResponse { success: true, message: "虚拟端口规则已更新".into() }))
    }
}
