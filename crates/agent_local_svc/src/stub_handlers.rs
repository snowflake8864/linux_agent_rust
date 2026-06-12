//! Service implementations that require pattern_mgr, snapman, jump managers, etc.

use std::sync::{Arc, Mutex};
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
    pub pattern_mgr: Arc<Mutex<pattern::pattern_rules_mgr::PatternRulesMgr>>,
}

#[tonic::async_trait]
impl DirPolicyService for DirPolicyServiceImpl {
    async fn get_dir_policy(&self, _: Request<grpc_gateway::common::Empty>) -> Result<Response<DirPolicy>, Status> {
        let rules = self.data_hub.get_cached_dir_policy();
        Ok(Response::new(DirPolicy { rules }))
    }

    async fn update_dir_policy(&self, req: Request<DirPolicy>) -> Result<Response<SimpleResponse>, Status> {
        require_offline()?;
        let rules = req.into_inner().rules;

        // Convert proto DirectionScanRule to POLICY_PROTECT_DIR
        let protect_dirs: Vec<pattern::pattern_rules_mgr::POLICY_PROTECT_DIR> = rules
            .iter()
            .map(|r| pattern::pattern_rules_mgr::POLICY_PROTECT_DIR {
                id: 0,
                dir: r.dir.clone(),
                protect_rw: 0,
                typ: r.typ as u8,
                is_extend: 0,
                include_file: String::new(),
                file_ext: String::new(),
                is_white: String::new(),
                white_hash: String::new(),
            })
            .collect();

        // Write to pattern_mgr (→ /proc/osec/)
        self.pattern_mgr.lock().unwrap().set_protect_dir(protect_dirs);

        // Update cache for subsequent GetDirPolicy calls
        self.data_hub.set_cached_dir_policy(rules);

        Ok(Response::new(SimpleResponse { success: true, message: "目录保护策略已更新".into() }))
    }
}

// ========================= ExtortPolicy =========================

pub struct ExtortPolicyServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
    pub pattern_mgr: Arc<Mutex<pattern::pattern_rules_mgr::PatternRulesMgr>>,
}

#[tonic::async_trait]
impl ExtortPolicyService for ExtortPolicyServiceImpl {
    async fn get_extort_policy(&self, _: Request<grpc_gateway::common::Empty>) -> Result<Response<ExtortPolicy>, Status> {
        let rules = self.data_hub.get_cached_extort_policy();
        Ok(Response::new(ExtortPolicy { rules }))
    }

    async fn update_extort_policy(&self, req: Request<ExtortPolicy>) -> Result<Response<SimpleResponse>, Status> {
        require_offline()?;
        let rules = req.into_inner().rules;

        // Convert proto ExtortProtectRule to POLICY_EXIPOR_PROTECT
        let extort_rules: Vec<pattern::pattern_rules_mgr::POLICY_EXIPOR_PROTECT> = rules
            .iter()
            .map(|r| {
                let mut map_comm = std::collections::HashMap::new();
                for (k, v) in &r.map_comm {
                    map_comm.insert(k.clone(), v.clone());
                }
                pattern::pattern_rules_mgr::POLICY_EXIPOR_PROTECT {
                    file_type: r.file_type.clone(),
                    typ: r.typ as u8,
                    map_comm,
                }
            })
            .collect();

        // Write to pattern_mgr (→ /proc/osec/)
        self.pattern_mgr.lock().unwrap().set_exiport_dir(extort_rules);

        // Update cache
        self.data_hub.set_cached_extort_policy(rules);

        Ok(Response::new(SimpleResponse { success: true, message: "勒索保护策略已更新".into() }))
    }
}

// ========================= Jump =========================

pub struct JumpServiceImpl {
    pub data_hub: Arc<AgentDataHub>,
}

#[tonic::async_trait]
impl JumpService for JumpServiceImpl {
    async fn get_jump_status(&self, _: Request<grpc_gateway::common::Empty>) -> Result<Response<JumpStatus>, Status> {
        let status = crate::data_hub::JUMP_STATUS.lock().unwrap().clone();
        Ok(Response::new(status))
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
        let id = self.data_hub.create_backup(&name).await
            .map_err(|e| Status::internal(e))?;
        Ok(Response::new(CreateBackupResponse { success: true, backup_id: id, message: "备份已创建".into() }))
    }
    async fn restore_backup(&self, req: Request<RestoreBackupRequest>) -> Result<Response<RestoreBackupResponse>, Status> {
        require_offline()?;
        let id = req.into_inner().backup_id;
        self.data_hub.restore_backup(&id).await
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
        let rules = grpc_gateway::notify::VIRTUAL_PORT_CACHE.lock().unwrap().clone();
        Ok(Response::new(VirtualPortList { rules }))
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
