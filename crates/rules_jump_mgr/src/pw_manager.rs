// src/pw_manager.rs
use crate::PutPwJumpInfo;
use crate::utils::{run_cmd_capture, run_cmd_status};
use logging::{log_info,log_error};

pub struct PasswordManager;

impl PasswordManager {
    pub fn new() -> Self { Self }

    /// 备份/user 的 shadow 行（返回 shadow hash 字符串）
    async fn backup_shadow(&self, user: &str) -> Result<Option<String>, String> {
        match run_cmd_capture("getent", &["shadow", user]).await {
            Ok(s) => {
                // s 格式: "user:HASH:..."
                let parts: Vec<&str> = s.splitn(2, ':').collect();
                if parts.len() >= 2 {
                    // 第二段以 HASH 开始
                    let rest = s.split(':').collect::<Vec<&str>>();
                    if rest.len() >= 2 {
                        return Ok(Some(rest[1].to_string()));
                    }
                }
                Ok(None)
            }
            Err(e) => Err(format!("getent shadow failed: {}", e)),
        }
    }

    /// 用明文密码设置用户密码（调用 chpasswd）
    async fn set_password_plain(&self, user: &str, newpw: &str) -> Result<(), String> {
        // echo "user:newpw" | chpasswd
        let cmd = format!("echo \"{}:{}\" | chpasswd", user, newpw);
        run_cmd_status("bash", &["-c", &cmd]).await.map_err(|e| format!("chpasswd failed: {}", e))
    }

    /// 用 shadow hash 恢复密码（usermod -p '<hash>' user）
    async fn restore_shadow_hash(&self, user: &str, hash: &str) -> Result<(), String> {
        // usermod -p '<hash>' user
        run_cmd_status("usermod", &["-p", hash, user]).await.map_err(|e| format!("usermod -p failed: {}", e))
    }

    pub async fn do_pw_jump_async(
        &self,
        user: &str,
        newpw: &str,
        info: &mut PutPwJumpInfo,
    ) -> Result<(), String> {
        let real_user = if user.trim().is_empty() {
            if let Ok(u) = std::env::var("USER") {
                u
            } else {
                let output = tokio::process::Command::new("whoami")
                    .output()
                    .await
                    .map_err(|e| format!("failed to run whoami: {}", e))?;
                let u = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if u.is_empty() {
                    return Err("cannot determine current user".to_string());
                }
                u
            }
        } else {
            user.to_string()
        };

        info.user = real_user.clone(); 
        log_info!("Starting pw jump for user {}", real_user);

        // 1. 备份 shadow
        let orig_hash_opt = self.backup_shadow(&real_user).await.map_err(|e| {
            log_error!("backup_shadow failed: {}", e);
            e
        })?;

        log_info!("1--------Starting pw jump for user {}", real_user);
        if let Err(e) = self.set_password_plain(&real_user, newpw).await {
            log_error!("set_password_plain failed: {}", e);
            if let Some(h) = orig_hash_opt.as_deref() {
                let _ = self.restore_shadow_hash(&real_user, h).await;
            }
            info.status = 2;
            info.reason = format!("set_password failed: {}", e);
            return Err(info.reason.clone());
        }

        log_info!("2--------Starting pw jump for user {}", real_user);

        info.user = real_user;
        info.pw = newpw.to_string();
        info.status = 1;
        info.reason = "password changed".to_string();
        Ok(())
    }
}

