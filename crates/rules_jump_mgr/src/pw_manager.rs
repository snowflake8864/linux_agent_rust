// src/pw_manager.rs
use crate::PutPwJumpInfo;
use crate::utils::{run_cmd_capture, run_cmd_status};
use logging::{log_info,log_error};

/// 管理密码变更：备份原始 shadow 行 (getent shadow user),
/// 使用 chpasswd 修改密码（需要 root），失败则用 usermod -p <hash> 恢复原始 hash。
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

    pub async fn do_pw_jump_async(&self, user: &str, newpw: &str, info: &mut PutPwJumpInfo) -> Result<(), String> {
        log_info!("Starting pw jump for user {}", user);

        // 1. 备份 shadow
        let orig_hash_opt = self.backup_shadow(user).await.map_err(|e| {
            log_error!("backup_shadow failed: {}", e);
            e
        })?;

        log_info!("1--------Starting pw jump for user {}", user);
        // 2. 尝试设置新密码
        if let Err(e) = self.set_password_plain(user, newpw).await {
            log_error!("set_password_plain failed: {}", e);
            // 回滚：尝试恢复原有 hash
            if let Some(h) = orig_hash_opt.as_deref() {
                let _ = self.restore_shadow_hash(user, h).await;
            }
            info.status = 2;
            info.reason = format!("set_password failed: {}", e);
            return Err(info.reason.clone());
        }

        log_info!("2--------Starting pw jump for user {}", user);
        // 3. 可选：校验用户能否登录或其他检查（此处只填 info）
        info.user = user.to_string();
        info.pw = newpw.to_string();
        info.status = 1;
        info.reason = "password changed".to_string();
        Ok(())
    }
}

