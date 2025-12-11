use logging::log_warn;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use tokio::fs;

// 必须加这三行！！
use std::os::unix::fs::MetadataExt;   // mode, uid, gid, ctime, mtime 全靠它
use libc::{getpwuid, getgrgid};
use std::ffi::CStr;

#[derive(Debug, Clone, Deserialize)]
pub struct DirectionScanRule {
    pub dir: String,
    pub pid: u32,
    #[serde(rename = "type")]
    pub typ: u32,
}

#[derive(Debug, Serialize)]
pub struct FileInfoUpload {
    pub dir: String,
    pub rw: String,
    pub group: String,
    pub user: String,
    pub size: String,
    pub starttime: String,
    pub updatetime: String,
    pub level: String,
    pub dirtype: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hash: String,
    #[serde(rename = "type")]
    pub file_type: u8,  // 1=目录 2=文件
    pub pid: u32,
}

// 核心：扫描单个目录（非递归）
pub async fn scan_single_dir(dir: &str, pid: u32) -> Result<Vec<FileInfoUpload>, String> {
    let path = Path::new(dir);

    if !path.is_dir() {
        log::warn!("监控目录不存在或无权限: {}", dir);
        return Ok(vec![]);
    }

    let mut entries = tokio::fs::read_dir(path)
        .await
        .map_err(|e| format!("打开目录失败 {}: {}", dir, e))?;

    let mut records = Vec::new();

    while let Some(entry) = entries.next_entry().await.ok().flatten() {
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            if name == "." || name == ".." {
                continue;
            }
        }

        let Ok(metadata) = entry.metadata().await else { continue };

        let record = FileInfoUpload {
            dir: path.to_string_lossy().into_owned(),
            rw: mode_to_string(metadata.mode()),
            user: uid_to_name(metadata.uid()).unwrap_or_else(|| metadata.uid().to_string()),
            group: gid_to_name(metadata.gid()).unwrap_or_else(|| metadata.gid().to_string()),
            size: metadata.len().to_string(),
            starttime: metadata.ctime().to_string(),
            updatetime: metadata.mtime().to_string(),
            level: "RW".to_string(),
            dirtype: path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_lowercase(),
            hash: String::new(),
            file_type: if metadata.is_dir() { 1 } else { 2 },
            pid,
        };

        records.push(record);
    }

    Ok(records)
}

// 权限转 drwxr-xr-x
fn mode_to_string(mode: u32) -> String {
    let mut s = String::with_capacity(10);
    s.push(if mode & 0o040000 != 0 { 'd' } else { '-' });

    for i in (6..=0).step_by(3) {
        let bit = (mode >> i) & 0b111;
        s.push(if bit & 0b100 != 0 { 'r' } else { '-' });
        s.push(if bit & 0b010 != 0 { 'w' } else { '-' });
        s.push(if bit & 0b001 != 0 { 'x' } else { '-' });
    }
    s
}

#[cfg(unix)]
fn uid_to_name(uid: u32) -> Option<String> {
    unsafe {
        let pwd = libc::getpwuid(uid);
        if pwd.is_null() {
            None
        } else {
            std::ffi::CStr::from_ptr((*pwd).pw_name)
                .to_str()
                .ok()
                .map(|s| s.to_string())
        }
    }
}

#[cfg(unix)]
fn gid_to_name(gid: u32) -> Option<String> {
    unsafe {
        let grp = libc::getgrgid(gid);
        if grp.is_null() {
            None
        } else {
            std::ffi::CStr::from_ptr((*grp).gr_name)
                .to_str()
                .ok()
                .map(|s| s.to_string())
        }
    }
}
