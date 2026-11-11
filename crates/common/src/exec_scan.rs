//! 统一的“可执行文件”判定，供所有目录扫描入口复用。
//!
//! 注意：进程策略的最终身份是 (dev,inode) + 文件内容 MD5，这里的判定只用于
//! 启动预扫描 / 可执行文件列表，避免把非可执行文件（如无 x 权限的 ELF 库）
//! 或漏掉可执行脚本。

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
pub const SHEBANG_MAGIC: &[u8; 2] = b"#!";

/// 根据文件权限位与文件头判断是否为可执行文件（ELF 或带 shebang 的脚本）。
pub fn is_executable_magic(magic: &[u8], mode: u32) -> bool {
    mode & 0o111 != 0
        && (magic.starts_with(ELF_MAGIC) || magic.starts_with(SHEBANG_MAGIC))
}

/// 已读取完整内容时使用。
pub fn is_executable_payload(data: &[u8], mode: u32) -> bool {
    is_executable_magic(&data[..data.len().min(4)], mode)
}

/// 路径版本：跟随软链，读取文件头并检查 x 权限位。
pub fn is_executable_path(path: &Path) -> bool {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if !meta.is_file() {
        return false;
    }
    let mode = meta.permissions().mode();
    if mode & 0o111 == 0 {
        return false;
    }
    let mut f = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut magic = [0u8; 4];
    if f.read_exact(&mut magic).is_err() {
        return false;
    }
    is_executable_magic(&magic, mode)
}
