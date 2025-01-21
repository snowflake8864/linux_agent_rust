use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Error};
use std::path::Path;
use uuid::Uuid;
use md5::{Md5, Digest};  // 从 hashes 库中导入 Md5 和 Digest
use hex;

pub fn ensure_and_get_mgs_guid(file_path: &str) -> Result<String, Error> {

 // 检查文件是否存在
    if !Path::new(file_path).exists() {
        // 生成 UUID
        let message_uuid = Uuid::new_v4().to_string();

        // 打开文件并写入 UUID
        let mut ofile = OpenOptions::new().create(true).write(true).open(file_path)?;
        ofile.write_all(message_uuid.as_bytes())?;
        ofile.write_all(b"\n")?;
    }


    // 计算文件的 MD5 校验和
    let mut file = File::open(file_path)?;
    let mut file_contents = Vec::new();
    file.read_to_end(&mut file_contents)?;

    // 创建 Md5 哈希生成器
    let mut hasher = Md5::new();
    hasher.update(&file_contents);  // 更新哈希计算器
    let result = hasher.finalize();  // 获取哈希结果

    // 将 MD5 哈希值转换为十六进制字符串并返回
    Ok(hex::encode(result))
}

