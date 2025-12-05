//crates/snapman/src/lib.rs
use chrono::{DateTime, Local};
use tokio::process::Command;
use std::error::Error;
use std::str;
use anyhow::Result;
use logging::log_info;

#[derive(Debug)]
pub struct LvInfo {
    pub name: String,
    pub vg: String,
    pub origin: Option<String>,
}

// 获取卷组名称
pub async fn get_vg_name() -> Result<String, Box<dyn Error>> {
    let output = Command::new("vgs")
        .arg("--noheadings")
        .arg("-o")
        .arg("vg_name")
        .output()
        .await?;
    let vg_name = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if vg_name.is_empty() {
        Err("未找到卷组名称".into())
    } else {
        Ok(vg_name)
    }
}

// 列出逻辑卷
pub async fn list_lvs() -> Result<Vec<LvInfo>, Box<dyn Error>> {
    let output = Command::new("lvs")
        .arg("--noheadings")
        .arg("-o")
        .arg("lv_name,vg_name,origin")
        .output()
        .await?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lvs = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            lvs.push(LvInfo {
                name: parts[0].to_string(),
                vg: parts[1].to_string(),
                origin: if parts.len() >= 3 && !parts[2].is_empty() { Some(parts[2].to_string()) } else { None },
            });
        }
    }
    Ok(lvs)
}

pub async fn create_snapshot(name: &str, size: &str) -> Result<String, String> {
    // 获取卷组名
    let vg = get_vg_name().await.map_err(|e| e.to_string())?;
    let lvs = list_lvs().await.map_err(|e| e.to_string())?;
    let mut created_any = false;
    let mut created_size = String::new();

    for lv in lvs.iter() {
        // 跳过 swap 和已有快照
        if lv.name.contains("swap") || lv.name.contains("_snap") {
            continue;
        }

        let snap_name = format!("{}_snap_{}", lv.name, name);

        /*
        let lvs_cmd_str = format!(
            "lvs --noheadings -o lv_size {}/{}",
            lv.vg, lv.name
        );
        log_info!("🔍 调试命令（获取 LV 大小）: {}", lvs_cmd_str);
        */
        // 通过 lvs 获取原 LV 的大小
        let size_output = Command::new("lvs")
            .arg("--noheadings")
            .arg("-o")
            .arg("lv_size")
            .arg(format!("{}/{}", lv.vg, lv.name))
            .output()
            .await
            .map_err(|e| format!("获取卷大小失败: {}", e))?;

        let size_str = String::from_utf8_lossy(&size_output.stdout).trim().to_string();
        let lv_size_gb = parse_size_to_gb(&size_str)?;

        // 自动计算大小（若用户未指定）
        let size_final = if size.is_empty() {
            let snap_size_gb = ((lv_size_gb as f64) * 0.1).ceil() as u64;
            format!("{}G", snap_size_gb)
        } else {
            size.to_string()
        };

        // 检查空间是否足够
        check_free_space(&vg, &size_final).await?;

        log_info!("🧩 创建快照: {} -> {} (大小 {})", lv.name, snap_name, size_final);

        // 执行 lvcreate 创建快照
        let status = Command::new("lvcreate")
            .arg("-L")
            .arg(&size_final)
            .arg("-s")
            .arg(format!("/dev/{}/{}", lv.vg, lv.name))
            .arg("-n")
            .arg(&snap_name)
            .status()
            .await
            .map_err(|e| e.to_string())?;

        if status.success() {
            log_info!("✅ 成功创建快照: {}", snap_name);
            created_any = true;
            created_size = size_final.clone();
        } else {
            log_info!("❌ 创建快照失败: {}", snap_name);
        }
    }

    if !created_any {
        return Err("未找到可用于快照的根卷 (排除 swap 与 _snap_)".to_string());
    }

    Ok(created_size)
}

async fn check_free_space(vg: &str, required_size: &str) -> Result<(), String> {
    let required_gb = parse_size_to_gb(required_size)?;

    let vg_output = Command::new("vgs")
        .arg("--noheadings")
        .arg("-o")
        .arg("vg_name,vg_free")
        .output()
        .await
        .map_err(|e| e.to_string())?;
    let output_str = String::from_utf8_lossy(&vg_output.stdout);

    for line in output_str.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == vg {
            let free_str = parts[1];
            let free_gb = parse_size_to_gb(free_str)?;
            if free_gb < required_gb {
                return Err(format!(
                    "卷组 {} 剩余空间不足: 需要 {}G，当前可用 {}G",
                    vg, required_gb, free_gb
                ));
            } else {
                log_info!("VG {} 剩余空间充足 ({}G 可用)", vg, free_gb);
                return Ok(());
            }
        }
    }

    Err(format!("未找到卷组 {}", vg))
}
/*
/// 解析 LVM 输出的大小字符串（如 "36.12g" -> 36）
fn parse_size_to_gb(size_str: &str) -> Result<u64, String> {
    log_info!("1==={}",size_str);
    let s = size_str.trim().to_lowercase();
    log_info!("333==={}",s);
    if s.ends_with('g') {
        let num = s.trim_end_matches('g').parse::<f64>().map_err(|_| "解析失败")?;
        Ok(num.ceil() as u64)
    } else if s.ends_with('m') {
        let num = s.trim_end_matches('m').parse::<f64>().map_err(|_| "解析失败")?;
        Ok(((num / 1024.0).ceil()) as u64)
    } else if s.ends_with('t') {
        let num = s.trim_end_matches('t').parse::<f64>().map_err(|_| "解析失败")?;
        Ok((num * 1024.0).ceil() as u64)
    } else {
        Err(format!("无法解析大小: {}", size_str))
    }
}
*/
fn parse_size_to_gb(size_str: &str) -> Result<u64, String> {
    // 移除开头的非数值字符（如 <, <=, [, ( 等）
    let cleaned: String = size_str
        .trim()
        .chars()
        .skip_while(|c| !c.is_ascii_digit() && *c != '.')
        .collect();

    if cleaned.is_empty() {
        return Err(format!("清理后大小为空: {}", size_str));
    }

    let s = cleaned.to_lowercase();
    if s.ends_with('g') {
        let num_str = s.trim_end_matches('g');
        let num = num_str.parse::<f64>().map_err(|_| format!("无法解析 GB 数值: '{}'", num_str))?;
        Ok(num.ceil() as u64)
    } else if s.ends_with('m') {
        let num_str = s.trim_end_matches('m');
        let num = num_str.parse::<f64>().map_err(|_| format!("无法解析 MB 数值: '{}'", num_str))?;
        Ok(((num / 1024.0).ceil()) as u64)
    } else if s.ends_with('t') {
        let num_str = s.trim_end_matches('t');
        let num = num_str.parse::<f64>().map_err(|_| format!("无法解析 TB 数值: '{}'", num_str))?;
        Ok((num * 1024.0).ceil() as u64)
    } else {
        Err(format!("无法解析大小（未知单位）: '{}'", size_str))
    }
}

pub async fn list_snapshots() -> Result<(), Box<dyn std::error::Error>> {

    let output = Command::new("lvs")
        .args(&[
            "--noheadings",
            "-o",
            "lv_name,vg_name,lv_size,origin,lv_time",
        ])
        .output()
        .await?;

    let s = String::from_utf8_lossy(&output.stdout);

    log_info!("📋 当前快照列表:");
    log_info!(
        "{:<20} {:<8} {:<8} {:<12} {}",
        "LV", "VG", "Size", "Origin", "Created"
    );

    for line in s.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        let lv_name = parts[0];
        let vg_name = parts[1];
        let lv_size = parts[2];
        let origin = parts[3];
        let time_str = parts[4..].join(" ");

        // 只显示名称里包含 _snap_ 的 LV，排除 swap
        if !lv_name.contains("_snap_") || lv_name.contains("swap") {
            continue;
        }

        let dt: DateTime<Local> = DateTime::parse_from_str(&time_str, "%Y-%m-%d %H:%M:%S %z")
            .map(|dt| dt.with_timezone(&Local))
            .unwrap_or_else(|_| Local::now());

        log_info!(
            "{:<20} {:<8} {:<8} {:<12} {}",
            lv_name,
            vg_name,
            lv_size,
            origin,
            dt.format("%Y-%m-%d %H:%M:%S %z")
        );
    }

    Ok(())
}



// 删除快照
pub async fn clean_snapshot(name: &str) -> Result<(), String> {
    let lvs = list_lvs().await.map_err(|e| e.to_string())?;
    let mut found = false;

    for lv in lvs.iter() {
        if lv.name.contains(name) && lv.name.contains("_snap") {
            let status = Command::new("lvremove")
                .arg("-f")
                .arg(format!("/dev/{}/{}", lv.vg, lv.name))
                .status()
                .await
                .map_err(|e| e.to_string())?;
            if status.success() {
                log_info!("✅ 删除快照: {}", lv.name);
                found = true;
            }
        }
    }

    if !found {
        return Err(format!("未找到匹配的快照: {}", name));
    }
    Ok(())
}

// 删除所有快照
pub async fn clean_all_snapshots() -> Result<(), String> {
    let lvs = list_lvs().await.map_err(|e| e.to_string())?;
    for lv in lvs.iter() {
        if lv.name.contains("_snap") {
            let _ = Command::new("lvremove")
                .arg("-f")
                .arg(format!("/dev/{}/{}", lv.vg, lv.name))
                .status()
                .await;
            log_info!("✅ 删除快照: {}", lv.name);
        }
    }
    Ok(())
}

// 还原快照（根据后缀匹配）
pub async fn restore_snapshot(suffix: &str) -> Result<(), String> {
    let lvs = list_lvs().await.map_err(|e| e.to_string())?;
    let mut found = false;

    for lv in lvs.iter() {
        if lv.name.ends_with(suffix) && lv.name.contains("_snap") {
            log_info!("♻️  合并快照以还原: {}", lv.name);
            let status = Command::new("lvconvert")
                .arg("--merge")
                .arg(format!("/dev/{}/{}", lv.vg, lv.name))
                .status()
                .await
                .map_err(|e| e.to_string())?;

            if status.success() {
                log_info!("⚠️  原始卷正在使用中，合并将在系统重启后自动完成。");
                found = true;
            } else {
                log_info!("❌ 合并快照失败: {}", lv.name);
            }
        }
    }

    if !found {
        return Err(format!("未找到匹配的快照: {}", suffix));
    }

    Ok(())
}

fn parse_size(size: &str) -> Result<f64, String> {
    let size = size.trim().to_uppercase();
    if size.ends_with("G") {
        let n: f64 = size.trim_end_matches("G").parse().map_err(|_| "无效大小")?;
        Ok(n * 1024.0)
    } else if size.ends_with("M") {
        let n: f64 = size.trim_end_matches("M").parse().map_err(|_| "无效大小")?;
        Ok(n)
    } else {
        Err("仅支持 M/G 单位".to_string())
    }
}
