use std::path::{Path, PathBuf};
use std::fs;
use std::process::Command;
use std::pin::Pin;
use std::future::Future;
use std::collections::HashSet;
use tokio::time::{interval, Duration};
use tokio::sync::mpsc;
use logging::{log_info, log_error};
use common::manager::boot::BootManager;
use levenshtein::levenshtein;

pub trait LoadKernelDriver {
    fn load_kernel_driver(&mut self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>;
}

impl LoadKernelDriver for BootManager {
    fn load_kernel_driver(&mut self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {
//            let _ = unload_driver();
            // Ensure /opt/osec/Data/ exists
            let data_dir = PathBuf::from("/opt/osec/Data");
            if !data_dir.exists() {
                fs::create_dir_all(&data_dir)
                    .map_err(|e| format!("Failed to create directory /opt/osec/Data: {}", e))?;
            }

            // Copy /proc/kallsyms to /opt/osec/Data/kallsyms
            let kallsyms_src = PathBuf::from("/proc/kallsyms");
            let kallsyms_dst = data_dir.join("kallsyms");
            if kallsyms_src.exists() {
                fs::copy(&kallsyms_src, &kallsyms_dst)
                    .map_err(|e| format!("Failed to copy /proc/kallsyms to {:?}: {}", kallsyms_dst, e))?;
                log_info!("Copied /proc/kallsyms to {:?}", kallsyms_dst);
            } else {
                log_error!("/proc/kallsyms not found, skipping copy");
            }
            let mut interval = interval(Duration::from_secs(1));
            let mut failed_drivers = HashSet::new();

            let kernel_version = get_kernel_version()?;
            log_info!("Current kernel version: {}", kernel_version);

            let kernel_prefix = extract_kernel_prefix(&kernel_version)
                .ok_or_else(|| "Failed to extract kernel major version".to_string())?;

            let drivers: Vec<_> = fs::read_dir("/opt/osec/")
                .map_err(|e| e.to_string())?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|s| s.to_str())
                        .map(|s| s.starts_with("osec_base.ko-") && s["osec_base.ko-".len()..].starts_with(&kernel_prefix))
                        .unwrap_or(false)
                })
                .collect();

            if drivers.is_empty() {
                log_error!("No compatible drivers found with matching kernel prefix: {}", kernel_prefix);
                return Err("No matching major version drivers found".into());
            }

            loop {
                if is_driver_loaded() {
                    log_info!("Driver already loaded, skipping");
                    if let Ok(driver_name) = find_only_driver_in_opt_osec() {
                        return Ok(driver_name);
                    } else {
                        return Ok(String::new());
                    }
                }

                match try_load_driver_with_cache(&mut failed_drivers).await {
                    Ok(driver_name) => {
                        log_info!("Driver loaded successfully: {}", driver_name);
                        return Ok(driver_name);
                    }
                    Err(e) => {
                        log_error!("Driver loading failed: {}", e);
                        if failed_drivers.len() >= drivers.len() {
                            log_error!("All compatible drivers failed, stopping retry");
                            return Err("All available drivers failed to load".into());
                        }
                    }
                }

                interval.tick().await;
            }
        })
    }
}

fn has_any_driver() -> bool {
    if let Ok(entries) = fs::read_dir("/opt/osec/") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("osec_base.ko-") {
                    return true;
                }
            }
        }
    }
    false
}

fn is_driver_loaded() -> bool {
    if let Ok(content) = fs::read_to_string("/proc/modules") {
        content.lines().any(|line| line.starts_with("osec_base "))
    } else {
        false
    }
}

fn find_only_driver_in_opt_osec() -> Result<String, String> {
    let opt_dir = Path::new("/opt/osec/");
    let entries = fs::read_dir(opt_dir).map_err(|e| e.to_string())?;

    for entry in entries.flatten() {
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            if name.starts_with("osec_base.ko-") {
                return Ok(name.trim_start_matches("osec_base.ko-").to_string());
            }
        }
    }

    Err("No loaded driver file found".into())
}

pub fn unload_driver() -> Result<(), String> {
    let rmmod_status = Command::new("rmmod").arg("osec_base").status();
    match rmmod_status {
        Ok(status) if status.success() => {
            log_info!("Successfully unloaded existing osec_base driver");
            Ok(())
        }
        Ok(_) => {
            log_info!("rmmod failed, maybe driver not loaded");
            Ok(())
        }
        Err(e) => Err(format!("rmmod execution error: {}", e))
    }
}

fn get_kernel_version() -> Result<String, String> {
    let output = Command::new("uname").arg("-r").output().map_err(|e| e.to_string())?;
    let version = String::from_utf8(output.stdout).map_err(|e| e.to_string())?;
    Ok(version.trim().to_string())
}

fn extract_kernel_prefix(version: &str) -> Option<String> {
    version.split('-').next().map(|s| s.to_string())
}

fn find_best_driver_excluding(kernel_version: &str, failed: &HashSet<PathBuf>) -> Result<PathBuf, String> {
    let base_dir = Path::new("/opt/osec/");
    let entries = fs::read_dir(base_dir).map_err(|e| e.to_string())?;

    let kernel_prefix = extract_kernel_prefix(kernel_version)
        .ok_or_else(|| "Failed to extract kernel major version".to_string())?;

    let mut best: Option<(PathBuf, usize)> = None;

    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();

        if failed.contains(&path) {
            continue;
        }

        if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
            if filename.starts_with("osec_base.ko-") {
                let suffix = &filename["osec_base.ko-".len()..];

                if !suffix.starts_with(&kernel_prefix) {
                    continue;
                }

                let score = if suffix == kernel_version {
                    0
                } else {
                    levenshtein(suffix, kernel_version)
                };

                if best.is_none() || score < best.as_ref().unwrap().1 {
                    best = Some((path.clone(), score));
                    if score == 0 { break; }
                }
            }
        }
    }

    best.map(|(p, _)| p).ok_or("No matching driver found".to_string())
}

fn copy_driver(src: &Path, dst: &Path) -> Result<(), String> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::copy(src, dst).map_err(|e| e.to_string())?;
    Ok(())
}

fn load_driver(_path: &Path) -> Result<(), String> {
    let depmod_status = Command::new("depmod").status().map_err(|e| e.to_string())?;
    if !depmod_status.success() {
        return Err(format!("depmod failed: {:?}", depmod_status));
    }

    let modprobe_status = Command::new("modprobe").arg("osec_base").status().map_err(|e| e.to_string())?;
    if modprobe_status.success() {
        Ok(())
    } else {
        Err(format!("modprobe failed: {:?}", modprobe_status))
    }
}

fn cleanup_other_drivers(success_path: &Path, kernel_version: &str) -> Result<(), String> {
    let success_file = success_path.file_name().and_then(|f| f.to_str()).ok_or("Invalid success path")?;
    let opt_dir = Path::new("/opt/osec/");

    let lib_dir_str = format!("/lib/modules/{}/kernel/drivers/", kernel_version);
    let lib_dir = Path::new(&lib_dir_str);

    if let Ok(entries) = fs::read_dir(opt_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if name.starts_with("osec_base.ko-") && name != success_file {
                    let _ = fs::remove_file(&path);
                    log_info!("Removed unused driver file: {:?}", path);
                }
            }
        }
    }

    if let Ok(entries) = fs::read_dir(lib_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if name.starts_with("osec_base") && name != "osec_base.ko" {
                    let _ = fs::remove_file(&path);
                    log_info!("Cleaned unrelated files in target module dir: {:?}", path);
                }
            }
        }
    }

    Ok(())
}
async fn try_load_driver_with_cache(failed_drivers: &mut HashSet<PathBuf>) -> Result<String, String> {
    let kernel_version = get_kernel_version()?;
    log_info!("Current kernel version: {}", kernel_version);

    let driver_path = find_best_driver_excluding(&kernel_version, failed_drivers)?;
    log_info!("Selected driver file: {:?}", driver_path);

    let dst_path_str = format!("/lib/modules/{}/kernel/drivers/osec_base.ko", kernel_version);
    let dst_path = Path::new(&dst_path_str);

    if let Err(e) = copy_driver(&driver_path, dst_path)
        .and_then(|_| load_driver(dst_path))
        .and_then(|_| cleanup_other_drivers(&driver_path, &kernel_version))
    {
        log_error!("Driver loading failed: {}, marking as failed", e);
        failed_drivers.insert(driver_path);
        return Err(e);
    }

    let version_suffix = driver_path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("")
        .trim_start_matches("osec_base.ko-")
        .to_string();

    Ok(version_suffix)
}
