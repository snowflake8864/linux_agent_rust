use std::path::{Path, PathBuf};
use std::fs;
use std::process::Command;
use std::pin::Pin;
use std::future::Future;
use std::collections::HashSet;
use tokio::time::{interval, Duration};
use logging::{log_info, log_error, log_warn};
use common::manager::boot::BootManager;
use levenshtein::levenshtein;

pub trait LoadKernelDriver {
    fn load_kernel_driver(&mut self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>>;
}

impl LoadKernelDriver for BootManager {
    fn load_kernel_driver(&mut self) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + '_>> {
        Box::pin(async move {
            let kernel_version = get_kernel_version()?;
            log_info!("Current kernel version: {}", kernel_version);

            if is_running_in_container() {
                log_warn!("Detected container environment, skip kernel module loading");

                if is_driver_loaded() {
                    log_info!("osec_base already loaded on host kernel");
                    return Ok(String::new());
                } else {
                    log_warn!("osec_base not loaded, but container cannot load kernel module");
                    return Ok(String::new());
                }
            }

            if let Err(e) = cleanup_old_module_in_lib(&kernel_version) {
                log_error!("Warning during cleanup: {}", e);
            }

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

            let mut interval = interval(Duration::from_secs(1));
            let mut failed_drivers = HashSet::new();
            loop {
                if is_driver_loaded() {
                    /*
                    if !Path::new("/opt/osec/lib").exists() {
                        log_error!("/opt/osec/lib not found. Driver may be loaded from old system path.");
                        log_error!("Please ensure the agent is deployed correctly under /opt/osec/");
                        log_error!("Exiting to avoid conflicts.");
                        std::process::exit(1);
                    }
                    */
                    log_error!("Exiting to avoid conflicts,restart process");
                    std::process::exit(1);
                    /*
                    //log_info!("Driver already loaded and /opt/osec/lib exists, skipping");
                    if let Ok(driver_name) = find_only_driver_in_opt_osec() {
                        return Ok(driver_name);
                    } else {
                        return Ok(String::new());
                    }
                    */
                }
                match try_load_driver_with_cache(&kernel_version, &mut failed_drivers).await {
                    Ok(driver_name) => {
                        log_info!("Driver loaded successfully: {}", driver_name);
                        if let Err(e) = cleanup_unused_drivers(&driver_name) {
                            log_warn!("Failed to cleanup unused drivers: {}", e);
                        }
                        return Ok(driver_name);
                    }
                    Err(e) => {
                        log_error!("Driver loading failed: {}", e);
                        let exact_driver_path = Path::new("/opt/osec/").join(format!("osec_base.ko-{}", kernel_version));
                        if exact_driver_path.exists() && !failed_drivers.contains(&exact_driver_path) {
                            failed_drivers.insert(exact_driver_path);
                        } else if failed_drivers.len() >= drivers.len() {
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

fn cleanup_old_module_in_lib(kernel_version: &str) -> Result<(), String> {
    let old_path = format!("/lib/modules/{}/kernel/drivers/osec_base.ko", kernel_version);
    if Path::new(&old_path).exists() {
        match fs::remove_file(&old_path) {
            Ok(()) => log_info!("Cleaned up old module file: {}", old_path),
            Err(e) => log_error!("Failed to remove old module file {}: {}", old_path, e),
        }
    }
    Ok(())
}

fn cleanup_unused_drivers(except_driver: &str) -> Result<(), String> {
    let opt_dir = Path::new("/opt/osec/");
    for entry in fs::read_dir(opt_dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
            if name.starts_with("osec_base.ko-") && !name.ends_with(except_driver) {
                if let Err(e) = fs::remove_file(&path) {
                    log_warn!("Failed to remove unused driver {}: {}", path.display(), e);
                } else {
                    log_info!("Removed unused driver {}", path.display());
                }
            }
        }
    }
    Ok(())
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
    match Command::new("rmmod").arg("osec_base").status() {
        Ok(status) if status.success() => log_info!("Successfully unloaded existing osec_base driver"),
        Ok(_) => log_info!("rmmod failed, maybe driver not loaded"),
        Err(e) => return Err(format!("rmmod execution error: {}", e)),
    }
    Ok(())
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

fn setup_module_structure(src_path: &Path, kernel_version: &str) -> Result<(), String> {
    let mod_dir = Path::new("/opt/osec/lib/modules").join(kernel_version);
    fs::create_dir_all(&mod_dir).map_err(|e| e.to_string())?;

    let dst_ko = mod_dir.join("osec_base.ko");
    fs::copy(src_path, &dst_ko).map_err(|e| e.to_string())?;

    fs::write(mod_dir.join("modules.order"), "").map_err(|e| e.to_string())?;
    fs::write(mod_dir.join("modules.builtin"), "").map_err(|e| e.to_string())?;

    let status = Command::new("depmod")
        .arg("-b")
        .arg("/opt/osec")
        .arg("-a")
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        log_error!("depmod -b /opt/osec failed");
    }
    Ok(())
}

fn get_and_disable_selinux() -> Option<String> {
    let getenforce_path = if Path::new("/usr/sbin/getenforce").exists() {
        "/usr/sbin/getenforce"
    } else if Path::new("/sbin/getenforce").exists() {
        "/sbin/getenforce"
    } else {
        log_info!("getenforce not found, assuming SELinux not present");
        return None;
    };

    let output = Command::new(getenforce_path).output().ok()?;
    let enforce_state = String::from_utf8_lossy(&output.stdout).trim().to_string();
    log_info!("Current SELinux state: {}", enforce_state);

    if enforce_state.eq_ignore_ascii_case("Enforcing") {
        let setenforce_path = if Path::new("/usr/sbin/setenforce").exists() {
            "/usr/sbin/setenforce"
        } else if Path::new("/sbin/setenforce").exists() {
            "/sbin/setenforce"
        } else {
            log_warn!("setenforce not found, cannot disable SELinux temporarily");
            return Some(enforce_state);
        };
        let _ = Command::new(setenforce_path).arg("0").status();
        log_info!("Temporarily disabled SELinux");
    }
    Some(enforce_state)
}

fn restore_selinux(state: Option<String>) {
    let Some(st) = state else { return };
    if !st.eq_ignore_ascii_case("Enforcing") { return; }

    let setenforce_path = if Path::new("/usr/sbin/setenforce").exists() {
        "/usr/sbin/setenforce"
    } else if Path::new("/sbin/setenforce").exists() {
        "/sbin/setenforce"
    } else { return; };

    let _ = Command::new(setenforce_path).arg("1").status();
    log_info!("Restored SELinux enforcing mode");
}

fn is_module_loaded(module_name: &str) -> bool {
    if let Ok(content) = fs::read_to_string("/proc/modules") {
        content.lines().any(|line| line.starts_with(module_name))
    } else { false }
}

pub async fn try_load_driver_with_cache(
    kernel_version: &str,
    failed_drivers: &mut HashSet<PathBuf>,
) -> Result<String, String> {
    if is_running_in_container() {
        return Err("Kernel module loading disabled in container".into());
    }

    if !has_modprobe() {
        return Err("modprobe not found on system".into());
    }
    let original_selinux_state = get_and_disable_selinux();

    // 复制 /proc/kallsyms
    let data_dir = Path::new("/opt/osec/Data");
    let _ = fs::create_dir_all(data_dir);
    let _ = fs::copy("/proc/kallsyms", data_dir.join("kallsyms"));

    // 确保 uio 模块加载
    if !is_module_loaded("uio") {
        let _ = Command::new("modprobe").arg("uio").status();
    }

    // 选择驱动
    let driver_path = {
        let exact_driver = Path::new("/opt/osec/").join(format!("osec_base.ko-{}", kernel_version));
        if exact_driver.exists() { exact_driver } 
        else { find_best_driver_excluding(kernel_version, failed_drivers)? }
    };

    setup_module_structure(&driver_path, kernel_version)?;

    // 尝试 modprobe
    let _ = Command::new("modprobe").arg("osec_base").status();

    if is_module_loaded("osec_base") {
        restore_selinux(original_selinux_state);
        return Ok(driver_path.file_name().and_then(|f| f.to_str()).unwrap_or("").trim_start_matches("osec_base.ko-").to_string());
    }

    // 尝试 modprobe -d /opt/osec
    let _ = Command::new("modprobe").arg("-d").arg("/opt/osec").arg("osec_base").status();
    tokio::time::sleep(Duration::from_millis(500)).await;

    if is_module_loaded("osec_base") {
        restore_selinux(original_selinux_state);
        return Ok(driver_path.file_name().and_then(|f| f.to_str()).unwrap_or("").trim_start_matches("osec_base.ko-").to_string());
    }

    // 尝试 insmod
    let ko_path = Path::new("/opt/osec/lib/modules").join(kernel_version).join("osec_base.ko");
    if !ko_path.exists() {
        restore_selinux(original_selinux_state);
        return Err(format!("osec_base.ko not found at {}", ko_path.display()));
    }

    let output = Command::new("insmod").arg(&ko_path).output().map_err(|e| e.to_string())?;
    if output.status.success() {
        log_info!("insmod 成功加载 {}", ko_path.display());
    } else {
        let err = format!("insmod 失败: {}", String::from_utf8_lossy(&output.stderr));
        failed_drivers.insert(driver_path);
        restore_selinux(original_selinux_state);
        return Err(err);
    }

    restore_selinux(original_selinux_state);
    Ok(driver_path.file_name().and_then(|f| f.to_str()).unwrap_or("").trim_start_matches("osec_base.ko-").to_string())
}

fn is_driver_loaded_from_system_path(kernel_version: &str) -> bool {
    let system_ko_path = format!("/lib/modules/{}/kernel/drivers/osec_base.ko", kernel_version);
    Path::new(&system_ko_path).exists()
}

fn is_running_in_container() -> bool {
    // Docker / containerd / k8s 都能命中
    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        return cgroup.contains("docker")
            || cgroup.contains("kubepods")
            || cgroup.contains("containerd");
    }
    false
}

fn has_modprobe() -> bool {
    Path::new("/sbin/modprobe").exists()
        || Path::new("/bin/modprobe").exists()
        || Path::new("/usr/sbin/modprobe").exists()
}

fn can_load_kernel_module() -> bool {
    if is_running_in_container() {
        return false;
    }
    has_modprobe()
}

