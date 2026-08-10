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

pub fn ensure_kernel_hold() {
    if let Err(e) = check_and_hold_kernel() {
        log_warn!("Failed to ensure kernel hold: {}", e);
    }
}

fn check_and_hold_kernel() -> Result<(), String> {
    let kernel_version = get_kernel_version()?;
    log_info!("Checking kernel hold status for {}", kernel_version);

    if Path::new("/usr/bin/apt-mark").exists() || Path::new("/usr/bin/dpkg").exists() {
        hold_kernel_apt(&kernel_version)?;
    } else if Path::new("/usr/bin/yum").exists() || Path::new("/usr/bin/dnf").exists() {
        hold_kernel_yum(&kernel_version)?;
    } else {
        log_info!("No supported package manager found, skipping kernel hold");
    }

    Ok(())
}

fn hold_kernel_apt(kernel_version: &str) -> Result<(), String> {
    let image_pkg = format!("linux-image-{}", kernel_version);
    let headers_pkg = format!("linux-headers-{}", kernel_version);

    let output = Command::new("apt-mark")
        .args(["showhold", &image_pkg])
        .output()
        .map_err(|e| e.to_string())?;

    let is_held = String::from_utf8_lossy(&output.stdout).contains(&image_pkg);

    if !is_held {
        log_info!("Kernel {} is not held, attempting to hold...", kernel_version);
        
        let hold_result = Command::new("apt-mark")
            .arg("hold")
            .arg(&image_pkg)
            .output()
            .map_err(|e| e.to_string())?;

        if hold_result.status.success() {
            log_info!("✅ Kernel package {} is now held", image_pkg);
        } else {
            let stderr = String::from_utf8_lossy(&hold_result.stderr);
            log_warn!("Failed to hold {}: {}", image_pkg, stderr);
        }

        let headers_result = Command::new("apt-mark")
            .arg("hold")
            .arg(&headers_pkg)
            .output();

        if let Ok(out) = headers_result {
            if out.status.success() {
                log_info!("✅ Kernel headers {} is now held", headers_pkg);
            }
        }
    } else {
        log_info!("✅ Kernel {} is already held", kernel_version);
    }

    Ok(())
}

fn hold_kernel_yum(kernel_version: &str) -> Result<(), String> {
    let yum_conf = "/etc/yum.conf";
    
    if !Path::new(yum_conf).exists() {
        log_warn!("{} not found, skipping kernel hold", yum_conf);
        return Ok(());
    }

    let content = fs::read_to_string(yum_conf).map_err(|e| e.to_string())?;
    
    if content.contains("exclude=kernel") || content.contains("exclude=kernel*") {
        log_info!("✅ Kernel already excluded in yum.conf");
        return Ok(());
    }

    log_info!("Kernel {} not excluded in yum.conf, adding exclude=kernel*", kernel_version);
    
    let exclude_line = "\nexclude=kernel*\n";
    let new_content = if content.ends_with('\n') {
        format!("{}{}", content, exclude_line)
    } else {
        format!("{}\n{}", content, exclude_line)
    };

    fs::write(yum_conf, new_content).map_err(|e| e.to_string())?;
    log_info!("✅ Added exclude=kernel* to {}", yum_conf);

    Ok(())
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
                    let msg = "Driver already loaded and cannot be unloaded, skip kernel driver loading";
                    log_error!("{}", msg);
                    return Err(msg.to_string());
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
                        } else if failed_drivers.contains(&exact_driver_path) {
                            return Err("best driver failed to load".into());
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
    if !is_driver_loaded() {
        log_info!("osec_base driver not loaded, skip unload");
        return Ok(());
    }

    // Driver IS loaded, attempt to unload
    match do_rmmod() {
        Ok(()) => return Ok(()),
        Err(e) => {
            // rmmod 失败，大概率是引用计数不为0（EBUSY）
            log_warn!("首次 rmmod 失败: {}，尝试诊断引用计数问题", e);
        }
    }

    // ── 诊断：检查驱动引用计数 ──
    let refcnt = read_module_refcnt("osec_base");
    log_info!("osec_base refcnt = {}", refcnt);

    // ── 诊断：查找持有 /proc/osec/ 和 /sys/osec/ 引用的进程 ──
    let holders = find_osec_file_holders();
    if holders.is_empty() {
        log_info!("未发现进程持有 /proc/osec/ 或 /sys/osec/ 的文件描述符");
    } else {
        log_warn!("发现 {} 个进程持有 osec 文件引用:", holders.len());
        for (pid, paths) in &holders {
            log_warn!("  pid={} : {}", pid, paths.join(", "));
        }

        // 杀掉这些进程
        let my_pid = std::process::id();
        for (pid, _) in &holders {
            if *pid == my_pid {
                log_info!("  跳过自身 pid={}", pid);
                continue;
            }
            log_warn!("  尝试杀掉 pid={} 以释放引用", pid);
            kill_process(*pid);
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    // ── 再次检查 refcnt ──
    let refcnt_after = read_module_refcnt("osec_base");
    log_info!("处理后 osec_base refcnt = {}", refcnt_after);

    // ── 重试 rmmod ──
    match do_rmmod() {
        Ok(()) => Ok(()),
        Err(e) => {
            // 仍然失败，输出完整诊断信息
            log_error!("重试 rmmod 仍然失败: {}", e);
            log_osec_holders();
            Err(format!("rmmod osec_base failed after cleanup: {} (refcnt={})", e, read_module_refcnt("osec_base")))
        }
    }
}

/// 执行 rmmod + 二次确认，返回 Ok(()) 或 Err
fn do_rmmod() -> Result<(), String> {
    match Command::new("rmmod").arg("osec_base").status() {
        Ok(status) if status.success() => {
            // 二次确认 /proc/modules
            if is_driver_loaded() {
                Err("rmmod returned success but osec_base still in /proc/modules".to_string())
            } else {
                log_info!("Successfully unloaded existing osec_base driver");
                Ok(())
            }
        }
        Ok(status) => Err(format!("rmmod osec_base failed with exit code: {}", status)),
        Err(e) => Err(format!("rmmod execution error: {}", e)),
    }
}

/// 读取内核模块引用计数 (from /sys/module/<name>/refcnt)
fn read_module_refcnt(name: &str) -> i32 {
    let path = format!("/sys/module/{}/refcnt", name);
    match fs::read_to_string(&path) {
        Ok(s) => s.trim().parse::<i32>().unwrap_or(-1),
        Err(_) => -1,
    }
}

/// 扫描 /proc/*/fd/*，返回所有持有 /proc/osec/ 或 /sys/osec/ 文件描述符的 (pid, [path])
fn find_osec_file_holders() -> Vec<(u32, Vec<String>)> {
    let mut result: Vec<(u32, Vec<String>)> = Vec::new();
    let my_pid = std::process::id();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return result,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // 只处理数字目录 (pid)
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // 跳过自己
        if pid == my_pid {
            continue;
        }

        // 读取 /proc/<pid>/fd/ 下的所有符号链接
        let fd_dir = entry.path().join("fd");
        let fds = match fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue, // 权限不够或进程已退出
        };

        let mut matched_paths: Vec<String> = Vec::new();
        for fd_entry in fds.flatten() {
            // 读取符号链接的目标
            match fs::read_link(fd_entry.path()) {
                Ok(target) => {
                    let target_str = target.to_string_lossy().to_string();
                    if target_str.starts_with("/proc/osec") || target_str.starts_with("/sys/osec") {
                        matched_paths.push(target_str);
                    }
                }
                Err(_) => continue,
            }
        }

        if !matched_paths.is_empty() {
            result.push((pid, matched_paths));
        }
    }

    // 按 pid 排序，便于阅读
    result.sort_by_key(|(pid, _)| *pid);
    result
}

/// 杀掉指定进程 (先 SIGTERM 优雅退出，失败则 SIGKILL)
fn kill_process(pid: u32) {
    let pid_i32 = pid as i32;
    unsafe {
        if libc::kill(pid_i32, libc::SIGTERM) == 0 {
            log_info!("  已发送 SIGTERM 到 pid={}", pid);
        } else {
            // SIGTERM 失败（可能权限不够或进程不存在），尝试 SIGKILL
            let err = std::io::Error::last_os_error();
            log_warn!("  SIGTERM 到 pid={} 失败: {}，尝试 SIGKILL", pid, err);
            if libc::kill(pid_i32, libc::SIGKILL) == 0 {
                log_info!("  已发送 SIGKILL 到 pid={}", pid);
            } else {
                let err2 = std::io::Error::last_os_error();
                log_error!("  杀掉 pid={} 失败: {}", pid, err2);
            }
        }
    }
}

/// 诊断输出：打印当前持有 osec 文件引用的所有进程
fn log_osec_holders() {
    let holders = find_osec_file_holders();
    if holders.is_empty() {
        log_info!("[诊断] 无进程持有 /proc/osec/ 或 /sys/osec/ 的文件描述符");
    } else {
        log_error!("[诊断] {} 个进程仍持有 osec 文件引用:", holders.len());
        for (pid, paths) in &holders {
            // 尝试读取进程名
            let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
                .unwrap_or_else(|_| "?".to_string());
            log_error!("  pid={} comm={} : {}", pid, comm.trim(), paths.join(", "));
        }
    }
    // 同时输出 refcnt
    log_info!("[诊断] refcnt={}", read_module_refcnt("osec_base"));
}

// ── 驱动失败计数（持久化到文件，跨重启累计）──

const DRIVER_FAIL_COUNT_FILE: &str = "/opt/osec/driver_fail_count";
pub const MAX_DRIVER_FAILURES: u32 = 3;

pub fn read_driver_fail_count() -> u32 {
    match fs::read_to_string(DRIVER_FAIL_COUNT_FILE) {
        Ok(content) => content.trim().parse::<u32>().unwrap_or(0),
        Err(_) => 0,
    }
}

pub fn increment_driver_fail_count() -> u32 {
    let count = read_driver_fail_count() + 1;
    let _ = fs::write(DRIVER_FAIL_COUNT_FILE, count.to_string());
    log_warn!("Driver fail count incremented to {}", count);
    count
}

pub fn reset_driver_fail_count() {
    let _ = fs::remove_file(DRIVER_FAIL_COUNT_FILE);
    log_info!("Driver fail count reset");
}

pub fn should_skip_driver() -> bool {
    read_driver_fail_count() >= MAX_DRIVER_FAILURES
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

