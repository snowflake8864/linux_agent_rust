use libc::{sigaction, SIGPIPE, SIG_IGN, SA_RESTART, sigemptyset};
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use online::StartOnline;
use task::{TaskService, TimerTask};
use kernel_event::{StartKernelHandler, EventHandler,send_data_to_kernel};
use kernel_module::{LoadKernelDriver, unload_driver, ensure_kernel_hold, DriverBackend};
#[cfg(feature = "ebpf")]
use ebpf_backend::{EbpfBackend, capability::EbpfCapability};
use common::backend::{SecurityBackend, NoopBackend, set_backend, init_dpi_writer};
use common::manager::boot::BootManager;
use reporter::{AuditLogInfo, AuditProcess, StartBashLog, StartAutoProcess};
use tokio::sync::mpsc;
use logging::{log_info, CustomLogger, log_error, log_warn};
use netlink::netlink::NlSockInfo;
use std::sync::Arc;
use tokio::sync::Mutex;
use config::net_info::NETINFO_CONFIG;
use grpc_gateway::agent_mode::{AgentMode, AGENT_MODE, ADMISSION_NETWORK_ANOMALY};
use udisk::{StartUsbService, StartUsbHotplugHandler};
use docker::StartDockerMonitor;
use virus_scan_grpc::StartVirusScanGrpcService;
use std::fs;
use std::path::Path;
use std::net::IpAddr;
use std::time::Duration;


const PID_FILE: &str = "/var/run/osec_backend.pid";

fn pid_is_running(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

fn ensure_single_instance() {
    if Path::new(PID_FILE).exists() {
        if let Ok(content) = fs::read_to_string(PID_FILE) {
            if let Ok(old_pid) = content.trim().parse::<u32>() {

                if pid_is_running(old_pid) {
                    eprintln!("❌ osec_backend 已在运行 (PID={})！", old_pid);
                    std::process::exit(1);
                }
            }
        }
    }

    let current_pid = std::process::id();
    if let Err(e) = fs::write(PID_FILE, current_pid.to_string()) {
        eprintln!("⚠ 无法写入 PID 文件: {}", e);
    }

    println!("✔ 单实例检查通过，当前 PID={}", current_pid);
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    ensure_single_instance(); 
    // 初始化日志
    CustomLogger::init("/opt/osec/osec_backend.conf")
        .await
        .expect("无法初始化日志");
    // 忽略 SIGPIPE 信号
    unsafe {
        let mut sa: sigaction = std::mem::zeroed();
        sa.sa_sigaction = SIG_IGN as usize;
        sa.sa_flags = SA_RESTART;
        sigemptyset(&mut sa.sa_mask);
        if sigaction(SIGPIPE, &sa, std::ptr::null_mut()) != 0 {
            panic!("sigaction failed to set SIGPIPE to ignore");
        }
    }
    log_info!("程序开始启动");

    // 卸载现有内核驱动（driver 模式才会用，ebpf 模式跳过）
    // 如果卸载失败，记录失败次数，后续可能跳过驱动加载
    match unload_driver() {
        Err(e) => {
            kernel_module::increment_driver_fail_count();
            log_error!("驱动卸载失败: {} (fail_count={})", e, kernel_module::read_driver_fail_count());
        }
        Ok(()) => {
            log_info!("驱动卸载检查完成");
        }
    }

    // 初始化 BootManager
    let init = BootManager::init().await;

    // 初始化 SQLite 数据库（受 [SQLITE_DB] 和 [DB_POLICY] 开关控制）
    local_store::init_all();

    // 启动早期同步探测服务器连通性：拿到 token 才算真正在线。
    // 在线则跳过 DB 进程策略加载（交给服务器重推），离线才加载本地表并下发。
    let online = match online::probe_online(Duration::from_secs(5)).await {
        Some(_) => { log_info!("[startup] 在线探测成功（拿到 token），跳过 DB 进程策略加载"); true }
        None => { log_info!("[startup] 在线探测失败（拿不到 token），按离线处理"); false }
    };

    // 从 DB 恢复策略到内存（仅 SQLite 开关开启时生效）
    {
        let cfg = NETINFO_CONFIG.lock().unwrap();
        let db_enabled = cfg.sqlite_db.enabled;
        let load_process = cfg.db_policy.process_policy;
        let load_peripheral = cfg.db_policy.peripheral_policy;
        let usb_protect = cfg.usb_protect;
        drop(cfg);
        log_info!("[startup] cfg: sqlite_db.enabled={} db_policy.process_policy={} db_policy.peripheral_policy={} usb_protect={} online={}",
            db_enabled, load_process, load_peripheral, usb_protect, online);
        if db_enabled {
            if load_process && !online {
                // 启动即离线：合并加载在线基线表(上次服务器策略) + 离线本地表(gRPC 策略)，
                // 延用上次在线时服务器下发的策略，不丢；在线交给服务器重推，避免与 scan 的 md5_map 锁互锁
                process_mgr::POLICY_MANAGER.lock().unwrap().load_policy_from_db_merged();
            }
            if load_peripheral {
                // 合并加载在线表 + 本地表，避免在线启动时丢失用户本地策略修改
                agent_local_svc::AgentDataHub::load_peripheral_policy_merged();
            }
        }

        // 启动时若 usb_protect 开启，物理禁用所有已加载的黑名单设备
        if usb_protect {
            let black_eids: Vec<String> = {
                let guard = udisk::list::SHARED_USB_LIST.lock().unwrap();
                guard.get_blacklist().iter().map(|d| d.perpheral_eid.clone()).collect()
            };
            if !black_eids.is_empty() {
                log_info!("[startup] usb_protect 开启，禁用 {} 个已加载黑名单设备", black_eids.len());
                udisk::monitor::handle_blacklist_update(&black_eids);
            }
        }
    }

    // 创建通信通道
    let (file_audit_log_tx, file_audit_log_rx) = mpsc::channel::<AuditLogInfo>(4096);
    reporter::set_audit_log_tx(file_audit_log_tx.clone());
    let (auto_process_tx, auto_process_rx) = mpsc::channel::<AuditProcess>(4096);
    reporter::set_auto_process_tx(auto_process_tx.clone());
    let (token_tx, token_rx) = mpsc::channel::<String>(8);
    let (host_is_offline_tx, host_is_offline_rx) = mpsc::channel::<bool>(8);

    // 捕获 eBPF 后端引用，供策略下发完成后再启动后台 MD5 扫描（避免与下发互锁）
    #[cfg(feature = "ebpf")]
    let mut ebpf_scan: Option<Arc<ebpf_backend::EbpfBackend>> = None;

    // ── 后端选择 ──
    {
        let mut cfg = NETINFO_CONFIG.lock().unwrap();
        let backend_mode = cfg.backend_mode.clone();
        let admission_enabled = cfg.admission.enabled;
        let admission_mode = cfg.admission.mode;
        let admission_switch = cfg.admission_switch;
        // .o 加载由 [EBPF] 段独立控制，服务器 SWITCH/PROTECT 只控制运行时行为
        let proc_enabled = cfg.ebpf_proc_agent;
        let file_enabled = cfg.ebpf_file_agent;
        let net_enabled = cfg.ebpf_net_agent;
        log_info!("[eBPF] 模块加载: proc={}, file={}, net={}", proc_enabled, file_enabled, net_enabled);
        log_info!("[eBPF] 运行时开关: proc_switch={}, file_switch={} | 模式: proc_protect={}, file_protect={}",
            cfg.proc_switch, cfg.file_switch, cfg.proc_protect, cfg.file_protect);

        log_info!("后端模式: {}", backend_mode);

        let backend: Arc<dyn SecurityBackend> = match backend_mode.as_str() {
            #[cfg(feature = "ebpf")]
            "ebpf" => {
                // 纯 eBPF 模式：不加载驱动，直接初始化 eBPF
                log_info!("===== 进入 eBPF 模式 =====");
                log_info!("[eBPF] 检测系统能力...");
                let cap = EbpfCapability::check();
                log_info!("[eBPF] 内核版本: {} (ok={})", cap.kernel_version, cap.kernel_ok);
                log_info!("[eBPF] BTF: {}  |  BPF LSM: {}  |  bpffs: {}",
                    cap.btf_ok, cap.bpf_lsm_ok, cap.bpf_fs_ok);
                if !cap.all_ok() {
                    for reason in cap.fail_reasons() {
                        log_error!("[eBPF] ❌ 能力检测失败: {}", reason);
                    }
                    std::process::exit(1);
                }
                log_info!("[eBPF] ✅ 能力检测通过");

                log_info!("[eBPF] 使用接口: {}", cfg.ifcfg);
                log_info!("[eBPF] 创建 EbpfBackend (bpf_dir=/opt/osec/bpf)...");
                let ebpf = Arc::new(EbpfBackend::new(
                    "/opt/osec/bpf",
                    file_enabled, cfg.file_switch, cfg.file_protect,
                    proc_enabled, cfg.proc_switch, cfg.proc_protect,
                    net_enabled,
                    &cfg.ifcfg, "xdp",
                    cfg.ebpf_proc_rules_max_entries,
                ).unwrap_or_else(|e| {
                    log_error!("EbpfBackend 创建失败: {}", e);
                    std::process::exit(1);
                }));

                // 在 attach LSM + 开启保护模式之前，先把信任进程白名单下发到 proc_rules。
                // 否则保护模式一开、白名单还没写入，agent 自身调用的 /usr/sbin/tc 等信任进程会被拦截。
                // 此时 BPF maps 已由 EbpfBackend::new() 创建（proc_rules 已存在），可安全写入。
                set_backend(ebpf.clone());
                init_dpi_writer();
                pattern::process_pattern_rules_mgr::PROCESS_PATTERN_RULES_MGR.lock().init();

                if let Err(e) = ebpf.init() {
                    log_error!("[eBPF] ❌ EbpfBackend 初始化失败: {}", e);
                    std::process::exit(1);
                }
                // init() 内会关闭 feature_switches[1] 避免空表误报，
                // 此时信任白名单已写入 proc_rules，可以安全开启进程检测。
                ebpf.enable_proc_detection();
                log_info!("[eBPF] ✅ EbpfBackend 初始化完成，所有 BPF 程序已加载到内核");

                // 扫描系统可执行文件目录（hash→inode 映射）留到策略下发之后再启动，
                // 避免与 apply_loaded_policy_to_kernel 争抢 md5_map 锁导致主线程阻塞。
                ebpf_scan = Some(ebpf.clone());

                // 启动 eBPF 进程/文件事件 ring buffer reader（拦截/监控告警上报）
                ebpf.start_proc_event_reader();
                ebpf.start_file_event_reader();
                // 启动网络事件 ring buffer reader（虚开端口/重定向命中 → 告警队列）
                ebpf.start_net_event_reader();
                // 虚开端口告警上报 worker：批量 POST /v1/upOpenPort（对齐驱动模式路径）
                {
                    let bm = Arc::new(init.clone());
                    tokio::spawn(async move {
                        reporter::fake_port_audit::run_open_port_audit_worker(bm).await;
                    });
                }

                // 准入控制：ECN-Echo
                if admission_enabled && admission_mode == 1 {
                    if let Err(e) = ebpf.write_tcp_force_ecn(true) {
                        log_error!("eBPF ECN 设置失败: {}", e);
                    }
                }

                cfg.mod_ver = "ebpf".to_string();
                ebpf
            }
            _ => {
                // driver 模式：先检查失败计数，超过上限则跳过驱动，直接 fallback eBPF
                let mod_ver = if kernel_module::should_skip_driver() {
                    log_warn!("驱动连续失败已达 {} 次上限，跳过内核驱动加载，尝试 eBPF",
                        kernel_module::read_driver_fail_count());
                    String::new()
                } else {
                    let mut init_clone = init.clone();
                    match init_clone.load_kernel_driver().await {
                        Ok(ver) => {
                            kernel_module::reset_driver_fail_count();
                            ver
                        }
                        Err(e) => {
                            log_error!("驱动加载失败: {}", e);
                            let count = kernel_module::increment_driver_fail_count();
                            log_warn!("驱动失败次数: {}/{}", count, kernel_module::MAX_DRIVER_FAILURES);
                            String::new()
                        }
                    }
                };

                if !mod_ver.is_empty() {
                    log_info!("驱动加载成功: {}", mod_ver);
                    cfg.mod_ver = mod_ver;
                    ensure_kernel_hold();

                    // 准入控制通过 /proc
                    if admission_enabled {
                        let proc_path = "/proc/osec/tcp_force_ecn";
                        if std::path::Path::new(proc_path).exists() {
                            let val = match admission_mode {
                                0 => "0", 1 => "1", 2 => "0", _ => "0",
                            };
                            let _ = std::fs::write(proc_path, val);
                        }
                    }

                    Arc::new(DriverBackend::new())
                } else {
                    // 驱动失败，fallback 到 eBPF（如果编译时启用）
                    #[cfg(feature = "ebpf")]
                    {
                        log_warn!("驱动加载失败，尝试 fallback 到 eBPF 模式");
                        let cap = EbpfCapability::check();
                        if !cap.all_ok() {
                            for reason in cap.fail_reasons() {
                                log_error!("eBPF 能力检测失败: {}", reason);
                            }
                            log_warn!("驱动和 eBPF 均不可用，以空后端模式继续运行");
                            cfg.mod_ver = "noop".to_string();
                            Arc::new(NoopBackend)
                        } else {
                            match EbpfBackend::new(
                                "/opt/osec/bpf",
                                file_enabled, cfg.file_switch, cfg.file_protect,
                                proc_enabled, cfg.proc_switch, cfg.proc_protect,
                                net_enabled,
                                &cfg.ifcfg, "xdp",
                                cfg.ebpf_proc_rules_max_entries,
                            ) {
                                Ok(raw_ebpf) => {
                                    let ebpf = Arc::new(raw_ebpf);
                                    // 保护模式生效前先下发信任进程白名单（同主 eBPF 分支）
                                    set_backend(ebpf.clone());
                                    init_dpi_writer();
                                    pattern::process_pattern_rules_mgr::PROCESS_PATTERN_RULES_MGR.lock().init();
                                    if let Err(e) = ebpf.init() {
                                        log_error!("EbpfBackend fallback init 失败: {}", e);
                                        log_warn!("eBPF 初始化失败，以空后端模式继续运行");
                                        cfg.mod_ver = "noop".to_string();
                                        Arc::new(NoopBackend)
                                    } else {
                                        // 后台扫描同样后移（与主 eBPF 分支一致）
                                        ebpf_scan = Some(ebpf.clone());
                                        ebpf.start_proc_event_reader();
                                        ebpf.start_file_event_reader();

                                        // 准入控制：ECN-Echo
                                        if admission_enabled && admission_mode == 1 {
                                            if let Err(e) = ebpf.write_tcp_force_ecn(true) {
                                                log_error!("eBPF ECN 设置失败: {}", e);
                                            }
                                        }

                                        cfg.mod_ver = "ebpf-fallback".to_string();
                                        ebpf
                                    }
                                }
                                Err(e) => {
                                    log_error!("EbpfBackend fallback 创建失败: {}", e);
                                    log_warn!("eBPF 创建失败，以空后端模式继续运行");
                                    cfg.mod_ver = "noop".to_string();
                                    Arc::new(NoopBackend)
                                }
                            }
                        }
                    }
                    #[cfg(not(feature = "ebpf"))]
                    {
                        log_warn!("驱动加载失败，eBPF 未编译，以空后端模式继续运行");
                        cfg.mod_ver = "noop".to_string();
                        Arc::new(NoopBackend)
                    }
                }
            }
        };

        // 设置全局后端
        set_backend(backend);

        // 注册 DPI writer 适配器，使 PatternRulesMgr 的 DPI 下发走 SecurityBackend
        init_dpi_writer();

        // 启动时根据配置文件应用自保开关（离线/在线都生效，不依赖 token/服务器）。
        // 自保走专用 self_protect_dirs + protected_pids，与 DPI dir_policies 完全独立。
        // 仅 eBPF 模式；driver 模式自保仍走其原有 netlink/驱动逻辑，不受影响。
        if backend_mode == "ebpf" {
            let self_protect = cfg.self_protect_switch;
            if let Err(e) = common::backend::with_backend(|b| b.write_self_protection(self_protect as u32)) {
                log_warn!("[eBPF] 启动应用自保开关失败: {}", e);
            }
        }

        let _ = cfg.to_ini(&format!("{}/net_info.ini", cfg.app_path));

        // 初始化 ADMISSION 全局变量
        agent_local_svc::ADMISSION_MODE.store(admission_mode, std::sync::atomic::Ordering::Relaxed);
        if admission_mode == 2 {
            agent_local_svc::ADMISSION_EFFECTIVE.store(admission_switch as u8, std::sync::atomic::Ordering::Relaxed);
        } else {
            agent_local_svc::ADMISSION_EFFECTIVE.store(admission_mode, std::sync::atomic::Ordering::Relaxed);
        }
        if admission_enabled && admission_mode == 2 {
            let hub = agent_local_svc::AgentDataHub::new();
            hub.start_auto_detect();
        }
        drop(cfg);
    }

    // 后端就绪后，仅在离线时把启动恢复的进程黑白名单下发到内核。
    // 在线时服务器会通过 task_fetcher 重推策略，这里跳过，避免与后台 MD5 扫描抢 md5_map 锁。
    // 注意：必须在 drop(cfg) 之后调用。apply_loaded_policy_to_kernel 内部会再次
    // lock NETINFO_CONFIG（检查 [SQLITE_DB]/[DB_POLICY] 开关）；若在 cfg 仍被持有
    // 的作用域内调用，会自死锁（std::sync::Mutex 不可重入），导致 gRPC 无法启动。
    if !online {
        process_mgr::POLICY_MANAGER.lock().unwrap().apply_loaded_policy_to_kernel();
    }

    // 策略下发完成后再启动 eBPF 后台 MD5 扫描，避免与下发争抢 md5_map 锁阻塞主线程。
    #[cfg(feature = "ebpf")]
    if let Some(ebpf) = ebpf_scan {
        let scan_dirs: Vec<String> = [
            "/bin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/lib/systemd",
        ].iter().map(|s| s.to_string()).collect();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = ebpf.scan_executables(&scan_dirs, true) {
                log_error!("[EbpfBackend] 扫描可执行文件失败: {}", e);
            }
            // 扫描完成后，从 DB 重建非扫描目录(/opt 等)可执行文件的 md5_map，
            // 避免重启后这些白名单进程再次被拦截一次。
            if let Err(e) = ebpf.load_md5_inode_cache() {
                log_error!("[EbpfBackend] 从 DB 加载 md5_inode_cache 失败: {}", e);
            }
            // 扫描容器 overlay rootfs 中的可执行文件（Docker/Podman/containerd），
            // 路径存储为容器内逻辑路径（如 /bin/ls），不含 overlay 前缀。
            if let Err(e) = ebpf.scan_container_overlays() {
                log_error!("[EbpfBackend] 扫描容器 overlay 失败: {}", e);
            }
            // 枚举运行中进程（含容器/其它 mount ns 进程），预填 inode_md5_map：
            // 容器里已运行的二进制后续 exec 时能直接命中缓存，不依赖 /proc/<pid>/root 的瞬时时序。
            if let Err(e) = ebpf.scan_running_processes() {
                log_error!("[EbpfBackend] 枚举运行进程预填 inode_md5_map 失败: {}", e);
            }
        });
        log_info!("eBPF md5_map 后台扫描已启动");
    }

    // 初始 AGENT_MODE 以启动探测结果为准（token 才是真正上线的依据）
    if online {
        AGENT_MODE.store(AgentMode::Online as u8, std::sync::atomic::Ordering::Relaxed);
    } else {
        AGENT_MODE.store(AgentMode::Offline as u8, std::sync::atomic::Ordering::Relaxed);
        ADMISSION_NETWORK_ANOMALY.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    log_info!("当前模式: {}", if online { "在线" } else { "离线" });

    // 创建 Netlink 套接字（在离线模式下仍尝试创建，供内核事件使用）
    let nl_sock = NlSockInfo::create_socket()
        .map_err(|e| {
            logging::log_error!("Netlink套接字创建失败: {}", e);
            e
        })
        .ok();


    if let Some(ref sock) = nl_sock {
        match send_data_to_kernel(sock) {
            Ok(msg) => log_info!("向内核发送数据成功: {}", msg),
            Err(e) => log_error!("向内核发送数据失败: {}", e),
        }
        let cfg = NETINFO_CONFIG.lock().unwrap();

        if let Ok(ip) = cfg.server_ip.parse::<IpAddr>() {
            let bytes = match ip {
                IpAddr::V4(v4) => v4.octets().to_vec(),
                IpAddr::V6(v6) => v6.octets().to_vec(),
            };
            // 这里调用 send_message
            sock.send_message(0x703, &bytes)?; // 或者用 match 处理错误
        } else {
            log_error!("Invalid IP address: {}", cfg.server_ip);
        }

        drop(cfg);
    } else {
        log_error!("Netlink socket 未创建，跳过 send_data_to_kernel");
    }
/*
    // 初始化信号处理
    let sigint = unix_signal(SignalKind::interrupt())?;
    let  sigterm = unix_signal(SignalKind::terminate())?;
*/
    
    // 启动异步任务
    let start_services_handle = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.start_services(token_tx, host_is_offline_rx)
                .await
                .map_err(|e| {
                    logging::log_error!("start_services 失败: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        }
    });

    let log_services_handler = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.start_log_services(file_audit_log_rx)
                .await
                .map_err(|e| {
                    logging::log_error!("start_log_services 失败: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        }
    });

    let auto_process_handle = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.start_auto_process_services(auto_process_rx)
                .await
                .map_err(|e| {
                    logging::log_error!("start_auto_process_services 失败: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        }
    });

    let task_fetcher_handle = tokio::spawn({
        let mut init = init.clone();
        let nl_sock = nl_sock.clone();
        async move {
            init.task_fetcher(host_is_offline_tx, token_rx, nl_sock)
                .await
                .map_err(|e| {
                    logging::log_error!("task_fetcher 失败: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        }
    });

    let timer_task_handle = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.start_timer_task()
                .await
                .map_err(|e| {
                    logging::log_error!("start_timer_task 失败: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        }
    });

    let event_handler = Arc::new(Mutex::new(EventHandler::new()));
    let event_handler_send = Arc::clone(&event_handler);
    let mut task_kernel_send_handler = None;
    let mut task_kernel_rcv_handler = None;
    if let Some(nl_sock) = nl_sock {
        task_kernel_send_handler = Some(tokio::spawn({
            let mut init = init.clone();
            let tx = file_audit_log_tx.clone();
            let nl_sock = nl_sock.clone();
            async move {
                init.start_kernel_send_handler(nl_sock, event_handler_send, tx)
                    .await
                    .map_err(|e| {
                        logging::log_error!("start_kernel_send_handler 失败: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e)
                    })
            }
        }));
        let event_handler_rcv = Arc::clone(&event_handler);
        task_kernel_rcv_handler = Some(tokio::spawn({
            let mut init = init.clone();
            let nl_sock = nl_sock.clone();
            async move {
                init.start_kernel_rcv_handler(nl_sock, event_handler_rcv)
                    .await
                    .map_err(|e| {
                        logging::log_error!("start_kernel_rcv_handler 失败: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e)
                    })
            }
        }));
    } else {
        logging::log_error!("无法创建 socket，跳过内核事件处理");
    }

    // 读取系统组件开关
    let (sys_usb, sys_docker) = {
        let cfg = NETINFO_CONFIG.lock().unwrap();
        (cfg.system.usb_hotplug, cfg.system.docker_monitor)
    };

    // 创建USB热插拔信号通道
    let (usb_hotplug_tx, usb_hotplug_rx) = mpsc::channel::<bool>(100);

    let usb_monitor_handle = if sys_usb {
        Some(tokio::spawn({
            let mut init = init.clone();
            let tx = file_audit_log_tx.clone();
            async move {
                init.start_usb_services(tx, usb_hotplug_tx)
                    .await
                    .map_err(|e| {
                        logging::log_error!("start_usb_services 失败: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e)
                    })
            }
        }))
    } else {
        log_info!("[SYSTEM] USB_HOTPLUG=0，跳过 USB 服务启动");
        None
    };

    let usb_hotplug_handler_handle = if sys_usb {
        Some(tokio::spawn({
            let mut init = init.clone();
            async move {
                init.start_usb_hotplug_handler(usb_hotplug_rx)
                    .await
                    .map_err(|e| {
                        logging::log_error!("start_usb_hotplug_handler 失败: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e)
                    })
            }
        }))
    } else {
        None
    };

    let start_docker_monitor_handle = if sys_docker {
        Some(tokio::spawn({
            let mut init = init.clone();
            async move {
                init.start_docker_monitor_services()
                    .await
                    .map_err(|e| {
                        logging::log_error!("start_docker_monitor_services 失败: {}", e);
                        std::io::Error::new(std::io::ErrorKind::Other, e)
                    })
            }
        }))
    } else {
        log_info!("[SYSTEM] DOCKER_MONITOR=0，跳过 Docker 监控服务启动");
        None
    };

    // 启动病毒扫描 gRPC 服务
    let virus_scan_handle = tokio::spawn({
        let mut init = init.clone();
        async move {
            init.start_virus_scan_grpc_service()
                .await
                .map_err(|e| {
                    logging::log_error!("start_virus_scan_grpc_service 失败: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, e)
                })
        }
    });

    // 等待所有任务完成或接收退出信号
    println!("程序正在运行，按 Ctrl+C 或发送 SIGTERM 退出...");

    shutdown_signal().await;
    log_info!("程序退出，执行清理...");

    // 后端清理：eBPF 模式还原 NET_AGENT 设置的 sysctl（accept_local / ip_forward）
    if let Some(b) = common::backend::get_backend() {
        b.shutdown();
    }

    // 卸载驱动
    if let Err(e) = unload_driver() {
        log_error!("卸载驱动失败: {}", e);
    } else {
        log_info!("驱动卸载成功");
    }

    // 可选：等待一小段时间让日志 flush（如果日志是异步的）
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    log_info!("程序已安全退出");
     std::process::exit(0);
    //Ok(())

}

async fn shutdown_signal() {
    let mut sigint = unix_signal(SignalKind::interrupt()).expect("注册 SIGINT 失败");
    let mut sigterm = unix_signal(SignalKind::terminate()).expect("注册 SIGTERM 失败");

    tokio::select! {
        _ = sigint.recv() => log_info!("收到 SIGINT (Ctrl+C)"),
        _ = sigterm.recv() => log_info!("收到 SIGTERM"),
    }
}

