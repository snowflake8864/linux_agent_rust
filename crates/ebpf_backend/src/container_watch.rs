//! 动态容器 cgroup 收集器
//!
//! 扫描 `/sys/fs/cgroup`，把 cgroup v2 目录 inode（cgid）映射到容器：
//!
//!   cgid_容器根       -> ContainerEntry
//!   cgid_容器内子cgroup -> 同一个 ContainerEntry（别名）
//!
//! 这样 eBPF 的 `bpf_get_current_cgroup_id()` 无论返回容器根还是任意嵌套
//! 子 cgroup 的 id，都能 O(1) 命中。
//!
//! 支持 Docker / containerd(k8s) / CRI-O(k8s) / Podman，以及 cgroupfs 布局。
//! 仅在 eBPF 后端中使用；驱动模式不会创建本收集器。

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const MAX_DEPTH: usize = 16;
const RECONCILE_INTERVAL: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Runtime {
    Docker,
    Containerd,
    Crio,
    Podman,
    Kubernetes,
    Unknown,
}

impl Runtime {
    pub fn as_str(&self) -> &'static str {
        match self {
            Runtime::Docker => "docker",
            Runtime::Containerd => "containerd",
            Runtime::Crio => "crio",
            Runtime::Podman => "podman",
            Runtime::Kubernetes => "k8s",
            Runtime::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PidInfo {
    pub pid: i32,
    pub root_dev: u64,
    pub root_ino: u64,
    pub exe_dev: u64,
    pub exe_ino: u64,
}

#[derive(Clone, Debug)]
pub struct ContainerEntry {
    /// 容器根 cgroup 的 inode（该容器唯一的 root cgid）
    pub root_cgid: u64,
    pub runtime: Runtime,
    pub container_id: String,
    pub pod_uid: Option<String>,
    pub cgroup_path: PathBuf,
    /// 容器根 cgroup 中生命周期最长的进程（通常是容器 init / docker inspect .State.Pid）。
    /// 仅作兜底；真正稳定定位 rootfs 的是 `root_fd`。
    pub init_pid: Option<i32>,
    /// 容器根文件系统目录 fd（O_PATH），扫描时打开后由内核钉住 mount。
    /// 即使容器内 pid 全部退出，只要容器 mount 还在，fd 依然有效。
    pub root_fd: Option<Arc<OwnedFd>>,
    /// 容器整棵子树内所有进程（含嵌套子 cgroup）
    pub pids: Vec<PidInfo>,
}

#[derive(Default)]
struct Table {
    /// 任意 cgid（容器根或其子孙）-> 容器根 cgid
    alias: HashMap<u64, u64>,
    /// 容器根 cgid -> 容器
    containers: HashMap<u64, ContainerEntry>,
}

/// 对外句柄。内部表由后台线程动态更新，查询无锁竞争（读锁）。
pub struct ContainerWatcher {
    table: RwLock<Table>,
}

#[derive(Clone, Copy)]
enum MatchKind {
    /// systemd 风格：<prefix><id><suffix>，如 docker-<id>.scope
    Scope { prefix: &'static str, suffix: &'static str },
    /// cgroupfs 风格：目录名本身就是 64 位十六进制容器 ID
    RawHex,
}

struct Probe {
    runtime: Runtime,
    roots: &'static [&'static str],
    kind: MatchKind,
    /// k8s: 从父目录 kubepods-*-pod<uid>.slice / pod<uid> 解析 pod UID
    pod_from_parent: bool,
}

fn probes() -> Vec<Probe> {
    vec![
        Probe {
            runtime: Runtime::Docker,
            roots: &["system.slice", "user.slice"],
            kind: MatchKind::Scope { prefix: "docker-", suffix: ".scope" },
            pod_from_parent: false,
        },
        Probe {
            runtime: Runtime::Containerd,
            roots: &["kubepods.slice", "system.slice", "user.slice"],
            kind: MatchKind::Scope { prefix: "cri-containerd-", suffix: ".scope" },
            pod_from_parent: true,
        },
        Probe {
            runtime: Runtime::Crio,
            roots: &["kubepods.slice", "system.slice", "user.slice"],
            kind: MatchKind::Scope { prefix: "crio-", suffix: ".scope" },
            pod_from_parent: true,
        },
        Probe {
            runtime: Runtime::Podman,
            roots: &["system.slice", "user.slice", "machine.slice"],
            kind: MatchKind::Scope { prefix: "libpod-", suffix: ".scope" },
            pod_from_parent: false,
        },
        // cgroupfs 布局（非 systemd cgroup driver）：
        //   /sys/fs/cgroup/kubepods/<qos>/pod<uid>/<64位hex>
        Probe {
            runtime: Runtime::Kubernetes,
            roots: &["kubepods"],
            kind: MatchKind::RawHex,
            pod_from_parent: true,
        },
        // cgroupfs Docker：/sys/fs/cgroup/docker/<64位hex>
        Probe {
            runtime: Runtime::Docker,
            roots: &["docker"],
            kind: MatchKind::RawHex,
            pod_from_parent: false,
        },
    ]
}

fn is_hex_id(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

fn match_probe(dir: &Path, probe: &Probe) -> Option<(Runtime, String, Option<String>)> {
    let name = dir.file_name()?.to_str()?;
    let cid = match probe.kind {
        MatchKind::Scope { prefix, suffix } => {
            if !name.starts_with(prefix) || !name.ends_with(suffix) {
                return None;
            }
            let end = name.len().saturating_sub(suffix.len());
            if end <= prefix.len() {
                return None;
            }
            name[prefix.len()..end].to_string()
        }
        MatchKind::RawHex => {
            if !is_hex_id(name) {
                return None;
            }
            name.to_string()
        }
    };
    if cid.is_empty() {
        return None;
    }
    let pod = if probe.pod_from_parent {
        extract_pod_uid(dir)
    } else {
        None
    };
    Some((probe.runtime, cid, pod))
}

/// 从祖先目录解析 k8s pod UID：
/// - systemd: kubepods-burstable-pod<uid>.slice
/// - cgroupfs: pod<uid>
fn extract_pod_uid(dir: &Path) -> Option<String> {
    let mut cur = dir.parent();
    while let Some(d) = cur {
        if let Some(name) = d.file_name().and_then(|s| s.to_str()) {
            let pos = if let Some(i) = name.find("-pod") {
                Some(i + 4)
            } else if name.starts_with("pod") {
                Some(3)
            } else {
                None
            };
            if let Some(pos) = pos {
                let uid = name[pos..].trim_end_matches(".slice");
                if !uid.is_empty() {
                    // systemd 会把 UID 中的 '-' 转义成 '_'
                    return Some(uid.replace('_', "-"));
                }
            }
        }
        cur = d.parent();
    }
    None
}

fn stat_ino(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).ok().map(|m| m.ino())
}

fn pid_root_dev_ino(pid: i32) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(format!("/proc/{}/root", pid)).ok()?;
    Some((meta.dev(), meta.ino()))
}

fn pid_exe_dev_ino(pid: i32) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let link = fs::read_link(format!("/proc/{}/exe", pid)).ok()?;
    let meta = fs::metadata(link).ok()?;
    Some((meta.dev(), meta.ino()))
}

fn read_cgroup_procs(cgdir: &Path) -> Vec<i32> {
    let mut out = Vec::new();
    if let Ok(s) = fs::read_to_string(cgdir.join("cgroup.procs")) {
        for line in s.lines() {
            if let Ok(pid) = line.trim().parse::<i32>() {
                out.push(pid);
            }
        }
    }
    out
}

/// 读取进程启动时间（/proc/<pid>/stat 第 22 个字段）。
fn proc_starttime(pid: i32) -> Option<u64> {
    let s = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // comm 可能含空格/括号，取最后一个 ')' 之后的部分，从 state（第 3 字段）开始
    let rparen = s.rfind(')')?;
    let rest = s.get(rparen + 2..)?;
    // starttime 是整体第 22 字段，在 rest 中下标为 22 - 3 = 19
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// 从容器根 cgroup 的进程里挑生命周期最长的那个（启动最早）。
/// 容器根 cgroup 通常只有 init 进程；偶尔有其它进程时按 starttime 选最早。
fn pick_init_pid(procs: &[i32]) -> Option<i32> {
    let mut best: Option<(u64, i32)> = None;
    for &pid in procs {
        let started = proc_starttime(pid).unwrap_or(u64::MAX);
        let cand = (started, pid);
        if best.map_or(true, |b| cand < b) {
            best = Some(cand);
        }
    }
    best.map(|(_, pid)| pid)
}

/// 打开 `/proc/<pid>/root` 得到容器根目录 fd。
/// O_PATH fd 会钉住目标 mount，后续用 `/proc/self/fd/<fd>/<path>` 访问，
/// 不再依赖该 pid 是否存活。
pub(crate) fn open_proc_root_fd(pid: i32) -> Option<Arc<OwnedFd>> {
    open_dir_fd(&format!("/proc/{}/root", pid))
}

/// 打开一个目录，得到 O_PATH dirfd。
pub(crate) fn open_dir_fd(path: &str) -> Option<Arc<OwnedFd>> {
    let c = CString::new(path).ok()?;
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    Some(Arc::new(unsafe { OwnedFd::from_raw_fd(fd) }))
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

// include/uapi/linux/openat2.h: RESOLVE_IN_ROOT = 0x10
const RESOLVE_IN_ROOT: u64 = 0x10;

/// 以 dirfd 为根打开文件，绝对符号链接按容器根解析，不会逃逸到宿主机。
/// 这是修复 `.../merged/bin/lzma -> /etc/alternatives/lzma` 这类绝对链接的关键。
pub(crate) fn open_file_in_root(root_fd: RawFd, path: &str) -> Option<OwnedFd> {
    let rel = path.trim_start_matches('/');
    let rel = if rel.is_empty() { "." } else { rel };
    let c = CString::new(rel).ok()?;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_IN_ROOT,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd as libc::c_long,
            c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if ret < 0 {
        return None;
    }
    Some(unsafe { OwnedFd::from_raw_fd(ret as i32) })
}

fn collect_pids(cgdir: &Path) -> (Vec<PidInfo>, usize) {
    let mut v = Vec::new();
    let mut failed = 0usize;
    for pid in read_cgroup_procs(cgdir) {
        match pid_root_dev_ino(pid) {
            Some((rd, ri)) => {
                let (ed, ei) = pid_exe_dev_ino(pid).unwrap_or((0, 0));
                v.push(PidInfo {
                    pid,
                    root_dev: rd,
                    root_ino: ri,
                    exe_dev: ed,
                    exe_ino: ei,
                });
            }
            None => failed += 1,
        }
    }
    (v, failed)
}

struct ScanBuilder {
    alias: HashMap<u64, u64>,
    containers: HashMap<u64, ContainerEntry>,
    pid_stat_failed: usize,
}

/// 对账时复用的旧 fd 信息：只有容器身份完全一致才复用，
/// 容器退出/重启/同名重建都会因为路径、id 或 init_pid 变化而重新打开。
struct ReuseFd {
    cgroup_path: PathBuf,
    container_id: String,
    init_pid: Option<i32>,
    fd: Arc<OwnedFd>,
}

/// 递归扫描。owner 为当前所处的容器根 cgid（None=宿主机层级）。
/// 一进入匹配到的容器目录就切换 owner，并把整棵子树的 cgid 都别名到该容器。
fn walk(
    dir: &Path,
    depth: usize,
    owner: Option<u64>,
    active: &[&Probe],
    reuse: &HashMap<u64, ReuseFd>,
    b: &mut ScanBuilder,
    visited: &mut HashSet<PathBuf>,
) {
    if depth > MAX_DEPTH {
        return;
    }
    if !visited.insert(dir.to_path_buf()) {
        return;
    }
    let cgid = match stat_ino(dir) {
        Some(v) => v,
        None => return,
    };

    let mut current = owner;
    // 内层容器覆盖外层，支持 docker-in-docker 等嵌套
    for probe in active {
        if let Some((runtime, cid, pod)) = match_probe(dir, probe) {
            // 容器根 cgroup 的 init 进程：生命周期与容器一致，用于稳定定位 rootfs
            let root_procs = read_cgroup_procs(dir);
            let init_pid = pick_init_pid(&root_procs);
            // 只有 cgroup 路径、容器 id、init pid 都一致才复用旧 fd；
            // 容器退出/重启/重建都会重新打开。
            let reused_fd = reuse.get(&cgid).and_then(|r| {
                if r.cgroup_path.as_path() == dir
                    && r.container_id == cid
                    && r.init_pid == init_pid
                {
                    Some(Arc::clone(&r.fd))
                } else {
                    None
                }
            });
            b.containers.insert(
                cgid,
                ContainerEntry {
                    root_cgid: cgid,
                    runtime,
                    container_id: cid,
                    pod_uid: pod,
                    cgroup_path: dir.to_path_buf(),
                    init_pid,
                    root_fd: reused_fd,
                    pids: Vec::new(),
                },
            );
            current = Some(cgid);
            break;
        }
    }

    if let Some(owner_cgid) = current {
        b.alias.insert(cgid, owner_cgid);
        let (pids, failed) = collect_pids(dir);
        b.pid_stat_failed += failed;
        if let Some(entry) = b.containers.get_mut(&owner_cgid) {
            // 优先用 init pid 打开容器根目录 fd；root cgroup 为空时，
            // 后续子 cgroup 扫描到任意存活进程再补开。
            if entry.root_fd.is_none() {
                let mut candidates: Vec<i32> = Vec::with_capacity(pids.len() + 1);
                if let Some(init_pid) = entry.init_pid {
                    candidates.push(init_pid);
                }
                candidates.extend(pids.iter().map(|p| p.pid));
                for pid in candidates {
                    if let Some(fd) = open_proc_root_fd(pid) {
                        entry.root_fd = Some(fd);
                        break;
                    }
                }
            }
            entry.pids.extend(pids);
        }
    }

    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            match e.file_type() {
                Ok(ft) if ft.is_dir() => {
                    walk(&e.path(), depth + 1, current, active, reuse, b, visited);
                }
                _ => {}
            }
        }
    }
}

fn scan_all(reuse: &HashMap<u64, ReuseFd>) -> Table {
    let probes = probes();
    let mut roots: Vec<&'static str> = probes
        .iter()
        .flat_map(|p| p.roots.iter().copied())
        .collect();
    roots.sort_unstable();
    roots.dedup();

    let mut b = ScanBuilder {
        alias: HashMap::new(),
        containers: HashMap::new(),
        pid_stat_failed: 0,
    };
    let mut visited = HashSet::new();

    for root in roots {
        let base = Path::new(CGROUP_ROOT).join(root);
        if !base.is_dir() {
            continue;
        }
        let active: Vec<&Probe> = probes
            .iter()
            .filter(|p| p.roots.iter().any(|r| *r == root))
            .collect();
        walk(&base, 0, None, &active, reuse, &mut b, &mut visited);
    }

    if b.pid_stat_failed > 0 {
        log::debug!(
            "[container_watch] {} pid stat failed (permission?)",
            b.pid_stat_failed
        );
    }

    // 同一 pid 直接属于唯一 cgroup；排序去重保证稳定
    for entry in b.containers.values_mut() {
        entry.pids.sort_by_key(|p| p.pid);
        entry.pids.dedup_by_key(|p| p.pid);
    }

    Table {
        alias: b.alias,
        containers: b.containers,
    }
}

fn reconcile(table: &RwLock<Table>) -> (usize, usize) {
    // 先短暂持读锁，克隆旧 fd 句柄（Arc），再释放锁做全量扫描。
    // 容器已退出时新表里没有该条目，旧表替换后 Arc 归零，fd 自动关闭。
    let reuse: HashMap<u64, ReuseFd> = {
        let r = table.read().unwrap_or_else(|e| e.into_inner());
        r.containers
            .iter()
            .filter_map(|(cgid, entry)| {
                entry.root_fd.as_ref().map(|fd| {
                    (
                        *cgid,
                        ReuseFd {
                            cgroup_path: entry.cgroup_path.clone(),
                            container_id: entry.container_id.clone(),
                            init_pid: entry.init_pid,
                            fd: Arc::clone(fd),
                        },
                    )
                })
            })
            .collect()
    };

    let scanned = scan_all(&reuse);
    let counts = (scanned.containers.len(), scanned.alias.len());
    let mut w = table.write().unwrap_or_else(|e| e.into_inner());
    *w = scanned;
    counts
}

fn run_loop(watcher: Arc<ContainerWatcher>, rx: Receiver<()>) {
    let mut last: Option<(usize, usize)> = None;
    loop {
        let counts = reconcile(&watcher.table);
        if last != Some(counts) {
            log::info!(
                "[container_watch] 容器={} cgid别名={}",
                counts.0,
                counts.1
            );
            last = Some(counts);
        }
        match rx.recv_timeout(RECONCILE_INTERVAL) {
            Ok(()) => {
                // cgroup 目录可能刚创建，稍等稳定
                thread::sleep(Duration::from_millis(50));
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                // inotify 线程不可用：退化为纯周期对账
                thread::sleep(RECONCILE_INTERVAL);
            }
        }
    }
}

fn spawn_inotify(tx: Sender<()>) {
    let _ = thread::Builder::new()
        .name("container-watch-inotify".into())
        .spawn(move || {
            let mut ino = match inotify::Inotify::init() {
                Ok(i) => i,
                Err(e) => {
                    log::warn!(
                        "[container_watch] inotify 初始化失败: {}（退化为周期对账）",
                        e
                    );
                    return;
                }
            };

            let mask = inotify::WatchMask::CREATE
                | inotify::WatchMask::DELETE
                | inotify::WatchMask::MOVED_TO
                | inotify::WatchMask::MOVED_FROM;

            let mut roots: Vec<&'static str> = probes()
                .iter()
                .flat_map(|p| p.roots.iter().copied())
                .collect();
            roots.sort_unstable();
            roots.dedup();

            let mut watched = 0usize;
            for root in roots {
                let base = Path::new(CGROUP_ROOT).join(root);
                if base.is_dir() && ino.watches().add(&base, mask).is_ok() {
                    watched += 1;
                }
            }
            log::info!("[container_watch] inotify 监听 {} 个 cgroup 根", watched);
            if watched == 0 {
                return;
            }

            let mut buf = [0u8; 4096];
            loop {
                match ino.read_events_blocking(&mut buf) {
                    Ok(events) => {
                        let mut any = false;
                        for _ in events {
                            any = true;
                        }
                        if any {
                            let _ = tx.send(());
                        }
                    }
                    Err(e) => {
                        log::warn!("[container_watch] inotify read error: {}", e);
                        thread::sleep(Duration::from_secs(1));
                    }
                }
            }
        });
}

fn is_cgroup_v2(path: &str) -> bool {
    use std::os::unix::io::AsRawFd;
    let fd = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd.as_raw_fd(), &mut stat) } != 0 {
        return false;
    }
    // CGROUP2_SUPER_MAGIC = 0x63677270
    stat.f_type == 0x63677270
}

impl ContainerWatcher {
    /// 启动动态收集（仅 eBPF 模式调用）。非 cgroup v2 环境返回空表。
    pub fn start() -> Arc<Self> {
        let watcher = Arc::new(Self {
            table: RwLock::new(Table::default()),
        });

        if !is_cgroup_v2(CGROUP_ROOT) {
            log::warn!(
                "[container_watch] {} 不是 cgroup v2，跳过容器收集（按宿主机进程处理）",
                CGROUP_ROOT
            );
            return watcher;
        }

        let (tx, rx) = mpsc::channel::<()>();
        spawn_inotify(tx);

        let w = Arc::clone(&watcher);
        let _ = thread::Builder::new()
            .name("container-watch".into())
            .spawn(move || run_loop(w, rx));

        watcher
    }

    /// 不收集（proc agent 未启用时使用），所有查询都返回空。
    pub fn disabled() -> Arc<Self> {
        Arc::new(Self {
            table: RwLock::new(Table::default()),
        })
    }

    /// 进程所属 cgid -> 容器。None 表示宿主机进程（或容器尚未被扫描到）。
    pub fn lookup(&self, cgid: u64) -> Option<ContainerEntry> {
        let t = self.table.read().unwrap_or_else(|e| e.into_inner());
        let root = t.alias.get(&cgid)?;
        t.containers.get(root).cloned()
    }

    pub fn is_container(&self, cgid: u64) -> bool {
        let t = self.table.read().unwrap_or_else(|e| e.into_inner());
        t.alias.contains_key(&cgid)
    }

    /// 当前全部容器快照
    pub fn snapshot(&self) -> Vec<ContainerEntry> {
        let t = self.table.read().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<ContainerEntry> = t.containers.values().cloned().collect();
        v.sort_by_key(|e| e.root_cgid);
        v
    }

    /// 查某个 pid 属于哪个容器（低频用；高频请用 lookup(cgid)）
    pub fn lookup_pid(&self, pid: i32) -> Option<ContainerEntry> {
        let t = self.table.read().unwrap_or_else(|e| e.into_inner());
        t.containers
            .values()
            .find(|e| e.pids.iter().any(|p| p.pid == pid))
            .cloned()
    }
}
