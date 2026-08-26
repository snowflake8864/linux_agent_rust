use aya::maps::Array;
use aya::programs::{
    tc::SchedClassifierLinkId, xdp::XdpLinkId, SchedClassifier, TcAttachType, Xdp, XdpFlags,
};
use aya::{Bpf, BpfLoader};
use log::{info, warn};

/// 多模块 eBPF 加载器 — 按功能独立加载 .o 文件
pub struct ModularLoader {
    pub file_bpf: Option<Bpf>,
    pub proc_bpf: Option<Bpf>,
    pub net_bpf: Option<Bpf>,
    /// 已挂载的 XDP (程序名, link_id) — 退出时精确 detach
    xdp_attached: Option<(String, XdpLinkId)>,
    /// 已挂载的 TC egress (程序名, link_id) — 退出时精确 detach。
    /// TC cls_bpf filter 在内核侧持有 prog 引用，进程退出不会自动卸载，必须显式处理
    tc_attached: Option<(String, SchedClassifierLinkId)>,
}

impl ModularLoader {
    pub fn new() -> Self {
        Self {
            file_bpf: None,
            proc_bpf: None,
            net_bpf: None,
            xdp_attached: None,
            tc_attached: None,
        }
    }

    pub fn load_file_agent(&mut self, path: &str) -> anyhow::Result<()> {
        info!("[EbpfBackend] 📦 解析 ELF: file_agent.bpf.o");
        let bpf = BpfLoader::new().load_file(path)?;
        // 列出文件中包含的所有 BPF 程序名
        for (name, _prog) in bpf.programs() {
            info!("[EbpfBackend]   发现程序: {}", name);
        }
        self.file_bpf = Some(bpf);
        Ok(())
    }

    pub fn load_proc_agent(&mut self, path: &str) -> anyhow::Result<()> {
        info!("[EbpfBackend] 📦 解析 ELF: proc_agent.bpf.o");
        let bpf = BpfLoader::new().load_file(path)?;
        for (name, _prog) in bpf.programs() {
            info!("[EbpfBackend]   发现程序: {}", name);
        }
        self.proc_bpf = Some(bpf);
        Ok(())
    }

    pub fn load_net_agent(&mut self, path: &str) -> anyhow::Result<()> {
        info!("[EbpfBackend] 📦 解析 ELF: net_agent.bpf.o");
        let bpf = BpfLoader::new().load_file(path)?;
        for (name, _prog) in bpf.programs() {
            info!("[EbpfBackend]   发现程序: {}", name);
        }
        self.net_bpf = Some(bpf);
        Ok(())
    }

    /// 挂载文件管控 eBPF 程序 (LSM hooks)
    pub fn attach_file_programs(&mut self) -> anyhow::Result<()> {
        use aya::programs::{KProbe, Lsm};
        use aya::Btf;

        info!("[EbpfBackend] 🔌 获取 BTF (from sysfs)...");
        let btf = Btf::from_sys_fs()?;
        info!("[EbpfBackend] ✅ BTF 获取成功");
        let bpf = self
            .file_bpf
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("File agent not loaded"))?;

        if let Some(prog) = bpf.program_mut("enforce_file_open") {
            info!("[EbpfBackend] 🔌 加载 LSM: file_open...");
            let lsm: &mut Lsm = prog.try_into()?;
            lsm.load("file_open", &btf)?;
            lsm.attach()?;
            info!("[EbpfBackend] ✅ LSM attached: file_open");
        } else {
            warn!("[EbpfBackend] ⚠ 未找到程序: enforce_file_open");
        }

        if let Some(prog) = bpf.program_mut("enforce_inode_create") {
            info!("[EbpfBackend] 🔌 加载 LSM: inode_create...");
            let lsm: &mut Lsm = prog.try_into()?;
            lsm.load("inode_create", &btf)?;
            lsm.attach()?;
            info!("[EbpfBackend] ✅ LSM attached: inode_create");
        } else {
            warn!("[EbpfBackend] ⚠ 未找到程序: enforce_inode_create");
        }

        if let Some(prog) = bpf.program_mut("enforce_inode_unlink") {
            info!("[EbpfBackend] 🔌 加载 LSM: inode_unlink...");
            let lsm: &mut Lsm = prog.try_into()?;
            lsm.load("inode_unlink", &btf)?;
            lsm.attach()?;
            info!("[EbpfBackend] ✅ LSM attached: inode_unlink");
        } else {
            warn!("[EbpfBackend] ⚠ 未找到程序: enforce_inode_unlink");
        }

        if let Some(prog) = bpf.program_mut("enforce_vfs_mkdir") {
            info!("[EbpfBackend] 🔌 加载 kprobe: vfs_mkdir...");
            let kprobe: &mut KProbe = prog.try_into()?;
            kprobe.load()?;
            kprobe.attach("vfs_mkdir", 0)?;
            info!("[EbpfBackend] ✅ KProbe attached: vfs_mkdir");
        } else {
            warn!("[EbpfBackend] ⚠ 未找到程序: enforce_vfs_mkdir");
        }

        Ok(())
    }

    /// 挂载进程管控 eBPF 程序 (LSM bprm_check_security)
    pub fn attach_proc_programs(&mut self) -> anyhow::Result<()> {
        use aya::programs::Lsm;
        use aya::Btf;

        info!("[EbpfBackend] 🔌 获取 BTF (from sysfs)...");
        let btf = Btf::from_sys_fs()?;
        info!("[EbpfBackend] ✅ BTF 获取成功");
        let bpf = self
            .proc_bpf
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Proc agent not loaded"))?;

        if let Some(prog) = bpf.program_mut("enforce_bprm_check_security") {
            info!("[EbpfBackend] 🔌 加载 LSM: bprm_check_security (进程执行拦截)...");
            let lsm: &mut Lsm = prog.try_into()?;
            lsm.load("bprm_check_security", &btf)?;
            lsm.attach()?;
            info!("[EbpfBackend] ✅ LSM attached: bprm_check_security ← 进程执行将触发此钩子");
        } else {
            warn!("[EbpfBackend] ⚠ 未找到程序: enforce_bprm_check_security");
        }

        // task_kill hook: prevent protected processes (agent + designated PIDs)
        // from being killed by external processes
        if let Some(prog) = bpf.program_mut("enforce_task_kill") {
            info!("[EbpfBackend] 🔌 加载 LSM: task_kill (防杀保护)...");
            let lsm: &mut Lsm = prog.try_into()?;
            lsm.load("task_kill", &btf)?;
            lsm.attach()?;
            info!("[EbpfBackend] ✅ LSM attached: task_kill ← 保护进程不被 kill");
        } else {
            warn!("[EbpfBackend] ⚠ 未找到程序: enforce_task_kill");
        }

        Ok(())
    }

    /// 挂载网络管控 eBPF 程序 (XDP + TC egress + Cgroup connect4)
    pub fn attach_net_programs(&mut self, interface: &str, engine: &str) -> anyhow::Result<()> {
        let bpf = self
            .net_bpf
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Net agent not loaded"))?;

        if engine == "xdp" {
            // 先清理上次异常退出（SIGKILL/崩溃）可能残留的挂载：
            // - TC cls_bpf filter 内核侧持有 prog 引用，进程死亡不会自动卸载；
            // - kernel < 5.9 时 XDP netlink 挂载同样残留（>= 5.9 走 bpf_link 由内核自动回收）。
            // 本 agent 是该接口 XDP/clsact 的唯一属主，直接清掉旧挂载，避免 EEXIST / 双份拦截。
            let _ = std::process::Command::new("ip")
                .args(["link", "set", "dev", interface, "xdp", "off"])
                .output();
            let _ = std::process::Command::new("tc")
                .args(["qdisc", "del", "dev", interface, "clsact"])
                .output();

            // XDP (ingress)
            for name in &["xdp_pkt_mod", "xdp_packet_filter"] {
                if let Some(prog) = bpf.program_mut(name) {
                    info!("[EbpfBackend] 🔌 加载 XDP: {} on {}...", name, interface);
                    let xdp: &mut Xdp = prog.try_into()?;
                    xdp.load()?;
                    let link_id = xdp.attach(interface, XdpFlags::default())?;
                    self.xdp_attached = Some((name.to_string(), link_id));
                    info!("[EbpfBackend] ✅ XDP attached: {} -> {}", name, interface);
                    break;
                }
            }

            // TC egress (回程流量识别/改写)。挂在网桥（如 br0）等接口上可能因
            // clsact qdisc 无法建立而失败（内核返回 ENOENT）——与 cgroup connect4
            // 一样降级为警告，不阻断 XDP/进程/文件功能。
            if let Some(prog) = bpf.program_mut("tc_packet_filter") {
                info!("[EbpfBackend] 🔌 加载 TC egress: tc_packet_filter on {}...", interface);
                let tc_result = (|| -> anyhow::Result<SchedClassifierLinkId> {
                    let _ = std::process::Command::new("tc")
                        .args(["qdisc", "add", "dev", interface, "clsact"])
                        .output();
                    let tc: &mut SchedClassifier = prog.try_into()?;
                    tc.load()?;
                    Ok(tc.attach(interface, TcAttachType::Egress)?)
                })();
                match tc_result {
                    Ok(link_id) => {
                        self.tc_attached = Some(("tc_packet_filter".to_string(), link_id));
                        info!("[EbpfBackend] ✅ TC Egress attached: tc_packet_filter -> {}", interface);
                    }
                    Err(e) => warn!("[EbpfBackend] ⚠ TC Egress 挂载失败（非致命，XDP 仍生效）: {}", e),
                }
            } else {
                warn!("[EbpfBackend] ⚠ 未找到程序: tc_packet_filter");
            }
        }

        // Cgroup connect4 hook (本地连接拦截)
        // 注意: BPF_CGROUP_INET4_CONNECT 要求 cgroup v2 (unified hierarchy)。
        // 在 cgroup v1 或 hybrid 模式系统上，/sys/fs/cgroup 不是有效的 cgroup v2 fd，
        // 此时 attach 会失败。这是正常的——将错误降级为警告，不影响 XDP/TC 功能。
        if let Some(prog) = bpf.program_mut("enforce_connect4") {
            let cgroup_path = if std::path::Path::new("/sys/fs/cgroup/unified").exists() {
                "/sys/fs/cgroup/unified"
            } else if Self::is_cgroup_v2("/sys/fs/cgroup") {
                "/sys/fs/cgroup"
            } else {
                warn!("[EbpfBackend] ⚠ 系统非 cgroup v2，跳过 Cgroup connect4 挂载（cgroup v1 不支持此钩子）");
                return Ok(());
            };
            info!("[EbpfBackend] 🔌 加载 Cgroup connect4 (cgroup_path={})...", cgroup_path);
            match (|| -> anyhow::Result<()> {
                let cgroup_fd = std::fs::File::open(cgroup_path)?;
                let program: &mut aya::programs::CgroupSockAddr = prog.try_into()?;
                program.load()?;
                program.attach(cgroup_fd)?;
                Ok(())
            })() {
                Ok(()) => info!("[EbpfBackend] ✅ Cgroup connect4 attached"),
                Err(e) => warn!("[EbpfBackend] ⚠ Cgroup connect4 挂载失败（非致命，XDP/TC 仍生效）: {}", e),
            }
        } else {
            warn!("[EbpfBackend] ⚠ 未找到程序: enforce_connect4");
        }

        Ok(())
    }

    pub fn file_bpf_mut(&mut self) -> Option<&mut Bpf> {
        self.file_bpf.as_mut()
    }

    /// 退出时卸载网络管控 eBPF（XDP/TC）。
    ///
    /// 为什么必须显式卸载：
    /// - TC (cls_bpf)：netlink filter 挂载，内核侧 filter 持有 prog 引用，
    ///   进程退出（包括 Ctrl+C 后的 process::exit）不会自动卸载，流量拦截会持续生效；
    /// - XDP：kernel >= 5.9 走 bpf_link 会随进程退出由内核自动回收，这里做确定性兜底。
    ///
    /// LSM/kprobe/cgroup connect4 为 bpf_link 挂载，内核随进程退出自动回收，无需处理。
    pub fn detach_net_programs(&mut self) {
        if let Some((name, link_id)) = self.tc_attached.take() {
            if let Some(bpf) = self.net_bpf.as_mut() {
                if let Some(prog) = bpf.program_mut(&name) {
                    let tc_res: Result<&mut SchedClassifier, _> = prog.try_into();
                    match tc_res {
                        Ok(tc) => match tc.detach(link_id) {
                            Ok(()) => info!("[EbpfBackend] ✅ TC egress 已卸载: {}", name),
                            Err(e) => warn!("[EbpfBackend] ⚠ TC egress 卸载失败: {}: {}", name, e),
                        },
                        Err(e) => warn!("[EbpfBackend] ⚠ TC 程序类型转换失败 {}: {}", name, e),
                    }
                } else {
                    warn!("[EbpfBackend] ⚠ 未找到 TC 程序: {}", name);
                }
            }
        }
        if let Some((name, link_id)) = self.xdp_attached.take() {
            if let Some(bpf) = self.net_bpf.as_mut() {
                if let Some(prog) = bpf.program_mut(&name) {
                    let xdp_res: Result<&mut Xdp, _> = prog.try_into();
                    match xdp_res {
                        Ok(xdp) => match xdp.detach(link_id) {
                            Ok(()) => info!("[EbpfBackend] ✅ XDP 已卸载: {}", name),
                            Err(e) => warn!("[EbpfBackend] ⚠ XDP 卸载失败: {}: {}", name, e),
                        },
                        Err(e) => warn!("[EbpfBackend] ⚠ XDP 程序类型转换失败 {}: {}", name, e),
                    }
                } else {
                    warn!("[EbpfBackend] ⚠ 未找到 XDP 程序: {}", name);
                }
            }
        }
    }

    pub fn proc_bpf_mut(&mut self) -> Option<&mut Bpf> {
        self.proc_bpf.as_mut()
    }

    pub fn net_bpf_mut(&mut self) -> Option<&mut Bpf> {
        self.net_bpf.as_mut()
    }

    /// 写入 global_modes map (0=MONITOR, 1=PROTECT → eBPF 用 1=MONITOR, 2=PROTECT)
    pub fn set_global_mode(bpf: &mut Bpf, feature_idx: u32, protect: bool) -> anyhow::Result<()> {
        let map = match bpf.map_mut("global_modes") {
            Some(m) => m,
            None => { info!("[EbpfBackend] global_modes map 不存在，跳过"); return Ok(()); }
        };
        let mut arr: Array<_, u8> = Array::try_from(map)?;
        let val: u8 = if protect { 2 } else { 1 }; // 1=MONITOR, 2=PROTECT
        arr.set(feature_idx, val, 0)?;
        info!("[EbpfBackend] ✅ global_modes[{}] = {} ({})", feature_idx, val,
            if protect { "PROTECT" } else { "MONITOR" });
        Ok(())
    }

    /// 写入 agent PID 到 agent_pids map，让自保规则放行 agent 自身的文件操作
    pub fn set_agent_pid(bpf: &mut Bpf, pid: u32) -> anyhow::Result<()> {
        let map = match bpf.map_mut("agent_pids") {
            Some(m) => m,
            None => { info!("[EbpfBackend] agent_pids map 不存在，跳过"); return Ok(()); }
        };
        let mut arr: Array<_, u32> = Array::try_from(map)?;
        arr.set(0, pid, 0)?;
        info!("[EbpfBackend] ✅ agent_pids[0] = {} (agent PID 已写入，自保规则将放行本进程)", pid);
        Ok(())
    }

    /// 启用/禁用 eBPF 模块的 feature_switches
    /// feature_idx: 0=FILE, 1=PROC, 2=NET
    pub fn enable_feature(bpf: &mut Bpf, feature_idx: u32, enabled: bool) -> anyhow::Result<()> {
        let map = match bpf.map_mut("feature_switches") {
            Some(m) => m,
            None => {
                info!("[EbpfBackend] feature_switches map 不存在，跳过 enable({})", feature_idx);
                return Ok(());
            }
        };
        let mut arr: Array<_, u8> = Array::try_from(map)?;
        let val: u8 = if enabled { 1 } else { 0 };
        arr.set(feature_idx, val, 0)?;
        info!("[EbpfBackend] ✅ feature_switches[{}] = {}", feature_idx, val);
        Ok(())
    }

    /// 添加受保护 PID（防 kill），用于扩展自保规则。
    /// pid: TGID 值
    pub fn add_protected_pid(bpf: &mut Bpf, pid: u32) -> anyhow::Result<()> {
        use aya::maps::HashMap;
        let map = match bpf.map_mut("protected_pids") {
            Some(m) => m,
            None => { info!("[EbpfBackend] protected_pids map 不存在，跳过"); return Ok(()); }
        };
        let mut hash: HashMap<_, u32, u8> = HashMap::try_from(map)?;
        let val: u8 = 1;
        hash.insert(pid, val, 0)?;
        info!("[EbpfBackend] ✅ protected_pids[{}] 已添加（防 kill）", pid);
        Ok(())
    }

    /// 移除受保护 PID
    pub fn remove_protected_pid(bpf: &mut Bpf, pid: u32) -> anyhow::Result<()> {
        use aya::maps::HashMap;
        let map = match bpf.map_mut("protected_pids") {
            Some(m) => m,
            None => { info!("[EbpfBackend] protected_pids map 不存在，跳过"); return Ok(()); }
        };
        let mut hash: HashMap<_, u32, u8> = HashMap::try_from(map)?;
        hash.remove(&pid)?;
        info!("[EbpfBackend] ✅ protected_pids[{}] 已移除", pid);
        Ok(())
    }

    /// 检测 /sys/fs/cgroup 是否为 cgroup v2 (unified hierarchy)
    /// cgroup v2 的 magic number 是 0x63677270 ("cgrp")，
    /// 通过 statfs 的 f_type 字段来判断
    fn is_cgroup_v2(path: &str) -> bool {
        let fd = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };
        use std::os::unix::io::AsRawFd;
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::fstatfs(fd.as_raw_fd(), &mut stat) };
        if ret != 0 {
            return false;
        }
        // CGROUP2_SUPER_MAGIC = 0x63677270
        stat.f_type == 0x63677270
    }
}
