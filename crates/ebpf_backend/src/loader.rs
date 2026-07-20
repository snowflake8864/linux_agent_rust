use aya::programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya::{Bpf, BpfLoader};
use log::info;

/// 多模块 eBPF 加载器 — 按功能独立加载 .o 文件
pub struct ModularLoader {
    pub file_bpf: Option<Bpf>,
    pub proc_bpf: Option<Bpf>,
    pub net_bpf: Option<Bpf>,
}

impl ModularLoader {
    pub fn new() -> Self {
        Self {
            file_bpf: None,
            proc_bpf: None,
            net_bpf: None,
        }
    }

    pub fn load_file_agent(&mut self, path: &str) -> anyhow::Result<()> {
        info!("[EbpfBackend] Loading file_agent from: {}", path);
        let bpf = BpfLoader::new().load_file(path)?;
        self.file_bpf = Some(bpf);
        Ok(())
    }

    pub fn load_proc_agent(&mut self, path: &str) -> anyhow::Result<()> {
        info!("[EbpfBackend] Loading proc_agent from: {}", path);
        let bpf = BpfLoader::new().load_file(path)?;
        self.proc_bpf = Some(bpf);
        Ok(())
    }

    pub fn load_net_agent(&mut self, path: &str) -> anyhow::Result<()> {
        info!("[EbpfBackend] Loading net_agent from: {}", path);
        let bpf = BpfLoader::new().load_file(path)?;
        self.net_bpf = Some(bpf);
        Ok(())
    }

    /// 挂载文件管控 eBPF 程序 (LSM hooks)
    pub fn attach_file_programs(&mut self) -> anyhow::Result<()> {
        use aya::programs::{KProbe, Lsm};
        use aya::Btf;

        let btf = Btf::from_sys_fs()?;
        let bpf = self
            .file_bpf
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("File agent not loaded"))?;

        if let Some(prog) = bpf.program_mut("enforce_file_open") {
            let lsm: &mut Lsm = prog.try_into()?;
            lsm.load("file_open", &btf)?;
            lsm.attach()?;
            info!("[EbpfBackend] Attached LSM: file_open");
        }

        if let Some(prog) = bpf.program_mut("enforce_inode_create") {
            let lsm: &mut Lsm = prog.try_into()?;
            lsm.load("inode_create", &btf)?;
            lsm.attach()?;
            info!("[EbpfBackend] Attached LSM: inode_create");
        }

        if let Some(prog) = bpf.program_mut("enforce_inode_unlink") {
            let lsm: &mut Lsm = prog.try_into()?;
            lsm.load("inode_unlink", &btf)?;
            lsm.attach()?;
            info!("[EbpfBackend] Attached LSM: inode_unlink");
        }

        if let Some(prog) = bpf.program_mut("enforce_vfs_mkdir") {
            let kprobe: &mut KProbe = prog.try_into()?;
            kprobe.load()?;
            kprobe.attach("vfs_mkdir", 0)?;
            info!("[EbpfBackend] Attached kprobe: vfs_mkdir");
        }

        Ok(())
    }

    /// 挂载进程管控 eBPF 程序 (LSM bprm_check_security)
    pub fn attach_proc_programs(&mut self) -> anyhow::Result<()> {
        use aya::programs::Lsm;
        use aya::Btf;

        let btf = Btf::from_sys_fs()?;
        let bpf = self
            .proc_bpf
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Proc agent not loaded"))?;

        if let Some(prog) = bpf.program_mut("enforce_bprm_check_security") {
            let lsm: &mut Lsm = prog.try_into()?;
            lsm.load("bprm_check_security", &btf)?;
            lsm.attach()?;
            info!("[EbpfBackend] Attached LSM: bprm_check_security");
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
            // XDP (ingress)
            for name in &["xdp_pkt_mod", "xdp_packet_filter"] {
                if let Some(prog) = bpf.program_mut(name) {
                    let xdp: &mut Xdp = prog.try_into()?;
                    xdp.load()?;
                    xdp.attach(interface, XdpFlags::default())?;
                    info!("[EbpfBackend] Attached XDP to {}", interface);
                    break;
                }
            }

            // TC egress (packet modification)
            if let Some(prog) = bpf.program_mut("tc_packet_filter") {
                let _ = std::process::Command::new("tc")
                    .args(["qdisc", "add", "dev", interface, "clsact"])
                    .output();
                let tc: &mut SchedClassifier = prog.try_into()?;
                tc.load()?;
                tc.attach(interface, TcAttachType::Egress)?;
                info!("[EbpfBackend] Attached TC Egress to {}", interface);
            }
        }

        // Cgroup connect4 hook (本地连接拦截)
        if let Some(prog) = bpf.program_mut("enforce_connect4") {
            let cgroup_fd = std::fs::File::open("/sys/fs/cgroup")?;
            let program: &mut aya::programs::CgroupSockAddr = prog.try_into()?;
            program.load()?;
            program.attach(cgroup_fd)?;
            info!("[EbpfBackend] Attached Cgroup Connect hook");
        }

        Ok(())
    }

    pub fn file_bpf_mut(&mut self) -> Option<&mut Bpf> {
        self.file_bpf.as_mut()
    }

    pub fn proc_bpf_mut(&mut self) -> Option<&mut Bpf> {
        self.proc_bpf.as_mut()
    }

    pub fn net_bpf_mut(&mut self) -> Option<&mut Bpf> {
        self.net_bpf.as_mut()
    }
}
