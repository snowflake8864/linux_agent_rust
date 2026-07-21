//! eBPF BPF map 键/值类型（与内核 eBPF 程序 struct 布局一致）

// --- 文件管控 ---
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DirKey {
    pub dev: u64,
    pub inode: u64,
}

unsafe impl aya::Pod for DirKey {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DirPolicy {
    pub ops_mask: u8,
    pub action: u8,
    pub mode: u8,
    pub recursive: u8,
    pub filter_type: u8,
    pub suffix_count: u8,
    pub reserved: [u8; 2],
    pub suffixes: [[u8; 8]; 8],
    pub exact_filename: [u8; 32],
}

unsafe impl aya::Pod for DirPolicy {}

impl Default for DirPolicy {
    fn default() -> Self {
        Self {
            ops_mask: 0,
            action: 0,
            mode: 0,
            recursive: 0,
            filter_type: 0,
            suffix_count: 0,
            reserved: [0; 2],
            suffixes: [[0u8; 8]; 8],
            exact_filename: [0u8; 32],
        }
    }
}

// --- 进程管控 ---
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcKey {
    pub dev: u64,
    pub inode: u64,
}

unsafe impl aya::Pod for ProcKey {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcRuleVal {
    pub action: u8, // 0=allow, 1=deny
    pub mode: u8,   // 0=inherit, 1=monitor, 2=protect
    pub reserved: [u8; 6],
}

unsafe impl aya::Pod for ProcRuleVal {}

// --- 网络管控 ---
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PktModKey {
    pub protocol: u8,   // 6=TCP, 17=UDP
    pub direction: u8,  // 0=any, 1=ingress, 2=egress
    pub padding: [u8; 2],
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

unsafe impl aya::Pod for PktModKey {}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PktModValue {
    pub tcp_flags_enable: u8,
    pub tcp_set_ecn_echo: u8,
    pub tcp_set_cwr: u8,
    pub tcp_set_reserved: u8,
    pub tcp_flags_mask: u8,
    pub tcp_flags_value: u8,
    pub reserved_bits_mask: u8,
    pub reserved_bits_value: u8,
    pub port_mod_enable: u8,
    pub new_src_port: u16,
    pub new_dst_port: u16,
    pub ip_mod_enable: u8,
    pub new_src_ip: u32,
    pub new_dst_ip: u32,
    pub allowed_ip: u32,
    pub allowed_mask: u32,
    pub padding: [u8; 3],
}

unsafe impl aya::Pod for PktModValue {}

// --- 进程事件 ring buffer (匹配 eBPF C struct unified_event) ---
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UnifiedEvent {
    pub event_type: u8,           // __u8 type; 2=EVENT_PROC
    pub pid: u32,                 // __u32 pid
    pub uid: u32,                 // __u32 uid
    pub blocked: u8,              // __u8 blocked; 1=被拦截, 0=仅监控
    pub comm: [u8; 16],           // char comm[16]
    pub path: [u8; 64],           // char path[64]
    pub _padding: [u8; 2],        // pad to 90 bytes (1+4+4+1+16+64=90)
}

unsafe impl aya::Pod for UnifiedEvent {}

impl Default for PktModValue {
    fn default() -> Self {
        Self {
            tcp_flags_enable: 0,
            tcp_set_ecn_echo: 0,
            tcp_set_cwr: 0,
            tcp_set_reserved: 0,
            tcp_flags_mask: 0,
            tcp_flags_value: 0,
            reserved_bits_mask: 0,
            reserved_bits_value: 0,
            port_mod_enable: 0,
            new_src_port: 0,
            new_dst_port: 0,
            ip_mod_enable: 0,
            new_src_ip: 0,
            new_dst_ip: 0,
            allowed_ip: 0,
            allowed_mask: 0,
            padding: [0; 3],
        }
    }
}
