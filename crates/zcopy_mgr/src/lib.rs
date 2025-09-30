//crate/zcopy_mgr/src/lib.rs
use libc::{c_void, mmap, munmap, MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE};
use logging::{log_info, log_error};
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::{close, read, sysconf, SysconfVar};
use std::ffi::CStr;
use std::fmt;
use std::fs::{read_dir, File};
use std::io::{self, Read};
use std::os::unix::io::RawFd;
use std::path::Path;
use std::ptr;
use std::net::{Ipv4Addr, Ipv6Addr};
// 常量定义
const UIO_BASE_PATH: &str = "/sys/class/uio/";
const UIO_DEV_PREFIX: &str = "/dev/uio";
const FILE_AUDIT_DATA_COUNT: usize = 4096;
const MAX_PROCESS_PATH: usize = 512;

// 结构体定义
#[repr(C)]
pub struct OsecNetworkReport {
    pub src: IpAddrUnion,
    pub src_port: u16,
    pub dst: IpAddrUnion,
    pub dest_port: u16,
    pub pid: u32,
    pub comm: [u8; 128],
}

#[repr(C)]
pub struct OsecOpenportReport {
    pub type_: u32,
    pub src_ip: IpAddrUnion,
    pub src_port: u16,
    pub dest_ip: IpAddrUnion,
    pub attack_dest_ip: IpAddrUnion,
    pub dest_port: u16,
    pub pid: u32,
    pub comm: [u8; 128],
}
impl OsecOpenportReport {
    /// 判断 src_ip 是否为 IPv4（通过 IPv4-mapped IPv6 格式识别）
    pub unsafe fn src_is_ipv4(&self) -> bool {
        self.is_ipv4_mapped(&self.src_ip)
    }

    /// 判断任意 IpAddrUnion 是否为 IPv4-mapped IPv6
    unsafe fn is_ipv4_mapped(&self, ip: &IpAddrUnion) -> bool {
        let bytes = &ip.as_u8;
        // IPv4-mapped IPv6: ::ffff:0.0.0.0 格式
        bytes[0..12] == [0u8; 12] && bytes[12] == 0 && bytes[13] == 0 && bytes[14] == 0 && bytes[15] == 0
            || (bytes[0..10] == [0u8; 10] && bytes[10] == 0xFF && bytes[11] == 0xFF)
    }

    /// 提取 IPv4 地址，失败返回 0.0.0.0
    pub unsafe fn extract_ipv4(&self, ip: &IpAddrUnion) -> Ipv4Addr {
        if self.is_ipv4_mapped(ip) {
            // 从 as_u8 的最后 4 字节提取
            Ipv4Addr::new(ip.as_u8[12], ip.as_u8[13], ip.as_u8[14], ip.as_u8[15])
        } else {
            Ipv4Addr::UNSPECIFIED // 0.0.0.0
        }
    }

    /// 提取 IPv6 地址
    pub unsafe fn extract_ipv6(&self, ip: &IpAddrUnion) -> Ipv6Addr {
        Ipv6Addr::new(
            u16::from_be(ip.v6[0]),
            u16::from_be(ip.v6[1]),
            u16::from_be(ip.v6[2]),
            u16::from_be(ip.v6[3]),
            u16::from_be(ip.v6[4]),
            u16::from_be(ip.v6[5]),
            u16::from_be(ip.v6[6]),
            u16::from_be(ip.v6[7]),
        )
    }

    /// 安全获取 comm 字段（C 字符串转 Rust String）
    pub unsafe fn get_comm(&self) -> String {
        let len = self.comm.iter().position(|&c| c == 0).unwrap_or(128);
        String::from_utf8_lossy(&self.comm[..len]).to_string()
    }
}

#[repr(C)]
pub struct OsecDnsReport {
    type_: u32,
    src_ip: u32,
    src_port: u16,
    dest_ip: u32,
    dest_port: u16,
    pid: u32,
    comm: [u8; 128],
    is_ipv6: u8, // 位字段：is_ipv6 占 1 位，ip_cnt 占 4 位
    ip_cnt: u8,
    ip_addrs: IpAddrArrayUnion,
    dns_name: [u8; 255],
}

/*
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AvProcessInfo {
    pub pid: i32,
    pub ppid: i32,
    pub uid: i32,
    pub type_: i32,
    pub flags: u32, // 合并 is_dir, deny, param_pos, level, is_monitor_mode
    pub timestamp: u64,
    pub path: [u8; MAX_PROCESS_PATH],
}

// 拆解后的 flags 字段结构体
#[derive(Debug)]
pub struct AvProcessFlags {
    pub is_dir: u8,
    pub deny: u8,
    pub param_pos: u16,
    pub level: u8,
    pub is_monitor_mode: u8,
}

impl From<u32> for AvProcessFlags {
    fn from(flags: u32) -> Self {
        AvProcessFlags {
            is_dir:           ((flags >> 0) & 0b0000_0111) as u8,
            deny:             ((flags >> 3) & 0b0000_0111) as u8,
            param_pos:        ((flags >> 6) & 0b0000_0011_1111_1111) as u16,
            level:            ((flags >> 16) & 0b0000_0111) as u8,
            is_monitor_mode:  ((flags >> 19) & 0b0000_0011) as u8,
        }
    }
}

impl AvProcessInfo {
    /// 提取位字段结构体
    pub fn flags_parsed(&self) -> AvProcessFlags {
        self.flags.into()
    }

    /// 获取单个字段方法（你可以在业务代码中直接调用）
    pub fn is_dir(&self) -> u8 {
        self.flags_parsed().is_dir
    }

    pub fn deny(&self) -> u8 {
        self.flags_parsed().deny
    }

    pub fn param_pos(&self) -> u16 {
        self.flags_parsed().param_pos
    }

    pub fn level(&self) -> u8 {
        self.flags_parsed().level
    }

    pub fn is_monitor_mode(&self) -> u8 {
        self.flags_parsed().is_monitor_mode
    }

    /// 安全解析路径为字符串
    pub fn get_path_str(&self) -> Option<String> {
        let ptr = self.path.as_ptr();
        unsafe {
            //CStr::from_ptr(ptr as *const u8)
            CStr::from_ptr(ptr as *const std::os::raw::c_char)
                .to_str()
                .ok()
                .map(|s| s.to_string())
        }
    }
}

*/


#[repr(C)]
#[derive(Clone, Copy)]
pub struct AvProcessInfo {
    // 私有字段：承载 union { struct { pid, ppid, uid, unused }; uint8_t md5[16]; }
    _union_data: [u8; 16],

    pub type_: i32,

    pub flags: u32,

    // 路径（512 字节）
    pub path: [u8; MAX_PROCESS_PATH],
}

// 编译时断言：确保 Rust 结构体大小与内核一致
// 内核布局：16 (union) + 2 (type)  + 4 (flags) + 512 (path) = 534
const _: () = assert!(std::mem::size_of::<AvProcessInfo>() == 536);

// 位字段解析结构体
#[derive(Debug)]
pub struct AvProcessFlags {
    pub is_dir: u8,
    pub deny: u8,
    pub param_pos: u16,
    pub level: u8,
    pub is_monitor_mode: u8,
    pub is_docker_process: bool, // 新增字段
}

impl From<u32> for AvProcessFlags {
    fn from(flags: u32) -> Self {
        AvProcessFlags {
            is_dir: ((flags >> 0) & 0b111) as u8,
            deny: ((flags >> 3) & 0b111) as u8,
            param_pos: ((flags >> 6) & 0b11_1111_1111) as u16,
            level: ((flags >> 16) & 0b111) as u8,
            is_monitor_mode: ((flags >> 19) & 0b11) as u8,
            is_docker_process: ((flags >> 21) & 1) != 0,
        }
    }
}

impl AvProcessInfo {
    // === 以下方法与你旧代码完全一致，无需任何修改 ===

    /// 获取进程 ID（与旧版完全兼容）
    pub fn pid(&self) -> i32 {
        let data = unsafe {
            std::ptr::read_unaligned(self._union_data.as_ptr() as *const [i32; 4])
        };
        data[0]
    }

    /// 获取父进程 ID（与旧版完全兼容）
    pub fn ppid(&self) -> i32 {
        let data = unsafe {
            std::ptr::read_unaligned(self._union_data.as_ptr() as *const [i32; 4])
        };
        data[1]
    }

    /// 获取用户 ID（与旧版完全兼容）
    pub fn uid(&self) -> i32 {
        let data = unsafe {
            std::ptr::read_unaligned(self._union_data.as_ptr() as *const [i32; 4])
        };
        data[2]
    }

    // === 位字段解析方法（新增 is_docker_process，其余不变）===

    pub fn flags_parsed(&self) -> AvProcessFlags {
        self.flags.into()
    }

    pub fn is_dir(&self) -> u8 {
        self.flags_parsed().is_dir
    }

    pub fn deny(&self) -> u8 {
        self.flags_parsed().deny
    }

    pub fn param_pos(&self) -> u16 {
        self.flags_parsed().param_pos
    }

    pub fn level(&self) -> u8 {
        self.flags_parsed().level
    }

    pub fn is_monitor_mode(&self) -> u8 {
        self.flags_parsed().is_monitor_mode
    }

    /// 新增：是否为 Docker 进程
    pub fn is_docker_process(&self) -> bool {
        self.flags_parsed().is_docker_process
    }


    /// 获取 MD5 哈希值（16 字节）
    pub fn md5(&self) -> [u8; 16] {
        self._union_data
    }


    /// 安全地将路径解析为字符串
    pub fn get_path_str(&self) -> Option<String> {
        unsafe {
            CStr::from_ptr(self.path.as_ptr() as *const std::os::raw::c_char)
                .to_str()
                .ok()
                .map(|s| s.to_string())
        }
    }
}


use std::mem::{size_of, offset_of};

impl fmt::Debug for AvProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 获取布局信息
        let struct_size = size_of::<AvProcessInfo>();
        let path_offset = offset_of!(AvProcessInfo, path);
        let flags_raw = self.flags;
        let flags_hex = format!("{:#010x}", flags_raw);
        let parsed = self.flags_parsed();

        // 安全解析 path
        let path_str = unsafe {
            std::ffi::CStr::from_ptr(self.path.as_ptr() as *const std::os::raw::c_char)
                .to_string_lossy()
                .into_owned()
        };

        f.debug_struct("AvProcessInfo")
            .field("layout", &format!("size={}, path_offset={}", struct_size, path_offset))
            .field("pid", &self.pid())
            .field("ppid", &self.ppid())
            .field("uid", &self.uid())
            .field("type_", &self.type_)
            .field("flags (raw)", &flags_raw)
            .field("flags (hex)", &flags_hex)
            .field("is_dir", &parsed.is_dir)
            .field("deny", &parsed.deny)
            .field("param_pos", &parsed.param_pos)
            .field("level", &parsed.level)
            .field("is_monitor_mode", &parsed.is_monitor_mode)
            .field("is_docker_process", &parsed.is_docker_process)
            .field("path", &path_str)
            .field("path[0..10] (hex)", &&self.path[0..10])
            .finish()
    }
}
/*
impl fmt::Debug for AvProcessInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 安全地将 path 转为字符串用于调试
        let path_str = unsafe {
            std::ffi::CStr::from_ptr(self.path.as_ptr() as *const std::os::raw::c_char)
                .to_string_lossy()
                .into_owned()
        };

        f.debug_struct("AvProcessInfo")
            .field("pid", &self.pid())
            .field("ppid", &self.ppid())
            .field("uid", &self.uid())
            .field("type_", &self.type_)
            .field("flags", &self.flags)
            .field("is_docker_process", &self.is_docker_process())
            .field("path", &path_str)
            .finish()
    }
}
*/
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AvFileInfo {
    pid: i32,
    ppid: i32,
    uid: i32,
    pub comm: [u8; 128],
    pub comm_p: [u8; 16],
    pub path: [u8; 512],
    pub dst_path: [u8; 512],
    pub log_type: u16,
    pub flags: u16, // 合并 is_dir, type, rules_type, log_level
}

#[repr(C)]
pub struct SymbolMsg {
    sym_addr: i64,
    name: [u8; 0], // 变长数组
}

// IP 地址联合体
#[repr(C)]
pub union IpAddrUnion {
    pub v4: std::mem::ManuallyDrop<IpV4Addr>,
    pub v6: [u16; 8],
    pub as_u8: [u8; 16],
    pub as_u64: [u64; 2],
}

// 手动实现 Debug for IpAddrUnion
impl fmt::Debug for IpAddrUnion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            f.debug_struct("IpAddrUnion")
                .field("as_u8", &self.as_u8)
                .finish()
        }
    }
}

#[repr(C)]
pub struct IpV4Addr {
    pub pad: [u32; 3],
    pub ip4: u32,
}

impl fmt::Debug for IpV4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpV4Addr")
            .field("pad", &self.pad)
            .field("ip4", &self.ip4)
            .finish()
    }
}

#[repr(C)]
pub union IpAddrArrayUnion {
    ipv4: [u32; 12],
    ipv6: [u8; 48],
}

// 手动实现 Debug for IpAddrArrayUnion
impl fmt::Debug for IpAddrArrayUnion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            f.debug_struct("IpAddrArrayUnion")
                .field("ipv4", &self.ipv4)
                .finish()
        }
    }
}

// 为包含联合体的结构体实现 Debug
impl fmt::Debug for OsecNetworkReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OsecNetworkReport")
            .field("src", &self.src)
            .field("src_port", &self.src_port)
            .field("dst", &self.dst)
            .field("dest_port", &self.dest_port)
            .field("pid", &self.pid)
            .field("comm", &self.comm)
            .finish()
    }
}
/*
impl fmt::Debug for OsecOpenportReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OsecOpenportReport")
            .field("type_", &self.type_)
            .field("src_ip", &self.src_ip)
            .field("src_port", &self.src_port)
            .field("dest_ip", &self.dest_ip)
            .field("attack_dest_ip", &self.attack_dest_ip)
            .field("dest_port", &self.dest_port)
            .field("pid", &self.pid)
            .field("comm", &self.comm)
            .finish()
    }
}
*/
impl fmt::Debug for OsecOpenportReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let src_ip_str = if self.src_is_ipv4() {
                format!("{}", self.extract_ipv4(&self.src_ip))
            } else {
                format!("{}", self.extract_ipv6(&self.src_ip))
            };

            let dest_ip_str = if self.is_ipv4_mapped(&self.dest_ip) {
                format!("{}", self.extract_ipv4(&self.dest_ip))
            } else {
                format!("{}", self.extract_ipv6(&self.dest_ip))
            };

            let attack_dest_ip_str = if self.is_ipv4_mapped(&self.attack_dest_ip) {
                format!("{}", self.extract_ipv4(&self.attack_dest_ip))
            } else {
                format!("{}", self.extract_ipv6(&self.attack_dest_ip))
            };

            let comm_str = {
                let len = self.comm.iter().position(|&c| c == 0).unwrap_or(128);
                String::from_utf8_lossy(&self.comm[..len])
            };

            f.debug_struct("OsecOpenportReport")
                .field("type_", &self.type_)
                .field("src_ip", &src_ip_str)
                .field("src_port", &self.src_port)
                .field("dest_ip", &dest_ip_str)
                .field("attack_dest_ip", &attack_dest_ip_str)
                .field("dest_port", &self.dest_port)
                .field("pid", &self.pid)
                .field("comm", &comm_str)
                .finish()
        }
    }
}

impl fmt::Debug for OsecDnsReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OsecDnsReport")
            .field("type_", &self.type_)
            .field("src_ip", &self.src_ip)
            .field("src_port", &self.src_port)
            .field("dest_ip", &self.dest_ip)
            .field("dest_port", &self.dest_port)
            .field("pid", &self.pid)
            .field("comm", &self.comm)
            .field("is_ipv6", &self.is_ipv6)
            .field("ip_cnt", &self.ip_cnt)
            .field("ip_addrs", &self.ip_addrs)
            .field("dns_name", &self.dns_name)
            .finish()
    }
}




impl fmt::Debug for AvFileInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AvFileInfo")
            .field("pid", &self.pid)
            .field("ppid", &self.ppid)
            .field("uid", &self.uid)
            .field("comm", &self.comm)
            .field("comm_p", &self.comm_p)
            .field("path", &self.path)
            .field("dst_path", &self.dst_path)
            .field("log_type", &self.log_type)
            .field("flags", &self.flags)
            .finish()
    }
}

pub struct ZcopyMgr {
    uio_fd: Option<RawFd>,
    in_netlog_audit_size: usize,
    in_netlog_audit_addr: *mut c_void,
    in_netlog_cir_buffer: *mut c_void,
    in_netlog_audit_total_count: usize,
    out_netlog_audit_size: usize,
    out_netlog_cir_buffer: *mut c_void,
    out_netlog_audit_total_count: usize,
    openport_netlog_audit_size: usize,
    openport_netlog_cir_buffer: *mut c_void,
    openport_netlog_audit_total_count: usize,
    dns_netlog_audit_size: usize,
    dns_netlog_cir_buffer: *mut c_void,
    dns_netlog_audit_total_count: usize,
    process_audit_size: usize,
    process_cir_buffer: *mut c_void,
    process_audit_total_count: usize,
    file_audit_size: usize,
    file_cir_buffer: *mut c_void,
    file_audit_total_count: usize,
    pub in_netlog_audit_succeed: bool,
    pub out_netlog_audit_succeed: bool,
    pub openport_netlog_audit_succeed: bool,
    pub dns_netlog_audit_succeed: bool,
    pub process_audit_succeed: bool,
    pub file_audit_succeed: bool,
}
/*
fn print_layout() {
    use std::mem::{offset_of, size_of};
    log_info!("sizeof(OsecNetworkReport): {}", size_of::<OsecNetworkReport>());
    log_info!("src offset: {}", offset_of!(OsecNetworkReport, src));
    log_info!("src_port offset: {}", offset_of!(OsecNetworkReport, src_port));
    log_info!("dst offset: {}", offset_of!(OsecNetworkReport, dst));
    log_info!("dest_port offset: {}", offset_of!(OsecNetworkReport, dest_port));
    log_info!("pid offset: {}", offset_of!(OsecNetworkReport, pid));
    log_info!("comm offset: {}", offset_of!(OsecNetworkReport, comm));
}
*/
fn print_layout() {
    use std::mem::{offset_of, size_of};
    log_info!("sizeof(AvFileInfo): {}", size_of::<AvFileInfo>());
    log_info!("pid offset: {}", offset_of!(AvFileInfo, pid));
    log_info!("ppid offset: {}", offset_of!(AvFileInfo, ppid));
    log_info!("uid offset: {}", offset_of!(AvFileInfo, uid));
    log_info!("comm offset: {}", offset_of!(AvFileInfo, comm));
    log_info!("comm_p offset: {}", offset_of!(AvFileInfo, comm_p));
    log_info!("path offset: {}", offset_of!(AvFileInfo, path));
    log_info!("dst_path offset: {}", offset_of!(AvFileInfo, dst_path));
    log_info!("log_type offset: {}", offset_of!(AvFileInfo, log_type));
    log_info!("flags offset: {}", offset_of!(AvFileInfo, flags));
}
// 为 ZcopyMgr 实现 Send 和 Sync
unsafe impl Send for ZcopyMgr {}
unsafe impl Sync for ZcopyMgr {}

impl ZcopyMgr {
    pub fn new() -> io::Result<Self> {
        let mut mgr = ZcopyMgr {
            uio_fd: None,
            in_netlog_audit_size: 0,
            in_netlog_audit_addr: ptr::null_mut(),
            in_netlog_cir_buffer: ptr::null_mut(),
            in_netlog_audit_total_count: 0,
            out_netlog_audit_size: 0,
            out_netlog_cir_buffer: ptr::null_mut(),
            out_netlog_audit_total_count: 0,
            openport_netlog_audit_size: 0,
            openport_netlog_cir_buffer: ptr::null_mut(),
            openport_netlog_audit_total_count: 0,
            dns_netlog_audit_size: 0,
            dns_netlog_cir_buffer: ptr::null_mut(),
            dns_netlog_audit_total_count: 0,
            process_audit_size: 0,
            process_cir_buffer: ptr::null_mut(),
            process_audit_total_count: 0,
            file_audit_size: 0,
            file_cir_buffer: ptr::null_mut(),
            file_audit_total_count: 0,
            in_netlog_audit_succeed: false,
            out_netlog_audit_succeed: false,
            openport_netlog_audit_succeed: false,
            dns_netlog_audit_succeed: false,
            process_audit_succeed: false,
            file_audit_succeed: false,
        };
        //print_layout();
        // 查找 UIO 设备
        let uio_dev = find_uio_device("uio_zcopy")?;
        let uio_fd = open(Path::new(&uio_dev), OFlag::O_RDWR, Mode::empty())?;
        mgr.uio_fd = Some(uio_fd);

        // 获取页面大小
        let page_size = sysconf(SysconfVar::PAGE_SIZE)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to get page size"))? as usize;

        // 构造 UIO 路径
        let uio_sys_path = format!("/sys/class/uio/uio{}/maps/", uio_dev.trim_start_matches(UIO_DEV_PREFIX));

        // 处理 in_netlog
        mgr.map_buffer(&uio_sys_path, "map0", 0, |size| {
            size / std::mem::size_of::<OsecNetworkReport>() / 2
        })?;

        // out_netlog 与 in_netlog 共享缓冲区
        if mgr.in_netlog_audit_succeed {
            mgr.out_netlog_audit_total_count = mgr.in_netlog_audit_total_count;
            mgr.out_netlog_cir_buffer = unsafe {
                mgr.in_netlog_cir_buffer.add(mgr.in_netlog_audit_total_count * std::mem::size_of::<OsecNetworkReport>())
            };
            mgr.out_netlog_audit_succeed = true;
        }

        // 处理 openport_netlog
        mgr.map_buffer(&uio_sys_path, "map1", page_size, |size| {
            size / std::mem::size_of::<OsecOpenportReport>()
        })?;

        // 处理 dns_netlog
        mgr.map_buffer(&uio_sys_path, "map2", 2 * page_size, |size| {
            size / std::mem::size_of::<OsecDnsReport>()
        })?;

        // 处理 process_audit
        mgr.map_buffer(&uio_sys_path, "map3", 3 * page_size, |size| {
            size / std::mem::size_of::<AvProcessInfo>()
        })?;

        // 处理 file_audit
        mgr.map_buffer(&uio_sys_path, "map4", 4 * page_size, |size| {
            size / std::mem::size_of::<AvFileInfo>()
        })?;

        Ok(mgr)
    }

    fn map_buffer<F>(
        &mut self,
        uio_sys_path: &str,
        map_name: &str,
        offset: usize,
        count_calculator: F,
    ) -> io::Result<()>
    where
        F: Fn(usize) -> usize,
    {
        let addr_path = format!("{}/{}/addr", uio_sys_path, map_name);
        let size_path = format!("{}/{}/size", uio_sys_path, map_name);

        let addr_fd = open(Path::new(&addr_path), OFlag::O_RDONLY, Mode::empty())?;
        let size_fd = open(Path::new(&size_path), OFlag::O_RDONLY, Mode::empty())?;

        let mut addr_buf = [0u8; 32]; // 增加缓冲区大小
        let mut size_buf = [0u8; 32];

        let addr = read_addr(&addr_buf, addr_fd)?;
        let size = read_size(&size_buf, size_fd)?;

        let buffer = unsafe {
            mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                self.uio_fd.unwrap(),
                offset as libc::off_t,
            )
        };

        if buffer == MAP_FAILED {
            log_error!("Error mapping UIO device memory for {}", map_name);
            close(addr_fd)?;
            close(size_fd)?;
            return Err(io::Error::new(io::ErrorKind::Other, "mmap failed"));
        }

        match map_name {
            "map0" => {
                self.in_netlog_audit_size = size;
                self.in_netlog_audit_addr = addr;
                self.in_netlog_cir_buffer = buffer;
                self.in_netlog_audit_total_count = count_calculator(size);
                self.in_netlog_audit_succeed = true;
                log_info!("in_netlog_cir_buffer addr: {:?}, count: {}", buffer, self.in_netlog_audit_total_count);
            }
            "map1" => {
                self.openport_netlog_audit_size = size;
                self.openport_netlog_cir_buffer = buffer;
                self.openport_netlog_audit_total_count = count_calculator(size);
                self.openport_netlog_audit_succeed = true;
                log_info!("openport_netlog_cir_buffer addr: {:?}, count: {}", buffer, self.openport_netlog_audit_total_count);
            }
            "map2" => {
                self.dns_netlog_audit_size = size;
                self.dns_netlog_cir_buffer = buffer;
                self.dns_netlog_audit_total_count = count_calculator(size);
                self.dns_netlog_audit_succeed = true;
                log_info!("dns_netlog_cir_buffer addr: {:?}, count: {}", buffer, self.dns_netlog_audit_total_count);
            }
            "map3" => {
                self.process_audit_size = size;
                self.process_cir_buffer = buffer;
                self.process_audit_total_count = count_calculator(size);
                self.process_audit_succeed = true;
                log_info!("process_cir_buffer addr: {:?}, count: {}", buffer, self.process_audit_total_count);
            }
            "map4" => {
                self.file_audit_size = size;
                self.file_cir_buffer = buffer;
                self.file_audit_total_count = count_calculator(size);
                self.file_audit_succeed = true;
                log_info!("file_cir_buffer addr: {:?}, count: {}", buffer, self.file_audit_total_count);
            }
            _ => {}
        }

        close(addr_fd)?;
        close(size_fd)?;
        Ok(())
    }

    pub fn get_in_netlog_audit_data(&self, idx: usize) -> Option<&OsecNetworkReport> {
        if !self.in_netlog_audit_succeed || self.in_netlog_cir_buffer.is_null() {
            return None;
        }
        unsafe {
            let ptr = self.in_netlog_cir_buffer.add((idx % self.in_netlog_audit_total_count) * std::mem::size_of::<OsecNetworkReport>());
            Some(&*(ptr as *const OsecNetworkReport))
        }
    }

    pub fn get_out_netlog_audit_data(&self, idx: usize) -> Option<&OsecNetworkReport> {
        if !self.out_netlog_audit_succeed || self.out_netlog_cir_buffer.is_null() {
            return None;
        }
        unsafe {
            let ptr = self.out_netlog_cir_buffer.add((idx % self.out_netlog_audit_total_count) * std::mem::size_of::<OsecNetworkReport>());
            Some(&*(ptr as *const OsecNetworkReport))
        }
    }

    pub fn get_openport_log_audit_data(&self, idx: usize) -> Option<&OsecOpenportReport> {
        if !self.openport_netlog_audit_succeed || self.openport_netlog_cir_buffer.is_null() {
            return None;
        }
        unsafe {
            let ptr = self.openport_netlog_cir_buffer.add((idx % self.openport_netlog_audit_total_count) * std::mem::size_of::<OsecOpenportReport>());
            Some(&*(ptr as *const OsecOpenportReport))
        }
    }

    pub fn get_dns_log_audit_data(&self, idx: usize) -> Option<&OsecDnsReport> {
        if !self.dns_netlog_audit_succeed || self.dns_netlog_cir_buffer.is_null() {
            return None;
        }
        unsafe {
            let ptr = self.dns_netlog_cir_buffer.add((idx % self.dns_netlog_audit_total_count) * std::mem::size_of::<OsecDnsReport>());
            Some(&*(ptr as *const OsecDnsReport))
        }
    }

    pub fn get_process_audit_data(&self, idx: usize) -> Option<&AvProcessInfo> {
        if !self.process_audit_succeed || self.process_cir_buffer.is_null() {
            return None;
        }
        unsafe {
            let ptr = self.process_cir_buffer.add((idx % self.process_audit_total_count) * std::mem::size_of::<AvProcessInfo>());
            Some(&*(ptr as *const AvProcessInfo))
        }
    }

    pub fn get_file_audit_data(&self, idx: usize) -> Option<&AvFileInfo> {
        if !self.file_audit_succeed || self.file_cir_buffer.is_null() {
            return None;
        }
        unsafe {
            let ptr = self.file_cir_buffer.add((idx % self.file_audit_total_count) * std::mem::size_of::<AvFileInfo>());
            Some(&*(ptr as *const AvFileInfo))
        }
    }
}

impl Drop for ZcopyMgr {
    fn drop(&mut self) {
        unsafe {
            if self.in_netlog_cir_buffer != MAP_FAILED && !self.in_netlog_cir_buffer.is_null() {
                munmap(self.in_netlog_cir_buffer, self.in_netlog_audit_size);
            }
            if self.openport_netlog_cir_buffer != MAP_FAILED && !self.openport_netlog_cir_buffer.is_null() {
                munmap(self.openport_netlog_cir_buffer, self.openport_netlog_audit_size);
            }
            if self.dns_netlog_cir_buffer != MAP_FAILED && !self.dns_netlog_cir_buffer.is_null() {
                munmap(self.dns_netlog_cir_buffer, self.dns_netlog_audit_size);
            }
            if self.process_cir_buffer != MAP_FAILED && !self.process_cir_buffer.is_null() {
                munmap(self.process_cir_buffer, self.process_audit_size);
            }
            if self.file_cir_buffer != MAP_FAILED && !self.file_cir_buffer.is_null() {
                munmap(self.file_cir_buffer, self.file_audit_size);
            }
        }
        if let Some(fd) = self.uio_fd {
            let _ = close(fd);
        }
    }
}

fn find_uio_device(driver_name: &str) -> io::Result<String> {
    let dir = read_dir(UIO_BASE_PATH)?;
    for entry in dir {
        let entry = entry?;
        let name = entry.file_name().into_string().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "Invalid directory entry")
        })?;
        if !name.starts_with("uio") {
            continue;
        }

        let name_path = format!("{}/{}/name", UIO_BASE_PATH, name);
        let mut file = File::open(&name_path)?;
        let mut name_buf = String::new();
        file.read_to_string(&mut name_buf)?;
        let name_buf = name_buf.trim();

        if name_buf == driver_name {
            return Ok(format!("{}{}", UIO_DEV_PREFIX, name.trim_start_matches("uio")));
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, format!("UIO device for driver {} not found", driver_name)))
}

fn read_addr(buf: &[u8; 32], fd: RawFd) -> io::Result<*mut c_void> {
    let mut addr_buf = buf.to_vec();
    let nread = read(fd, &mut addr_buf)?;
    if nread == 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "Failed to read address"));
    }
    log_info!("Read address bytes: {:x?}, length: {}", &addr_buf[..nread], nread);

    // 解析地址字符串，去除换行符和空白
    let addr_str = std::str::from_utf8(&addr_buf[..nread])
        .map_err(|e| {
            log_error!("Invalid UTF-8 address: {:x?}, error: {}", &addr_buf[..nread], e);
            io::Error::new(io::ErrorKind::InvalidData, "Invalid address string")
        })?
        .trim();
    log_info!("Parsed address string: {}", addr_str);

    // 去除 "0x" 前缀并解析十六进制
    let addr_clean = addr_str.trim_start_matches("0x");
    let addr = u64::from_str_radix(addr_clean, 16)
        .map_err(|e| {
            log_error!("Invalid address format: {}, error: {}", addr_str, e);
            io::Error::new(io::ErrorKind::InvalidData, "Invalid address string")
        })?;
    log_info!("Converted address to u64: {:#x}", addr);

    Ok(addr as *mut c_void)
}

fn read_size(buf: &[u8; 32], fd: RawFd) -> io::Result<usize> {
    let mut size_buf = buf.to_vec();
    let nread = read(fd, &mut size_buf)?;
    if nread == 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "Failed to read size"));
    }
    log_info!("Read size bytes: {:x?}, length: {}", &size_buf[..nread], nread);

    // 解析大小字符串，去除换行符和空白
    let size_str = std::str::from_utf8(&size_buf[..nread])
        .map_err(|e| {
            log_error!("Invalid UTF-8 size: {:x?}, error: {}", &size_buf[..nread], e);
            io::Error::new(io::ErrorKind::InvalidData, "Invalid size string")
        })?
        .trim();
    log_info!("Parsed size string: {}", size_str);

    // 去除 "0x" 前缀并解析十六进制
    let size_clean = size_str.trim_start_matches("0x");
    let size = u64::from_str_radix(size_clean, 16)
        .map_err(|e| {
            log_error!("Invalid size format: {}, error: {}", size_str, e);
            io::Error::new(io::ErrorKind::InvalidData, "Invalid size string")
        })?;
    log_info!("Converted size to usize: {}", size);

    Ok(size as usize)
}
