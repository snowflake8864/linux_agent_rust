
//crate/reporter/src/netlink_msg.rs 
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NetlinkNetlog {
    pub start_idx: u32,
    pub end_idx: u32,
    pub max_idx: u32,
}
