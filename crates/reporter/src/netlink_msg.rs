
//crate/reporter/src/netlink_msg.rs 
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NetlinkNetlog {
    pub start_idx: i32,
    pub end_idx: i32,
    pub max_idx: i32,
}
