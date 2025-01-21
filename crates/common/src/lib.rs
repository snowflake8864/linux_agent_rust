//crates/common/src/lib.rs
use arc_swap::ArcSwap;
//use libc::{sockaddr_nl};
use config::net_info;
pub mod manager;

/*
const NETLINK_USER: i32 = 21;

pub struct NlSockInfo {
    pub sock: i32,
    pub dest_addr: sockaddr_nl,
    pub src_addr: sockaddr_nl,
}
*/

#[derive(Debug, Default, Clone)]
pub struct NetClient {
    pub token: Option<String>,
    pub base_url: String,
}

#[derive(Clone, Default)]
pub struct Core {
    pub netclient: NetClient,
    pub netinfocfg: net_info::NetInfoConfig,
    pub is_online: bool,
    //pub nl_sock: NlSockInfo,
}

pub struct Inner {
    pub shared_core: ArcSwap<Core>,
}

#[allow(clippy::derivable_impls)]
impl Default for Inner {
    fn default() -> Self {
        Self {
            shared_core: Default::default(),
        }
    }
}

