//crates/common/src/lib.rs
use std::sync::{Arc, Mutex};
use arc_swap::ArcSwap;
//use libc::{sockaddr_nl};
use config::net_info;
use pattern::pattern_rules_mgr;
pub mod manager;

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
    //pub pattern_mgr : pattern_rules_mgr::PatternRulesMgr ,
    pub pattern_mgr: Arc<Mutex<pattern_rules_mgr::PatternRulesMgr>>,
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
/*
impl Default for Inner {
    fn default() -> Self {
        Self {
            shared_core: ArcSwap::from_pointee(Core {
                netclient: NetClient {
                    token: None,
                    base_url: String::new(),
                },
                is_online: false,
                pattern_mgr: Arc::new(Mutex::new(pattern::PatternRulesMgr::new())),
            }),
        }
    }
}
*/
