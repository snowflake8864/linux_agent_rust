// udisk/src/list.rs
use crate::device::UsbInfo;
use std::collections::HashSet;
use std::sync::Mutex;
use std::sync::Arc;
use logging::log_info;
#[derive(Debug, Clone, PartialEq)]
pub enum DeviceListStatus {
    InWhitelist,
    InBlacklist,
    NotInAnyList,
}

#[derive(Debug, Clone)]
pub struct BlackWhiteList {
    pub blacklist: Vec<UsbInfo>,
    pub whitelist: Vec<UsbInfo>,
    black_eids: HashSet<String>,
    white_eids: HashSet<String>,
}

impl BlackWhiteList {
    pub fn new() -> Self {
        Self {
            blacklist: vec![],
            whitelist: vec![],
            black_eids: HashSet::new(),
            white_eids: HashSet::new(),
        }
    }
    pub fn from_vecs(black: Vec<UsbInfo>, white: Vec<UsbInfo>) -> Self {
        let black_eids = black.iter().map(|u| u.perpheral_eid.clone()).collect();
        let white_eids = white.iter().map(|u| u.perpheral_eid.clone()).collect();

        Self {
            blacklist: black,
            whitelist: white,
            black_eids,
            white_eids,
        }
    }

    pub fn get_device_list_status(&self, eid: &str) -> DeviceListStatus {
        if self.black_eids.contains(eid) {
            DeviceListStatus::InBlacklist
        } else if self.white_eids.contains(eid) {
            DeviceListStatus::InWhitelist
        } else {
            DeviceListStatus::NotInAnyList
        }
    }

    // 权限判断
    pub fn is_allowed(&self, eid: &str) -> bool {
        if self.black_eids.contains(eid) {
            return false;
        }
        if self.white_eids.is_empty() {
            return true;
        }
        self.white_eids.contains(eid)
    }

    pub fn get_whitelist(&self) -> &Vec<UsbInfo> {
        &self.whitelist
    }

    pub fn get_blacklist(&self) -> &Vec<UsbInfo> {
        &self.blacklist
    }



    pub fn update_whitelist(&mut self, new_whitelist: Vec<UsbInfo>) {
        let new_white_eids: HashSet<String> = new_whitelist.iter().map(|u| u.perpheral_eid.clone()).collect();

        // 从黑名单中移除也出现在白名单中的设备
        self.blacklist.retain(|u| !new_white_eids.contains(&u.perpheral_eid));
        self.black_eids = self.blacklist.iter().map(|u| u.perpheral_eid.clone()).collect();

        // 更新白名单
        self.whitelist = new_whitelist;
        self.white_eids = new_white_eids;
    }

    pub fn update_blacklist(&mut self, new_blacklist: Vec<UsbInfo>, usb_protect: bool) {
        let new_black_eids: HashSet<String> = new_blacklist.iter().map(|u| u.perpheral_eid.clone()).collect();

        // 找出新增的黑名单设备（原来不在黑名单中的）
        let added_to_blacklist: Vec<String> = new_black_eids
            .difference(&self.black_eids)
            .cloned()
            .collect();

        // 从白名单中移除也出现在黑名单中的设备（黑名单优先）
        self.whitelist.retain(|u| !new_black_eids.contains(&u.perpheral_eid));
        self.white_eids = self.whitelist.iter().map(|u| u.perpheral_eid.clone()).collect();

        // 更新黑名单
        self.blacklist = new_blacklist;
        self.black_eids = new_black_eids;

        // 禁用新增黑名单设备
        if !added_to_blacklist.is_empty() {
            log_info!("检测到 {} 个新增黑名单设备，尝试禁用...", added_to_blacklist.len());
            let blacklist_clone = added_to_blacklist.clone();
            std::thread::spawn(move || {
                crate::monitor::handle_blacklist_update(&blacklist_clone);
            });
        }
    }

    /// Remove devices from both whitelist and blacklist (action=0).
    pub fn remove_from_both(&mut self, eids: &[String]) {
        let remove_set: HashSet<&str> = eids.iter().map(|s| s.as_str()).collect();
        self.whitelist.retain(|u| !remove_set.contains(u.perpheral_eid.as_str()));
        self.blacklist.retain(|u| !remove_set.contains(u.perpheral_eid.as_str()));
        self.white_eids = self.whitelist.iter().map(|u| u.perpheral_eid.clone()).collect();
        self.black_eids = self.blacklist.iter().map(|u| u.perpheral_eid.clone()).collect();
    }

}

pub type SharedBlackWhiteList = Arc<Mutex<BlackWhiteList>>;

use once_cell::sync::Lazy;
pub static SHARED_USB_LIST: Lazy<SharedBlackWhiteList> = Lazy::new(|| Arc::new(Mutex::new(BlackWhiteList::new())));
