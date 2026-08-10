// udisk/src/list.rs
use crate::device::UsbInfo;
use std::collections::{HashMap, HashSet};
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

        // 合并已有设备信息：保留旧的 name/intro/type，避免全量替换时覆盖为空
        let existing: HashMap<String, &UsbInfo> = self.whitelist.iter()
            .map(|u| (u.perpheral_eid.clone(), u))
            .collect();
        self.whitelist = new_whitelist.into_iter().map(|mut dev| {
            if let Some(old) = existing.get(&dev.perpheral_eid) {
                if dev.perpheral_name.is_empty() { dev.perpheral_name = old.perpheral_name.clone(); }
                if dev.intro.is_empty() { dev.intro = old.intro.clone(); }
                if dev.type_.is_empty() { dev.type_ = old.type_.clone(); }
                if !dev.allow { dev.allow = old.allow; }
            }
            dev
        }).collect();
        self.white_eids = new_white_eids;
    }

    /// usb_protect: 由调用方在外层锁前读取 NETINFO_CONFIG，避免锁顺序反转导致死锁
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

        // 合并已有设备信息：保留旧的 name/intro/type，避免全量替换时覆盖为空
        let existing: HashMap<String, &UsbInfo> = self.blacklist.iter()
            .map(|u| (u.perpheral_eid.clone(), u))
            .collect();
        self.blacklist = new_blacklist.into_iter().map(|mut dev| {
            if let Some(old) = existing.get(&dev.perpheral_eid) {
                if dev.perpheral_name.is_empty() { dev.perpheral_name = old.perpheral_name.clone(); }
                if dev.intro.is_empty() { dev.intro = old.intro.clone(); }
                if dev.type_.is_empty() { dev.type_ = old.type_.clone(); }
                if !dev.allow { dev.allow = old.allow; }
            }
            dev
        }).collect();
        self.black_eids = new_black_eids;

        // 禁用新增黑名单设备 — 已移除 sysfs 物理禁用逻辑
        // 原因：std::thread::spawn 写 /sys/.../authorized=0 会与 libusb 事件循环竞态，
        // 导致内核层卡死（handle_events 无法返回），进而 gRPC accept loop 阻塞，进程 Ctrl+C 也无法终止。
        // 黑名单策略层拦截已足够生效；若需物理禁用，由 device_arrived + usb_protect 在 libusb 上下文中安全完成。
        if !added_to_blacklist.is_empty() {
            log_info!(
                "检测到 {} 个新增黑名单设备，已加入策略（不执行物理禁用，避免 libusb 竞态卡死）",
                added_to_blacklist.len()
            );
        }
    }

    pub fn remove_from_both(&mut self, eids: &[String]) {
        let rm: HashSet<String> = eids.iter().cloned().collect();
        self.whitelist.retain(|u| !rm.contains(&u.perpheral_eid));
        self.blacklist.retain(|u| !rm.contains(&u.perpheral_eid));
        self.white_eids = self.whitelist.iter().map(|u| u.perpheral_eid.clone()).collect();
        self.black_eids = self.blacklist.iter().map(|u| u.perpheral_eid.clone()).collect();
    }

    /// Add a single device to whitelist (merging: blacklist takes priority).
    pub fn update_whitelist_single(&mut self, device: UsbInfo) {
        self.blacklist.retain(|d| d.perpheral_eid != device.perpheral_eid);
        self.black_eids.remove(&device.perpheral_eid);
        if !self.white_eids.contains(&device.perpheral_eid) {
            self.white_eids.insert(device.perpheral_eid.clone());
            self.whitelist.push(device);
        }
    }

    /// Add a single device to blacklist (merging: blacklist takes priority).
    pub fn update_blacklist_single(&mut self, device: UsbInfo) {
        self.whitelist.retain(|d| d.perpheral_eid != device.perpheral_eid);
        self.white_eids.remove(&device.perpheral_eid);
        if !self.black_eids.contains(&device.perpheral_eid) {
            self.black_eids.insert(device.perpheral_eid.clone());
            self.blacklist.push(device);
        }
    }

}

pub type SharedBlackWhiteList = Arc<Mutex<BlackWhiteList>>;

use once_cell::sync::Lazy;
pub static SHARED_USB_LIST: Lazy<SharedBlackWhiteList> = Lazy::new(|| Arc::new(Mutex::new(BlackWhiteList::new())));
