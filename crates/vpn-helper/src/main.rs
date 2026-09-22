//! vpn-helper：直连厂商 VPN SDK 的拨号子进程（需 --features helper 编译）。
//!
//! 由 agent（crates/vpn supervisor）拉起并保活；KeepAlive5 内部阻塞+自动重连，
//! 进程退出即代表隧道中断，supervisor 会按退避间隔重新拉起。
//! 用法：vpn-helper [/opt/osec/vpn/vpn.conf [/opt/osec/vpn/client.conf]]

use std::env;
use std::ffi::{CStr, CString};
use std::fs;
use std::os::raw::{c_char, c_int, c_uchar, c_void};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VpnConf {
    vpn: VpnSection,
    #[serde(rename = "copsign")]
    copysign: CoopSignSection,
    auth: AuthSection,
    log: LogSection,
    sdk: SdkSection,
}

#[derive(Debug, Deserialize)]
struct VpnSection {
    serv_ip: String,
    serv_port: u16,
}

#[derive(Debug, Deserialize)]
struct CoopSignSection {
    serv_ip: String,
    serv_port: u16,
    ssl_config: String,
    ca_path: String,
    local_ws_port: u16,
    sign_cert_path: String,
    uuid: String,
}

#[derive(Debug, Deserialize)]
struct AuthSection {
    username: String,
    password: String,
    authtype: u8,
}

#[derive(Debug, Deserialize)]
struct LogSection {
    filename: String,
    level: u8,
}

#[derive(Debug, Deserialize)]
struct SdkSection {
    timeout: u8,
    ipv6: u8,
    cert_save_path: String,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct SdkRunParamCtx {
    pub servIp: [u8; 128],
    pub servPort: c_int,
    pub logfilename: [u8; 256],
    pub logLevel: c_int,
    pub timeout: c_int,
    pub isOpenIPv6: c_int,
    pub certSavePath: [c_char; 128],
    pub authtype: c_int,
    pub gbkeylibname: [u8; 256],
}

impl Default for SdkRunParamCtx {
    fn default() -> Self {
        Self {
            servIp: [0; 128],
            servPort: 0,
            logfilename: [0; 256],
            logLevel: 0,
            timeout: 0,
            isOpenIPv6: 0,
            certSavePath: [0; 128],
            authtype: 0,
            gbkeylibname: [0; 256],
        }
    }
}

extern "C" {
    fn FM_vpnclientInit(config_path: *const c_uchar, ctx: *mut SdkRunParamCtx) -> c_int;
    fn FM_vpnclientUninit() -> c_int;
    fn FM_coopSignLogin(
        server_ip: *const c_uchar,
        server_port: c_int,
        ssl_config_path: *const c_uchar,
        ca_path: *const c_uchar,
        local_ws_port: c_int,
        username: *const c_uchar,
        password: *const c_uchar,
        uuid: *const c_uchar,
        sign_cert_path: *const c_uchar,
    ) -> c_int;
    fn FM_setTunTransferMode(mode: c_int);
    fn FM_StartVPN_KeepAlive5(
        handshake_mode: c_int,
        auth_id: *const c_uchar,
        password: *const c_uchar,
        status_cb: *mut c_void,
        route_cb: *mut c_void,
    ) -> c_int;
    fn FM_StopVPN() -> c_int;
    fn FM_GetErrorMessage(code: c_int, msg: *mut c_char) -> c_int;
}

unsafe extern "C" fn vpn_online_status_callback(online: c_int) {
    eprintln!("[vpn-helper] online={}", online);
}

unsafe extern "C" fn route_status_callback(finish: c_int) {
    eprintln!("[vpn-helper] route status={}", finish);
}

fn copy_str_to_u8_array(dst: &mut [u8], value: &str) {
    let bytes = value.as_bytes();
    let len = bytes.len().min(dst.len().saturating_sub(1));
    dst[..len].copy_from_slice(&bytes[..len]);
    dst[len] = 0;
}

fn copy_str_to_c_char_array(dst: &mut [c_char], value: &str) {
    let c = CString::new(value).unwrap_or_default();
    let bytes = c.as_bytes_with_nul();
    let len = bytes.len().min(dst.len());
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst.as_mut_ptr() as *mut u8, len);
    }
    if len < dst.len() {
        dst[len] = 0;
    }
}

fn print_error(code: c_int) {
    let mut buf = [0 as c_char; 512];
    let ret = unsafe { FM_GetErrorMessage(code, buf.as_mut_ptr()) };
    if ret == 0 {
        let msg = unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        eprintln!("[vpn-helper] error: {} -> {}", code, msg);
    } else {
        eprintln!("[vpn-helper] error: {}", code);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let conf_path = args.get(1).map(|s| s.as_str()).unwrap_or("/opt/osec/vpn/vpn.conf");
    let client_conf = args.get(2).map(|s| s.as_str()).unwrap_or("/opt/osec/vpn/client.conf");

    let conf_str = match fs::read_to_string(conf_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[vpn-helper] 读取 {} 失败: {}", conf_path, e);
            std::process::exit(2);
        }
    };
    let conf: VpnConf = match toml::from_str(&conf_str) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[vpn-helper] 解析 {} 失败: {}", conf_path, e);
            std::process::exit(2);
        }
    };

    eprintln!(
        "[vpn-helper] vpn={}:{} cosign={}:{} user={}",
        conf.vpn.serv_ip, conf.vpn.serv_port, conf.copysign.serv_ip, conf.copysign.serv_port,
        conf.auth.username,
    );

    let config_path = CString::new(client_conf).unwrap_or_default();
    let mut ctx = SdkRunParamCtx::default();
    copy_str_to_u8_array(&mut ctx.servIp, &conf.vpn.serv_ip);
    ctx.servPort = conf.vpn.serv_port as c_int;
    copy_str_to_u8_array(&mut ctx.logfilename, &conf.log.filename);
    ctx.logLevel = conf.log.level as c_int;
    ctx.timeout = conf.sdk.timeout as c_int;
    ctx.isOpenIPv6 = conf.sdk.ipv6 as c_int;
    copy_str_to_c_char_array(&mut ctx.certSavePath, &conf.sdk.cert_save_path);
    ctx.authtype = conf.auth.authtype as c_int;

    let ret = unsafe { FM_vpnclientInit(config_path.as_ptr() as *const c_uchar, &mut ctx) };
    if ret != 0 {
        print_error(ret);
        std::process::exit(3);
    }
    eprintln!("[vpn-helper] FM_vpnclientInit OK");

    unsafe { FM_setTunTransferMode(0) };

    let server_ip = CString::new(conf.copysign.serv_ip.clone()).unwrap_or_default();
    let ssl_cfg = CString::new(conf.copysign.ssl_config.clone()).unwrap_or_default();
    let ca_path = CString::new(conf.copysign.ca_path.clone()).unwrap_or_default();
    let username = CString::new(conf.auth.username.clone()).unwrap_or_default();
    let password = CString::new(conf.auth.password.clone()).unwrap_or_default();
    let uuid = CString::new(conf.copysign.uuid.clone()).unwrap_or_default();
    let sign_cert_path = CString::new(conf.copysign.sign_cert_path.clone()).unwrap_or_default();

    let login_ret = unsafe {
        FM_coopSignLogin(
            server_ip.as_ptr() as *const c_uchar,
            conf.copysign.serv_port as c_int,
            ssl_cfg.as_ptr() as *const c_uchar,
            ca_path.as_ptr() as *const c_uchar,
            conf.copysign.local_ws_port as c_int,
            username.as_ptr() as *const c_uchar,
            password.as_ptr() as *const c_uchar,
            uuid.as_ptr() as *const c_uchar,
            sign_cert_path.as_ptr() as *const c_uchar,
        )
    };
    eprintln!("[vpn-helper] FM_coopSignLogin ret = {:#010x}({})", login_ret, login_ret);
    if login_ret != 0 {
        print_error(login_ret);
        unsafe {
            let _ = FM_vpnclientUninit();
        }
        std::process::exit(4);
    }

    unsafe { FM_setTunTransferMode(1) };

    // KeepAlive5 成功后内部阻塞+自动重连，直到被 kill（SIGTERM/SIGKILL）才退出
    let start_ret = unsafe {
        FM_StartVPN_KeepAlive5(
            0,
            username.as_ptr() as *const c_uchar,
            password.as_ptr() as *const c_uchar,
            vpn_online_status_callback as *mut c_void,
            route_status_callback as *mut c_void,
        )
    };
    eprintln!("[vpn-helper] FM_StartVPN_KeepAlive5 返回 {:#010x}({})", start_ret, start_ret);
    unsafe {
        let _ = FM_StopVPN();
        let _ = FM_vpnclientUninit();
    }
    std::process::exit(if start_ret == 0 { 0 } else { 5 });
}
