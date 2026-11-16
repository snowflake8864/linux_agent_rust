// crates/task/src/baseline_task.rs
// crates/task/src/baseline_task.rs

use std::fs;
use std::process::Command;
use std::sync::OnceLock;
use net_client::core::NetClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use logging::{log_error, log_info};
use tokio::time::Duration;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BaselineItem {
    pub val: u64,
    pub name: String,
    pub pass: i32,
    #[serde(default)]
    pub failed: String,
}

static LOCAL_OS_TYPE: OnceLock<i32> = OnceLock::new();

fn detect_local_os_type() -> i32 {
    let content = fs::read_to_string("/etc/os-release")
        .unwrap_or_default()
        .to_lowercase();

    if content.contains("neokylin") {
        1131
    } else if content.contains("kylin") {
        1130
    } else if content.contains("uos") || content.contains("uniontech") {
        1132
    } else if content.contains("centos") {
        1133
    } else if content.contains("ubuntu") {
        1134
    } else if content.contains("red hat")
        || content.contains("rhel")
        || content.contains("rocky")
        || content.contains("almalinux")
        || content.contains("openeuler")
    {
        1135
    } else {
        -1
    }
}

pub fn get_local_os_type() -> i32 {
    *LOCAL_OS_TYPE.get_or_init(|| detect_local_os_type())
}

const LINUX_PROXY_DISABLE: u64 = 1203;
const LINUX_ANTIVIRUS_ENABLE: u64 = 1302;
const LINUX_FIREWALL_ENABLE: u64 = 1301;
const LINUX_FILESHARE_DISABLE: u64 = 1401;
const LINUX_GUEST_ACCOUNT_DISABLE: u64 = 1501;
const LINUX_REMOTE_DESKTOP_DISABLE: u64 = 1600;

fn command_ok(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn command_stdout(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
}

fn matched_processes(names: &[&str]) -> Vec<String> {
    let Ok(dir) = fs::read_dir("/proc") else {
        return Vec::new();
    };

    let mut matched = Vec::new();

    for entry in dir.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };

        let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
            .map(|b| String::from_utf8_lossy(&b).replace('\0', " "))
            .unwrap_or_default();
        let exe_base = cmdline
            .split_whitespace()
            .next()
            .unwrap_or("")
            .rsplit('/')
            .next()
            .unwrap_or("");

        for &name in names {
            if comm.eq_ignore_ascii_case(name) || exe_base.eq_ignore_ascii_case(name) {
                matched.push(format!(
                    "{}({})",
                    if comm.is_empty() { name } else { comm.as_str() },
                    pid
                ));
                break;
            }
        }
    }

    matched
}

fn is_process_running(names: &[&str]) -> bool {
    !matched_processes(names).is_empty()
}

fn check_proxy() -> (i32, String) {
    let http_proxy = std::env::var("http_proxy")
        .or_else(|_| std::env::var("HTTP_PROXY"))
        .unwrap_or_default();
    let https_proxy = std::env::var("https_proxy")
        .or_else(|_| std::env::var("HTTPS_PROXY"))
        .unwrap_or_default();
    let all_proxy = std::env::var("all_proxy")
        .or_else(|_| std::env::var("ALL_PROXY"))
        .unwrap_or_default();

    let has_proxy = !http_proxy.is_empty() || !https_proxy.is_empty() || !all_proxy.is_empty();
    if has_proxy {
        (
            0,
            format!(
                "检测到系统环境变量配置了代理: http_proxy={}, https_proxy={}",
                if http_proxy.is_empty() { "无" } else { http_proxy.as_str() },
                if https_proxy.is_empty() { "无" } else { https_proxy.as_str() }
            ),
        )
    } else {
        (1, String::new())
    }
}

fn binary_in_path(name: &str) -> bool {
    let mut dirs: Vec<String> = std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .filter(|d| !d.is_empty())
        .map(|d| d.to_string())
        .collect();

    for dir in ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/bin", "/sbin"] {
        if !dirs.iter().any(|d| d == dir) {
            dirs.push(dir.to_string());
        }
    }

    dirs.iter()
        .any(|dir| std::path::Path::new(dir).join(name).exists())
}

fn check_antivirus() -> (i32, String) {
    let active = is_process_running(&[
        // ClamAV
        "clamd",
        "clamav",
        "freshclam",
        // 奇安信天擎
        "qianxin",
        "qaxsafe",
        "tianqing",
        // 360
        "360",
        "360sd",
        "360safe",
        "360tray",
        // 卡巴斯基
        "kaspersky",
        "kesl",
        // 火绒
        "huorong",
        "hips",
        // 瑞星
        "rav",
        "ravagent",
        "rising",
        // 金山
        "kscan",
        "kingsoft",
        // 腾讯
        "txav",
        "tencent",
        // 麒麟安全中心/kysec
        "kysec",
        "kylin-security-center",
        "kylin-sec-center",
        "security-center",
        "vigilixav",
    ]);

    if active {
        return (1, String::new());
    }

    // rkhunter/chkrootkit 为按需扫描器，无常驻进程，按“已安装”判定
    if binary_in_path("rkhunter")
        || binary_in_path("chkrootkit")
        || binary_in_path("clamscan")
        || binary_in_path("kysec_set")
    {
        return (1, String::new());
    }

    (
        0,
        "未检测到正在运行的杀毒软件/安全中心，也未安装 ClamAV/rkhunter/chkrootkit".to_string(),
    )
}

fn check_firewall() -> (i32, String) {
    let active = command_ok("firewall-cmd", &["--state"])
        || command_stdout("ufw", &["status"])
            .map(|out| out.to_lowercase().contains("status: active"))
            .unwrap_or(false)
        || command_stdout("nft", &["list", "ruleset"])
            .map(|out| out.contains("table "))
            .unwrap_or(false)
        || command_stdout("iptables", &["-S"])
            .map(|out| out.lines().any(|l| !l.starts_with("-P") && !l.trim().is_empty()))
            .unwrap_or(false)
        || is_process_running(&["firewalld"]);

    if active {
        (1, String::new())
    } else {
        (0, "未检测到已开启的防火墙(firewalld/ufw/nftables)".to_string())
    }
}

fn check_fileshare() -> (i32, String) {
    let matched = matched_processes(&[
        "smbd",
        "nmbd",
        "winbindd",
        "nfsd",
        "rpc.nfsd",
        "rpc.mountd",
        "vsftpd",
        "proftpd",
        "pure-ftpd",
        "tftpd",
        "in.tftpd",
        "atftpd",
        "syncthing",
    ]);

    if matched.is_empty() {
        (1, String::new())
    } else {
        (
            0,
            format!(
                "检测到网络文件共享服务正在运行: {}",
                matched.join(", ")
            ),
        )
    }
}

fn check_guest_account() -> (i32, String) {
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.first().is_some_and(|name| name.eq_ignore_ascii_case("guest")) {
                return (0, "检测到存在 guest 账号".to_string());
            }
        }
    }

    if let Ok(shadow) = fs::read_to_string("/etc/shadow") {
        for line in shadow.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 1 && parts[1].is_empty() {
                return (0, format!("检测到存在空密码账号: {}", parts[0]));
            }
        }
    }

    (1, String::new())
}

fn check_remote_desktop() -> (i32, String) {
    let matched = matched_processes(&[
        "xrdp",
        "xrdp-sesman",
        "Xvnc",
        "Xvnc4",
        "Xtightvnc",
        "Xtigervnc",
        "x11vnc",
        "vncserver",
        "vncserver-x11",
        "vncserver-x11-serviced",
        "x2goserver",
        "x2gocleansessions",
        "x2goagent",
        "nxagent",
        "nxserver",
        "nxnode",
        "nxexec",
        "vsmserver",
        "vsmagent",
        "tlwebaccess",
        "gnome-remote-de",
        "sunloginclient",
        "sunloginclientd",
        "todesk",
        "todeskd",
        "rustdesk",
        "teamviewer",
        "teamviewerd",
        "anydesk",
        "SRService",
        "SRServer",
    ]);

    if matched.is_empty() {
        (1, String::new())
    } else {
        (
            0,
            format!("检测到远程桌面服务正在运行: {}", matched.join(", ")),
        )
    }
}

fn run_baseline_check(val: u64) -> Option<(i32, String)> {
    match val {
        LINUX_PROXY_DISABLE => Some(check_proxy()),
        LINUX_ANTIVIRUS_ENABLE => Some(check_antivirus()),
        LINUX_FIREWALL_ENABLE => Some(check_firewall()),
        LINUX_FILESHARE_DISABLE => Some(check_fileshare()),
        LINUX_GUEST_ACCOUNT_DISABLE => Some(check_guest_account()),
        LINUX_REMOTE_DESKTOP_DISABLE => Some(check_remote_desktop()),
        _ => None,
    }
}

pub async fn process_baselines_from_client(
    net_client: &NetClient,
    url: &str,
    token: Option<&str>,
) -> Result<(), String> {
    let response = net_client
        .post_data_async(url, "", Duration::from_secs(10), token)
        .await
        .map_err(|e| format!("获取基线检查任务失败: {}", e))?;

    let parsed: Value = serde_json::from_str(&response)
        .map_err(|e| format!("解析基线检查任务响应失败: {}", e))?;

    if parsed["code"] != "000000" {
        let code = parsed["code"].as_str().unwrap_or("未知代码");
        return Err(format!("基线检查任务响应代码无效: {}", code));
    }

    let list = parsed["data"]["list"]
        .as_array()
        .ok_or("响应中缺少 data.list 或其格式不是数组")?;

    let mut baselines: Vec<BaselineItem> = Vec::new();

    for item in list {
        let val = item["val"].as_u64().ok_or("baseline.val 缺失或不是数字")?;
        let name = item["name"]
            .as_str()
            .ok_or("baseline.name 缺失或不是字符串")?
            .to_string();
        let pass = item["pass"].as_i64().unwrap_or(0) as i32;
        let failed = item["failed"].as_str().unwrap_or_default().to_string();

        baselines.push(BaselineItem {
            val,
            name,
            pass,
            failed,
        });
    }

    if baselines.is_empty() {
        log_info!("无基线检查任务");
        return Ok(());
    }

    for b in &baselines {
        log_info!("基线检查任务: val={}, name={}", b.val, b.name);
    }

    let local_os_type = get_local_os_type();
    log_info!("本机操作系统类型: {}", local_os_type);

    for b in baselines.iter_mut() {
        if let Some((pass, failed)) = run_baseline_check(b.val) {
            b.pass = pass;
            b.failed = failed;
        } else if b.val as i32 == local_os_type {
            b.pass = 1;
        }
    }

    for b in &baselines {
        log_info!(
            "基线检查结果: val={}, name={}, pass={}, failed={}",
            b.val,
            b.name,
            b.pass,
            b.failed
        );
    }

    log_info!("处理基线检查任务: {} 条", baselines.len());

    let baselines_array_str = serde_json::to_string(&baselines)
        .map_err(|e| format!("baseline 数组序列化失败: {}", e))?;

    let report_body = serde_json::json!({
        "list": baselines_array_str
    });

    let baselines_json = serde_json::to_string(&report_body)
        .map_err(|e| format!("report body 序列化失败: {}", e))?;

    let report_url = format!("{}/v1/putBaselines", net_client.get_base_url().unwrap_or_default());
    match net_client
        .post_data_async(&report_url, &baselines_json, Duration::from_secs(10), token)
        .await
    {
        Ok(_) => log_info!("基线检查结果上报成功"),
        Err(e) => log_error!("基线检查结果上报失败: {}", e),
    }

    Ok(())
}
