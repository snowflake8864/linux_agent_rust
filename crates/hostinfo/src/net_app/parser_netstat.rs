use crate::net_app::model::{NETAPP_STATE, PortBusinessInfo};
use crate::net_app::utils::*;
use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use chrono::Utc;

pub fn update_netstat_info() {
    let now = Utc::now().timestamp();
    let mut map = NETAPP_STATE.write().unwrap();
    map.port_map.clear();
    map.port_str_map.clear();

    // 构建 socket inode 到 PID 和进程路径的映射
    let inode_to_pid = build_inode_to_pid_map();

    // 解析 IPv4 TCP 连接
    parse_proc_net_tcp("/proc/net/tcp", &inode_to_pid, &mut map, now);
    
    // 解析 IPv6 TCP 连接
    parse_proc_net_tcp6("/proc/net/tcp6", &inode_to_pid, &mut map, now);
}

/// 构建 inode -> (pid, process_path) 的映射
fn build_inode_to_pid_map() -> HashMap<u32, (i32, String)> {
    let mut inode_map = HashMap::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid_str = entry.file_name().to_string_lossy().to_string();
            
            // 检查是否为数字目录（即进程目录）
            if let Ok(pid) = pid_str.parse::<i32>() {
                // 获取进程路径
                let process_info = get_process_info(pid);

                let fd_path = format!("/proc/{}/fd", pid);
                
                // 读取该进程的文件描述符
                if let Ok(fds) = fs::read_dir(fd_path) {
                    for fd_entry in fds.flatten() {
                        let link_path = fd_entry.path();
                        
                        // 读取符号链接目标
                        if let Ok(target) = fs::read_link(&link_path) {
                            let target_str = target.to_string_lossy();
                            
                            // 检查是否为 socket
                            if let Some(inode) = extract_socket_inode(&target_str) {
                                inode_map.insert(inode, (pid, process_info.clone()));
                            }
                        }
                    }
                }
            }
        }
    }

    inode_map
}

/// 从 socket 链接中提取 inode
fn extract_socket_inode(target: &str) -> Option<u32> {
    if target.starts_with("socket:[") && target.ends_with(']') {
        let start = target.find('[')?;
        let end = target.find(']')?;
        let inode_str = &target[start + 1..end];
        inode_str.parse().ok()
    } else {
        None
    }
}
/*
/// 获取进程信息（进程名或路径）
fn get_process_info(pid: i32) -> String {
    // 尝试获取命令行
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
        let args: Vec<&str> = cmdline.split('\0').filter(|s| !s.is_empty()).collect();
        if !args.is_empty() {
            // 返回第一个参数（通常是程序名）
            let program = args[0];
            // 如果是完整路径，只取文件名
            if let Some(name) = std::path::Path::new(program).file_name() {
                return name.to_string_lossy().to_string();
            } else {
                return program.to_string();
            }
        }
    }
    
    // 尝试获取 comm
    let comm_path = format!("/proc/{}/comm", pid);
    if let Ok(comm) = fs::read_to_string(&comm_path) {
        return comm.trim().to_string();
    }
    
    // 尝试获取 exe 并提取文件名
    let exe_path = format!("/proc/{}/exe", pid);
    if let Ok(path) = fs::read_link(&exe_path) {
        if let Some(name) = path.file_name() {
            return name.to_string_lossy().to_string();
        }
    }
    
    format!("[process:{}]", pid)
}
*/
fn get_process_info(pid: i32) -> String {
    let exe_path = format!("/proc/{}/exe", pid);
    if let Ok(path) = fs::read_link(&exe_path) {
        return path.to_string_lossy().to_string();
    }

    // 如果 exe 不可读，尝试 cmdline 获取路径（仍可能是相对路径）
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
        let args: Vec<&str> = cmdline.split('\0').filter(|s| !s.is_empty()).collect();
        if !args.is_empty() {
            return args[0].to_string(); // 不保证是绝对路径
        }
    }

    // 最后备选：comm 或 PID
    let comm_path = format!("/proc/{}/comm", pid);
    if let Ok(comm) = fs::read_to_string(&comm_path) {
        return format!("[comm:{}]", comm.trim());
    }

    format!("[process:{}]", pid)
}
/// 解析 /proc/net/tcp 文件
fn parse_proc_net_tcp(
    file: &str,
    inode_to_pid: &HashMap<u32, (i32, String)>,
    map: &mut crate::net_app::model::NetAppState,
    now: i64,
) {
    if let Ok(content) = fs::read_to_string(file) {
        let lines: Vec<&str> = content.lines().collect();
        
        // 跳过头部行
        for line in lines.into_iter().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            
            // 确保有足够的列
            if cols.len() < 10 {
                continue;
            }

            let (local_ip, local_port) = hex_to_ip_port(cols[1]);
            let (_remote_ip, _remote_port) = hex_to_ip_port(cols[2]);
            
            // 过滤掉本地回环地址的监听端口（但保留服务端口）
            if local_ip == "127.0.0.1" && local_port.parse::<u16>().unwrap_or(0) >= 6000 {
                continue;
            }

            // 只收集监听状态的端口
            if cols[3] != "0A" { // 0A 是 LISTEN 状态
                continue;
            }

            let status = proc_net_status_to_str(cols[3]).to_string();
            let inode: u32 = cols[9].parse().unwrap_or(0);

            // 通过 inode 获取 PID 和进程路径
            let (pid, process_path) = inode_to_pid.get(&inode)
                .map(|(p, path)| (*p, path.clone()))
                .unwrap_or((0, "--".to_string()));

            let info = PortBusinessInfo {
                time: now,
                protocol: "tcp".into(),
                local_ip: local_ip.clone(),
                local_port: local_port.parse().unwrap_or(0),
                remote_ip: _remote_ip,
                remote_port: _remote_port,
                status,
                pid,
                process_path,
            };

            // 插入到 port_map 中，优先保留 IPv4
            if !map.port_map.contains_key(&info.local_port) {
                map.port_map.insert(info.local_port, info.clone());
            }
            
            // 插入到 port_str_map 中，使用端口字符串作为 key
            let port_key = format!("{}:{}", info.local_ip, info.local_port);
            if !map.port_str_map.contains_key(&port_key) {
                map.port_str_map.insert(port_key, info);
            }
        }
    }
}

/// 解析 /proc/net/tcp6 文件
fn parse_proc_net_tcp6(
    file: &str,
    inode_to_pid: &HashMap<u32, (i32, String)>,
    map: &mut crate::net_app::model::NetAppState,
    now: i64,
) {
    if let Ok(content) = fs::read_to_string(file) {
        let lines: Vec<&str> = content.lines().collect();
        
        // 跳过头部行
        for line in lines.into_iter().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            
            // 确保有足够的列
            if cols.len() < 10 {
                continue;
            }

            let (local_ip, local_port) = hex_to_ipv6_port_compressed(cols[1]);
            let (_remote_ip, _remote_port) = hex_to_ipv6_port_compressed(cols[2]);
            
            // 过滤掉本地回环地址的监听端口（但保留服务端口）
            if local_ip == "::1" && local_port.parse::<u16>().unwrap_or(0) >= 6000 {
                continue;
            }

            // 只收集监听状态的端口
            if cols[3] != "0A" { // 0A 是 LISTEN 状态
                continue;
            }

            let status = proc_net_status_to_str(cols[3]).to_string();
            let inode: u32 = cols[9].parse().unwrap_or(0);

            // 通过 inode 获取 PID 和进程路径
            let (pid, process_path) = inode_to_pid.get(&inode)
                .map(|(p, path)| (*p, path.clone()))
                .unwrap_or((0, "--".to_string()));

            let info = PortBusinessInfo {
                time: now,
                protocol: "tcp6".into(),
                local_ip: local_ip.clone(),
                local_port: local_port.parse().unwrap_or(0),
                remote_ip: _remote_ip,
                remote_port: _remote_port,
                status,
                pid,
                process_path,
            };

            // 插入到 port_map 中，但不覆盖已有的 IPv4 记录
            if !map.port_map.contains_key(&info.local_port) {
                map.port_map.insert(info.local_port, info.clone());
            }
            
            // 插入到 port_str_map 中，使用端口字符串作为 key
            let port_key = format!("{}:{}", info.local_ip, info.local_port);
            if !map.port_str_map.contains_key(&port_key) {
                map.port_str_map.insert(port_key, info);
            }
        }
    }
}

/// 将十六进制字符串转换为压缩格式的 IPv6 地址和端口
fn hex_to_ipv6_port_compressed(hex: &str) -> (String, String) {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return ("::".into(), "0".into());
    }

    let ip_raw = parts[0];
    let port_hex = parts[1];

    // IPv6 地址是 32 个十六进制字符
    if ip_raw.len() != 32 {
        return ("::".into(), "0".into());
    }

    // 按 8 个字符一组解析
    let mut segments = [0u16; 8];
    for (i, chunk) in ip_raw.chars().collect::<Vec<_>>().chunks(8).enumerate() {
        let chunk_str: String = chunk.iter().collect();
        if let Ok(val) = u32::from_str_radix(&chunk_str, 16) {
            // 网络字节序转换
            let host_val = u32::from_be(val);
            segments[i * 2] = ((host_val >> 16) & 0xFFFF) as u16;
            segments[i * 2 + 1] = (host_val & 0xFFFF) as u16;
        }
    }

    // 使用标准库转换为 IPv6 地址并压缩
    let ip_addr = Ipv6Addr::new(
        segments[0], segments[1], segments[2], segments[3],
        segments[4], segments[5], segments[6], segments[7]
    ).to_string();

    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0).to_string();

    (ip_addr, port)
}
