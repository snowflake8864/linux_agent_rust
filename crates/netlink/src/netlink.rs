//crates/netlink/src/netlink.rs
use libc::{self, iovec, msghdr, sockaddr_nl, NLM_F_REQUEST};
use logging::{log_error, log_info};
use std::convert::TryInto;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::path::Path;
use std::ptr;
use std::{thread, time};

const NETLINK_USER: i32 = 20;

pub struct NlSockInfo {
    pub sock: i32,
    pub dest_addr: sockaddr_nl,
    pub src_addr: sockaddr_nl,
}

impl Clone for NlSockInfo {
    fn clone(&self) -> Self {
        NlSockInfo {
            sock: self.sock,
            dest_addr: self.dest_addr,
            src_addr: self.src_addr,
        }
    }
}
impl NlSockInfo {
    fn get_netlink_proto() -> io::Result<i32> {
        let path = Path::new("/sys/osec/proto");
        let retry_limit = 10;
        let retry_interval = time::Duration::from_secs(2);

        for attempt in 0..retry_limit {
            if path.exists() {
                // 文件存在，尝试读取和解析
                let mut file = File::open(path)?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;

                if let Some(stripped) = contents.strip_prefix("netlink:") {
                    if let Ok(proto) = stripped.trim().parse::<i32>() {
                        return Ok(proto);
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Invalid protocol format in /sys/osec/proto",
                        ));
                    }
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Missing 'netlink:' prefix in /sys/osec/proto",
                    ));
                }
            } else {
                // 文件还没出现，等待后重试
                if attempt < retry_limit - 1 {
                    thread::sleep(retry_interval);
                }
            }
        }

        // 超过重试次数，使用默认协议号
        Ok(21)
    }
    // 创建并绑定 Netlink socket
    pub fn create_socket() -> io::Result<Self> {
        let proto = Self::get_netlink_proto()?;
        let sock = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, proto) };
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut nl_sock = NlSockInfo {
            sock,
            dest_addr: unsafe { std::mem::zeroed() },
            src_addr: unsafe { std::mem::zeroed() },
        };

        nl_sock.src_addr.nl_family = libc::AF_NETLINK as u16;
        nl_sock.src_addr.nl_pid = unsafe { libc::getpid() as u32 };

        nl_sock.dest_addr.nl_family = libc::AF_NETLINK as u16;

        let ret = unsafe {
            libc::bind(
                sock,
                &nl_sock.src_addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(nl_sock)
    }

    // 创建 Netlink 消息
    fn create_netlink_message(msg_type: u16, data: &[u8]) -> Vec<u8> {
        let header_len = mem::size_of::<libc::nlmsghdr>();
        let msg_len = header_len + data.len();
        let mut message = vec![0; msg_len];

        // 初始化 Netlink 消息头
        let nlmsg_header = libc::nlmsghdr {
            nlmsg_len: msg_len as u32,
            nlmsg_type: msg_type,
            nlmsg_flags: NLM_F_REQUEST as u16,
            nlmsg_seq: 0,
            nlmsg_pid: unsafe { libc::getpid() as u32 },
        };

        // 将头部拷贝到缓冲区中
        unsafe {
            ptr::copy_nonoverlapping(
                &nlmsg_header as *const libc::nlmsghdr as *const u8,
                message.as_mut_ptr(),
                header_len,
            );
        }

        // 将数据有效负载拷贝到缓冲区中
        message[header_len..].copy_from_slice(data);

        message
    }

    pub fn send_message(&self, msg_type: u16, data: &[u8]) -> io::Result<isize> {
        let message = Self::create_netlink_message(msg_type, data);

        let iov = libc::iovec {
            iov_base: message.as_ptr() as *mut libc::c_void,
            iov_len: message.len(),
        };

        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &self.dest_addr as *const _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
        msg.msg_iovlen = 1;
        msg.msg_control = std::ptr::null_mut();
        msg.msg_controllen = 0;
        msg.msg_flags = 0;

        let send_len = unsafe { libc::sendmsg(self.sock, &msg, 0) };
        if send_len < 0 {
            return Err(io::Error::last_os_error());
        }
        log_info!("msg:{}", msg_type);
        Ok(send_len)
    }
    pub fn send_bool(&self, msg_type: u16, value: bool) -> io::Result<isize> {
        let data = if value {
            b"\x01\x00\x00\x00"
        } else {
            b"\x00\x00\x00\x00"
        };
        self.send_message(msg_type, data)
    }

    pub fn send_network_close(&self) -> io::Result<isize> {
        let data = b"\x00\x00\x00\x00";
        self.send_message(0x706, data)
    }
    pub fn send_uint32(&self, msg_type: u16, value: u32) -> io::Result<isize> {
        let bytes = value.to_ne_bytes(); // 保持原生字节序
        self.send_message(msg_type, &bytes)
    }
    pub fn receive_netlink_message(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 4096];
        let iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };

        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &self.src_addr as *const _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
        msg.msg_iovlen = 1;
        msg.msg_control = std::ptr::null_mut();
        msg.msg_controllen = 0;
        msg.msg_flags = 0;

        let ret = unsafe { libc::recvmsg(self.sock, &mut msg, 0) };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        buf.truncate(ret as usize);
        Ok(buf)
    }
    /*
        pub fn receive_messages_loop(&self) -> io::Result<()> {
            loop {
                let mut buf = vec![0u8; 4096];
                let iov = libc::iovec {
                    iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                    iov_len: buf.len(),
                };

                let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
                msg.msg_name = &self.src_addr as *const _ as *mut libc::c_void;
                msg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
                msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
                msg.msg_iovlen = 1;
                msg.msg_control = std::ptr::null_mut();
                msg.msg_controllen = 0;
                msg.msg_flags = 0;

                let ret = unsafe { libc::recvmsg(self.sock, &mut msg, 0) };

                if ret < 0 {
                    return Err(io::Error::last_os_error());
                } else if ret == 0 {
                    // EOF or no more data
                    println!("Netlink connection closed by kernel.");
                    break;
                }

                buf.truncate(ret as usize);
                println!("Received message from kernel: {:?}", buf);
            }

            Ok(())
        }
    */

    pub fn receive_messages_loop<F>(&self, mut callback: F) -> io::Result<()>
    where
        F: FnMut(&[u8]),
    {
        loop {
            let mut buf = vec![0u8; 4096];
            let iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };

            let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };

            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut addr as *mut _ as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
            msg.msg_iov = &iov as *const libc::iovec as *mut libc::iovec;
            msg.msg_iovlen = 1;
            msg.msg_control = std::ptr::null_mut();
            msg.msg_controllen = 0;
            msg.msg_flags = 0;

            let ret = unsafe { libc::recvmsg(self.sock, &mut msg, 0) };

            if ret < 0 {
                return Err(io::Error::last_os_error());
            } else if ret == 0 {
                println!("Netlink connection closed by kernel.");
                break;
            }

            buf.truncate(ret as usize);

            callback(&buf[..]);
        }

        Ok(())
    }
}
// 解析接收到的 Netlink 数据并返回所需的数据
pub fn parse_kosecs_msg_data(data: &[u8]) -> io::Result<(u32, &[u8], usize)> {
    if data.len() < std::mem::size_of::<u32>() * 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Insufficient data",
        ));
    }

    // 解析 Netlink 消息头 (nlmsghdr)
    let nlmsg_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let nlmsg_type = u16::from_le_bytes(data[4..6].try_into().unwrap());
    let nlmsg_flags = u16::from_le_bytes(data[6..8].try_into().unwrap());
    let nlmsg_seq = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let nlmsg_pid = u32::from_le_bytes(data[12..16].try_into().unwrap());

    println!(
        "Netlink message: len={}, type={}, flags={}, seq={}, pid={}",
        nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid
    );

    // 解析 vsec_msg_data 部分
    let vsec_msg_data_start = 16; // 从 Netlink header 后面开始
    if data.len() < vsec_msg_data_start + std::mem::size_of::<u32>() * 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vsec_msg_data header missing",
        ));
    }

    let data_type = u32::from_le_bytes(
        data[vsec_msg_data_start..vsec_msg_data_start + 4]
            .try_into()
            .unwrap(),
    );
    let data_len = u32::from_le_bytes(
        data[vsec_msg_data_start + 4..vsec_msg_data_start + 8]
            .try_into()
            .unwrap(),
    );

    println!(
        "vsec_msg_data: data_type={}, data_len={}",
        data_type, data_len
    );

    // 验证数据长度是否匹配
    if data.len() < vsec_msg_data_start + 8 + data_len as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Data length mismatch",
        ));
    }

    // 提取数据内容，这里使用切片而不是克隆
    let data_content = &data[vsec_msg_data_start + 8..vsec_msg_data_start + 8 + data_len as usize];
    println!("Data content: {:?}", data_content);

    // 返回 data_type、data_content（切片）和 data_content 的长度
    Ok((data_type, data_content, data_content.len()))
}
