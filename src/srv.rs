//! 极简 DNS SRV 查询（零新增依赖，只用 std）。
//!
//! 为什么不用 hickory-resolver：
//!   1. Android 上没有 /etc/resolv.conf，`tokio_from_system_conf()` 会直接失败；
//!   2. 主 crate 原本不直接依赖 tokio / hickory，加依赖会牵动 Cargo.lock，
//!      CI 里如果用了 --locked 会挂。
//!
//! 所以这里自己发 UDP 包，DNS 服务器硬编码成三个国内可达的公共 DNS。
//! 函数是同步阻塞的（超时 2 秒），只在用户主动发起连接时调一次，
//! 对 tokio 多线程 runtime 的影响可以接受。

use std::net::UdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 按顺序尝试：阿里 → 腾讯 → Cloudflare
const DNS_SERVERS: &[&str] = &["223.5.5.5:53", "119.29.29.29:53", "1.1.1.1:53"];
const TIMEOUT: Duration = Duration::from_millis(2000);

/// 查 SRV 记录，返回 (priority, target, port)，按 priority 升序。
/// 查不到返回 None（调用方应继续走原有逻辑）。
pub fn lookup_srv(name: &str) -> Option<Vec<(u16, String, u16)>> {
    for server in DNS_SERVERS {
        if let Some(v) = query_one(server, name) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

fn query_one(server: &str, name: &str) -> Option<Vec<(u16, String, u16)>> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(TIMEOUT)).ok()?;
    sock.set_write_timeout(Some(TIMEOUT)).ok()?;

    let qid = (SystemTime::now().duration_since(UNIX_EPOCH).ok()?.subsec_nanos() & 0xFFFF) as u16;

    let mut pkt = Vec::with_capacity(80);
    pkt.extend_from_slice(&qid.to_be_bytes()); // ID
    pkt.extend_from_slice(&[0x01, 0x00]); // flags: RD
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN / NS / AR = 0

    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&33u16.to_be_bytes()); // QTYPE = SRV
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    sock.send_to(&pkt, server).ok()?;

    let mut buf = [0u8; 1024];
    let (n, _) = sock.recv_from(&mut buf).ok()?;
    parse(&buf[..n], qid)
}

fn read_name(data: &[u8], mut off: usize) -> (String, usize) {
    let mut parts: Vec<String> = Vec::new();
    let mut next = off;
    let mut jumped = false;
    loop {
        if off >= data.len() {
            break;
        }
        let len = data[off] as usize;
        if len == 0 {
            off += 1;
            if !jumped {
                next = off;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            // 压缩指针
            if off + 1 >= data.len() {
                break;
            }
            let ptr = (((len & 0x3F) as usize) << 8) | data[off + 1] as usize;
            if !jumped {
                next = off + 2;
                jumped = true;
            }
            off = ptr;
            continue;
        }
        off += 1;
        if off + len > data.len() {
            break;
        }
        parts.push(String::from_utf8_lossy(&data[off..off + len]).to_string());
        off += len;
    }
    (parts.join("."), if jumped { next } else { off })
}

fn parse(data: &[u8], qid: u16) -> Option<Vec<(u16, String, u16)>> {
    if data.len() < 12 {
        return None;
    }
    if u16::from_be_bytes([data[0], data[1]]) != qid {
        return None;
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    if flags & 0x000F != 0 {
        // RCODE != NOERROR
        return None;
    }

    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut off = 12;
    for _ in 0..qd {
        let (_, n) = read_name(data, off);
        off = n + 4; // QTYPE + QCLASS
        if off > data.len() {
            return None;
        }
    }

    let mut out = Vec::new();
    for _ in 0..an {
        let (_, n) = read_name(data, off);
        off = n;
        if off + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[off], data[off + 1]]);
        let rdlen = u16::from_be_bytes([data[off + 8], data[off + 9]]) as usize;
        off += 10;
        let rd_end = off + rdlen;
        if rd_end > data.len() {
            break;
        }
        if rtype == 33 && rdlen >= 7 {
            let prio = u16::from_be_bytes([data[off], data[off + 1]]);
            let port = u16::from_be_bytes([data[off + 4], data[off + 5]]);
            let (target, _) = read_name(data, off + 6);
            if !target.is_empty() {
                out.push((prio, target, port));
            }
        }
        off = rd_end;
    }
    out.sort_by_key(|r| r.0);
    Some(out)
}