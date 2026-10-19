//! 极简 DNS SRV 查询（v3b：明文 HTTP 版 DoH，纯 std，不用 reqwest）。
//!
//! 演进过程：
//!   v1/v2：向 223.5.5.5:53 发裸 UDP —— 实测在手机上（WiFi 和蜂窝）都被拦，拿不到结果。
//!   v3   ：用 reqwest 走 HTTPS DoH —— 逻辑对，但主 crate 之前从没真正用过 reqwest，
//!          在 Android 上编译踩坑，CI 的 Build rustdesk lib 失败。
//!   v3b  ：改用「明文 HTTP 的 DoH」（http://223.5.5.5/resolve?...&type=SRV），
//!          只用 std 的 TcpStream 手写一个 HTTP/1.1 GET，零依赖、零 TLS，
//!          和 v2 一样只依赖标准库 —— v2 能编过，v3b 就能编过。
//!   v3c  ：v3b 里用了 `log::info!`，但主 crate 的 Cargo.toml 里**没有 log 依赖**
//!          （CI 报 error[E0433] use of undeclared crate or module `log`），
//!          这里把三处日志调用删掉 —— client.rs 那边本来就会打成功/失败日志。
//!
//! 端点实测可用（返回 JSON，含 "data":"10 5 33183 866601.xyz."）：
//!   http://223.5.5.5/resolve?name=...&type=SRV
//!   http://dns.alidns.com/resolve?name=...&type=SRV

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const HTTP_TIMEOUT: Duration = Duration::from_secs(3);
const UDP_TIMEOUT: Duration = Duration::from_millis(1200);

/// (Host 头, 连接地址)
const HTTP_ENDPOINTS: &[(&str, &str)] = &[
    ("223.5.5.5", "223.5.5.5:80"),          // 纯 IP，不依赖系统 DNS
    ("dns.alidns.com", "dns.alidns.com:80"), // 域名，走系统 DNS
];

const DNS_SERVERS: &[&str] = &["223.5.5.5:53", "119.29.29.29:53"];

/// 判断这个 peer 字符串是否需要走 SRV 解析（只认裸域名）。
pub fn needs_srv(peer: &str) -> bool {
    !peer.is_empty()
        && !hbb_common::is_ip_str(peer)
        && !hbb_common::is_domain_port_str(peer)
        && peer.contains('.')
        && peer.parse::<u32>().is_err()
}

/// 把裸域名解析成 "target:port"。解析不出来返回 None（调用方用原值继续）。
///
/// 保持 async 签名，是为了不修改 client.rs 里已经写好的 `.await`。
/// 内部是同步 IO，但只在建立连接时调一次，耗时很短。
pub async fn resolve_peer(peer: &str) -> Option<String> {
    let name = format!("_rustdesk._tcp.{}", peer.trim_end_matches('.'));
    let path = format!("/resolve?name={}&type=SRV", name);

    // 1) 明文 HTTP 版 DoH
    for (host, addr) in HTTP_ENDPOINTS {
        if let Some(body) = http_get(host, addr, &path) {
            if let Some(addr_str) = parse_srv_json(&body) {
                return Some(addr_str);
            }
        }
    }

    // 2) 兜底：原始 UDP 53
    if let Some(recs) = lookup_srv(&name) {
        if let Some((_, target, port)) = recs.into_iter().next() {
            if port != 0 && !target.is_empty() {
                return Some(format!("{}:{}", target.trim_end_matches('.'), port));
            }
        }
    }
    None
}

/// 手写一个最小的 HTTP/1.1 GET，返回响应体。
fn http_get(host: &str, addr: &str, path: &str) -> Option<String> {
    let sock_addr = addr.to_socket_addrs().ok()?.next()?;
    let mut s = TcpStream::connect_timeout(&sock_addr, HTTP_TIMEOUT).ok()?;
    s.set_read_timeout(Some(HTTP_TIMEOUT)).ok()?;
    s.set_write_timeout(Some(HTTP_TIMEOUT)).ok()?;

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-json\r\nUser-Agent: rustdesk\r\nConnection: close\r\n\r\n",
        path, host
    );
    s.write_all(req.as_bytes()).ok()?;

    let mut buf = Vec::with_capacity(2048);
    s.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);

    // 跳过响应头，取 body
    let idx = text.find("\r\n\r\n")?;
    let body = &text[idx + 4..];
    if !body.contains("\"Answer\"") {
        return None;
    }
    Some(body.to_string())
}

/// 从 DoH 的 JSON 里挑出优先级最高的 SRV，返回 "target:port"。
///
/// 不引 serde_json，直接扫 `"data":"..."`——这个接口的 Answer 项结构固定，
/// 且 Question 段里不含 data 字段，所以扫描到的一定是答案记录。
fn parse_srv_json(body: &str) -> Option<String> {
    let mut best: Option<(u64, String)> = None;
    let mut rest = body;

    while let Some(pos) = rest.find("\"data\":\"") {
        rest = &rest[pos + 8..];
        let end = match rest.find('"') {
            Some(e) => e,
            None => break,
        };
        let val = &rest[..end];
        rest = &rest[end..];

        // 形如 "10 5 33183 866601.xyz."
        let parts: Vec<&str> = val.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let prio: u64 = match parts[0].parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let port: u16 = match parts[2].parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let target = parts[3].trim_end_matches('.');
        if port == 0 || target.is_empty() {
            continue;
        }
        let s = format!("{}:{}", target, port);
        match &best {
            Some((p, _)) if *p <= prio => {}
            _ => best = Some((prio, s)),
        }
    }
    best.map(|(_, s)| s)
}

// ---------------------------------------------------------------------------
// UDP 兜底（v2 的实现，保留）
// ---------------------------------------------------------------------------

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
    sock.set_read_timeout(Some(UDP_TIMEOUT)).ok()?;
    sock.set_write_timeout(Some(UDP_TIMEOUT)).ok()?;

    let qid = (SystemTime::now().duration_since(UNIX_EPOCH).ok()?.subsec_nanos() & 0xFFFF) as u16;

    let mut pkt = Vec::with_capacity(80);
    pkt.extend_from_slice(&qid.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00]);
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&33u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());

    sock.send_to(&pkt, server).ok()?;

    let mut buf = [0u8; 1500];
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
        return None;
    }

    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut off = 12;
    for _ in 0..qd {
        let (_, n) = read_name(data, off);
        off = n + 4;
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
