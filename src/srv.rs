//! 极简 DNS SRV 查询（v3：DoH 优先，UDP 兜底）。
//!
//! 为什么从 v2 的「纯 UDP 53」改成「HTTPS DoH」：
//!   v2 实测在手机上两个网络（家里 WiFi、蜂窝）都拿不到 SRV 结果，
//!   而同一个域名带端口直连是通的 —— 说明不是 DNS 记录的问题，
//!   是「向 223.5.5.5:53 发裸 UDP」这条路在手机网络里被拦/被劫持了。
//!   DoH 走 443，和浏览器访问网页同一条路，拦不住。
//!
//! 依赖：reqwest（主 crate 已有直接依赖，features 含 rustls-tls + json）
//!       serde_json（同样已有）
//!   ⇒ 不新增依赖，不动 Cargo.lock，CI 的 --locked 不受影响。

use std::net::UdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DOH_TIMEOUT: Duration = Duration::from_millis(2500);
const UDP_TIMEOUT: Duration = Duration::from_millis(1200);

/// DoH 端点，按顺序尝试。前两个国内必达，第三个只在境外网络有意义。
const DOH_ENDPOINTS: &[&str] = &[
    // 域名端点：走系统 DNS 解析（实测手机系统 DNS 是好的，A 记录能正常解析）
    "https://dns.alidns.com/resolve",
    // IP 端点：完全绕开 DNS，证书含 IP SAN
    "https://223.5.5.5/resolve",
];

/// UDP 兜底用的 DNS 服务器
const DNS_SERVERS: &[&str] = &[
    "223.5.5.5:53",
    "119.29.29.29:53",
    "114.114.114.114:53",
];

/// 判断这个 peer 字符串是否需要走 SRV 解析。
///
/// 只认「裸域名」这一种：排除 IP、排除 域名:端口、排除纯数字 ID。
pub fn needs_srv(peer: &str) -> bool {
    !peer.is_empty()
        && !hbb_common::is_ip_str(peer)
        && !hbb_common::is_domain_port_str(peer)
        && peer.contains('.')
        && peer.parse::<u32>().is_err()
}

/// 把裸域名解析成 "target:port"。解析不出来返回 None（调用方用原值继续）。
///
/// 返回的是「域名:端口」形态 —— RustDesk 原生支持的输入格式，
/// 下游所有逻辑都会当成普通直连处理，和用户手输 IP:端口 完全同一条路径。
pub async fn resolve_peer(peer: &str) -> Option<String> {
    let name = format!("_rustdesk._tcp.{}", peer.trim_end_matches('.'));

    // 1) DoH over HTTPS —— 走 443，最可靠
    for base in DOH_ENDPOINTS {
        match doh_lookup(base, &name).await {
            Some(addr) => {
                log::info!("SRV(DoH) {} -> {} via {}", name, addr, base);
                return Some(addr);
            }
            None => continue,
        }
    }
    log::warn!("SRV: DoH 全部失败，回退到 UDP 53");

    // 2) 兜底：原始 UDP 53
    if let Some(recs) = lookup_srv(&name) {
        if let Some((_, target, port)) = recs.into_iter().next() {
            if port != 0 && !target.is_empty() {
                let addr = format!("{}:{}", target.trim_end_matches('.'), port);
                log::info!("SRV(UDP) {} -> {}", name, addr);
                return Some(addr);
            }
        }
    }
    None
}

/// 用 DNS-over-HTTPS 查一条 SRV 记录，返回 "target:port"。
async fn doh_lookup(base: &str, name: &str) -> Option<String> {
    let url = format!("{}?name={}&type=SRV", base, name);
    let cli = reqwest::Client::builder()
        .timeout(DOH_TIMEOUT)
        .build()
        .ok()?;
    let resp = cli
        .get(&url)
        .header("Accept", "application/dns-json")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let text = resp.text().await.ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let answers = v.get("Answer")?.as_array()?;

    let mut best: Option<(u64, String)> = None;
    for a in answers {
        let rtype = match a.get("type").and_then(|x| x.as_u64()) {
            Some(t) => t,
            None => continue,
        };
        if rtype != 33 {
            continue;
        }
        let data = match a.get("data").and_then(|x| x.as_str()) {
            Some(d) => d,
            None => continue,
        };
        // DoH 返回的 data 形如 "10 5 33183 866601.xyz."
        let parts: Vec<&str> = data.split_whitespace().collect();
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
        let addr = format!("{}:{}", target, port);
        match &best {
            Some((p, _)) if *p <= prio => {}
            _ => best = Some((prio, addr)),
        }
    }
    best.map(|(_, a)| a)
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
