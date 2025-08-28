use rand::TryRngCore;
use rand::rngs::OsRng;
use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket; // 使用OsRng替代thread_rng，它实现了Send
// DNS协议常量
const DNS_PORT: u16 = 53;
const TYPE_A: u16 = 1; // IPv4地址记录
const TYPE_AAAA: u16 = 28; // IPv6地址记录
const TYPE_MX: u16 = 15; // 邮件交换记录
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_SRV: u16 = 33;
const CLASS_IN: u16 = 1; // Internet类

// 解析DNS响应
#[derive(Debug)]
enum DnsRecord {
    A(Ipv4Addr),
    AAAA(std::net::Ipv6Addr),
    MX(u16, String),
    CNAME(String),
    NS(String),
    TXT(String),
    PTR(String),
    SOA(String),
    SRV(u16, u16, u16, String),
    Other(u16, Vec<u8>),
}

// DNS头部结构
#[derive(Debug)]
struct DnsHeader {
    id: u16,
    flags: u16,
    qdcount: u16, // 问题数
    ancount: u16, // 回答数
    nscount: u16, // 权威记录数
    arcount: u16, // 附加记录数
}

impl DnsHeader {
    // 序列化头部为字节数组
    fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        bytes[0..2].copy_from_slice(&self.id.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.flags.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.arcount.to_be_bytes());
        bytes
    }

    // 从字节数组解析头部
    fn from_bytes(bytes: &[u8]) -> Self {
        // 使用let-else简化错误处理（2024特性）
        let Some(header_bytes) = bytes.get(0..12) else {
            panic!("Invalid DNS header length");
        };

        DnsHeader {
            id: u16::from_be_bytes(header_bytes[0..2].try_into().unwrap()),
            flags: u16::from_be_bytes(header_bytes[2..4].try_into().unwrap()),
            qdcount: u16::from_be_bytes(header_bytes[4..6].try_into().unwrap()),
            ancount: u16::from_be_bytes(header_bytes[6..8].try_into().unwrap()),
            nscount: u16::from_be_bytes(header_bytes[8..10].try_into().unwrap()),
            arcount: u16::from_be_bytes(header_bytes[10..12].try_into().unwrap()),
        }
    }
}

// 构建DNS查询包
fn build_query(domain: &str, query_id: u16, qtype: u16) -> Vec<u8> {
    let mut query = Vec::new();
    let header = DnsHeader {
        id: query_id,
        flags: 0x0100,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };
    query.extend_from_slice(&header.to_bytes());
    let labels: Vec<&str> = domain.split('.').collect();
    for label in labels {
        if label.len() > 63 {
            panic!("标签长度不能超过63字节: {}", label);
        }
        if !label.is_empty() {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&CLASS_IN.to_be_bytes());
    query
}

// 解析域名（处理压缩）
// 另外有两点需要注意：
// (1) 一个域名仅能包含一个指针，要么只有两个字节就只包含一个指针，要么只在结尾部分跟随一个指针。
// (2) 包含指针的域名无须以字符 ‘\0’ 结尾。
fn parse_domain(response: &[u8], mut offset: usize) -> (String, usize) {
    let mut domain = String::new();
    let mut jumped = false;
    let mut original_offset = offset;
    let mut pointer_count = 0;

    while offset < response.len() {
        let len = response[offset] as usize;

        // 检查是否是指针（前两位为1）
        if (len & 0xC0) == 0xC0 {
            // 指针占2字节
            let pointer = (((response[offset] & 0x3F) as u16) << 8) | response[offset + 1] as u16;
            if !jumped {
                original_offset = offset + 2;
            }
            offset = pointer as usize;
            jumped = true;
            pointer_count += 1;
            if pointer_count > 5 {
                break;
            }
        } else if len == 0 {
            offset += 1;
            break;
        } else {
            offset += 1;
            let Some(label_bytes) = response.get(offset..offset + len) else {
                break;
            };
            if !domain.is_empty() {
                domain.push('.');
            }
            domain.push_str(&String::from_utf8_lossy(label_bytes));
            offset += len;
        }
    }
    // 只在未跳转时返回当前offset，否则返回原始offset
    let ret_offset = if jumped { original_offset } else { offset };
    (domain, ret_offset)
}

fn parse_response(response: &[u8], query_id: u16) -> Option<Vec<DnsRecord>> {
    if response.len() < 12 {
        return None;
    }
    let header = DnsHeader::from_bytes(response);
    if header.id != query_id {
        return None;
    }
    if (header.flags & 0x8000) == 0 {
        return None;
    }
    if (header.flags & 0x000F) != 0 {
        return None;
    }
    let mut offset = 12;
    for _ in 0..header.qdcount {
        let (_, new_offset) = parse_domain(response, offset);
        offset = new_offset;
        offset += 4;
    }
    let mut records = Vec::new();
    for _ in 0..header.ancount {
        let (_, new_offset) = parse_domain(response, offset);
        offset = new_offset;
        let Some(metadata) = response.get(offset..offset + 10) else {
            break;
        };
        let type_ = u16::from_be_bytes(metadata[0..2].try_into().unwrap());
        let _class = u16::from_be_bytes(metadata[2..4].try_into().unwrap());
        let _ttl = u32::from_be_bytes(metadata[4..8].try_into().unwrap());
        let data_len = u16::from_be_bytes(metadata[8..10].try_into().unwrap()) as usize;
        offset += 10;
        match (type_, data_len) {
            (TYPE_A, 4) => {
                let Some(ip_bytes) = response.get(offset..offset + 4) else {
                    continue;
                };
                records.push(DnsRecord::A(Ipv4Addr::new(
                    ip_bytes[0],
                    ip_bytes[1],
                    ip_bytes[2],
                    ip_bytes[3],
                )));
            }
            (TYPE_AAAA, 16) => {
                let Some(ip_bytes) = response.get(offset..offset + 16) else {
                    continue;
                };
                let ipv6 = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(ip_bytes).unwrap());
                records.push(DnsRecord::AAAA(ipv6));
            }
            (TYPE_MX, _) if data_len >= 3 => {
                let Some(mx_bytes) = response.get(offset..offset + data_len) else {
                    continue;
                };
                let pref = u16::from_be_bytes([mx_bytes[0], mx_bytes[1]]);
                let (mx_domain, _) = parse_domain(mx_bytes, 2);
                records.push(DnsRecord::MX(pref, mx_domain));
            }
            (TYPE_CNAME, _) | (TYPE_NS, _) | (TYPE_PTR, _) => {
                let Some(data) = response.get(offset..offset + data_len) else {
                    continue;
                };
                let (name, _) = parse_domain(data, 0);
                match type_ {
                    TYPE_CNAME => records.push(DnsRecord::CNAME(name)),
                    TYPE_NS => records.push(DnsRecord::NS(name)),
                    TYPE_PTR => records.push(DnsRecord::PTR(name)),
                    _ => {}
                }
            }
            (TYPE_TXT, _) => {
                let Some(data) = response.get(offset..offset + data_len) else {
                    continue;
                };
                let txt_len = data.get(0).copied().unwrap_or(0) as usize;
                let txt = if txt_len > 0 && txt_len + 1 <= data.len() {
                    String::from_utf8_lossy(&data[1..1 + txt_len]).to_string()
                } else {
                    String::new()
                };
                records.push(DnsRecord::TXT(txt));
            }
            (TYPE_SOA, _) => {
                let Some(data) = response.get(offset..offset + data_len) else {
                    continue;
                };
                let (mname, off1) = parse_domain(data, 0);
                let (rname, _off2) = parse_domain(data, off1);
                records.push(DnsRecord::SOA(format!("mname={}, rname={}", mname, rname)));
            }
            (TYPE_SRV, _) if data_len >= 7 => {
                let Some(data) = response.get(offset..offset + data_len) else {
                    continue;
                };
                let priority = u16::from_be_bytes([data[0], data[1]]);
                let weight = u16::from_be_bytes([data[2], data[3]]);
                let port = u16::from_be_bytes([data[4], data[5]]);
                let (target, _) = parse_domain(data, 6);
                records.push(DnsRecord::SRV(priority, weight, port, target));
            }
            (_, _) => {
                let Some(data) = response.get(offset..offset + data_len) else {
                    continue;
                };
                records.push(DnsRecord::Other(type_, data.to_vec()));
            }
        }
        offset += data_len;
    }
    Some(records)
}

// 异步解析域名
async fn resolve_domain(
    domain: &str,
    dns_server: &str,
    qtype: u16,
) -> Result<Vec<DnsRecord>, Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let dns_addr: SocketAddr = format!("{}:{}", dns_server, DNS_PORT)
        .parse()
        .map_err(|_| format!("无效的DNS服务器地址: {}", dns_server))?;
    let mut rng = OsRng;
    let query_id: u16 = rng.try_next_u32()? as u16;
    let query = build_query(domain, query_id, qtype);
    socket.send_to(&query, &dns_addr).await?;
    let mut buf = [0u8; 512];
    let timeout = tokio::time::Duration::from_secs(5);
    let (len, _) = tokio::time::timeout(timeout, socket.recv_from(&mut buf))
        .await
        .map_err(|_| "DNS查询超时")?
        .map_err(|e| format!("接收数据失败: {}", e))?;
    let records = parse_response(&buf[..len], query_id).ok_or("解析DNS响应失败")?;
    if records.is_empty() {
        return Err("未找到相关记录".into());
    }
    Ok(records)
}

#[tokio::main]
async fn main() {
    // 获取命令行参数
    let args: Vec<String> = env::args().collect();

    // 解析参数：支持指定DNS服务器和记录类型，默认为A记录和8.8.8.8
    let mut dns_server = "8.8.8.8";
    let mut qtype = TYPE_A;
    let mut domains = Vec::new();
    for arg in args.iter().skip(1) {
        if arg.starts_with("--dns=") {
            if let Some(server) = arg.split('=').nth(1) {
                dns_server = server;
            }
        } else if arg.starts_with("--type=") {
            if let Some(t) = arg.split('=').nth(1) {
                qtype = match t.to_uppercase().as_str() {
                    "A" => TYPE_A,
                    "AAAA" => TYPE_AAAA,
                    "MX" => TYPE_MX,
                    _ => {
                        eprintln!("不支持的记录类型: {}，仅支持A/AAAA/MX", t);
                        std::process::exit(1);
                    }
                };
            }
        } else {
            domains.push(arg.clone());
        }
    }

    // 使用let-else简化条件判断（2024特性）
    if domains.is_empty() {
        eprintln!(
            "用法: {} [--dns=服务器地址] [--type=类型] <域名1> <域名2> ...",
            args[0]
        );
        eprintln!(
            "示例: {} --dns=114.114.114.114 --type=MX example.com google.com",
            args[0]
        );
        std::process::exit(1);
    }

    println!(
        "使用DNS服务器: {}，记录类型: {:?}\n",
        dns_server,
        match qtype {
            TYPE_A => "A",
            TYPE_AAAA => "AAAA",
            TYPE_MX => "MX",
            _ => "Other",
        }
    );

    let mut tasks = Vec::new();
    for domain in domains {
        let dns_server = dns_server.to_string();
        let domain = domain.clone();
        tasks.push(tokio::spawn(async move {
            match resolve_domain(&domain, &dns_server, qtype).await {
                Ok(records) => {
                    println!("{} 的解析结果:", domain);
                    for rec in records {
                        match rec {
                            DnsRecord::A(ip) => println!("  A: {}", ip),
                            DnsRecord::AAAA(ipv6) => {
                                println!("  AAAA: {}", ipv6)
                            }
                            DnsRecord::MX(pref, mx) => {
                                println!("  MX: 优先级={} 域名={}", pref, mx)
                            }
                            DnsRecord::CNAME(name) => println!("  CNAME: {}", name),
                            DnsRecord::NS(name) => println!("  NS: {}", name),
                            DnsRecord::TXT(txt) => println!("  TXT: {}", txt),
                            DnsRecord::PTR(name) => println!("  PTR: {}", name),
                            DnsRecord::SOA(soa) => println!("  SOA: {}", soa),
                            DnsRecord::SRV(priority, weight, port, target) => {
                                println!(
                                    "  SRV: 优先级={} 权重={} 端口={} 目标={}",
                                    priority, weight, port, target
                                )
                            }
                            DnsRecord::Other(t, data) => println!("  其他类型 {}: {:?}", t, data),
                        }
                    }
                }
                Err(e) => eprintln!("解析 {} 失败: {}", domain, e),
            }
        }));
    }
    for task in tasks {
        let _ = task.await;
    }
}
