use clap::Parser;
use rand::TryRngCore;
use rand::rngs::OsRng;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::UdpSocket;

/// DNS协议相关类型和常量
mod dns {
    use std::str::FromStr;

    /// DNS记录类型解析错误
    #[derive(Debug)]
    pub struct ParseRecordTypeError {
        message: String,
    }

    impl std::fmt::Display for ParseRecordTypeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.message)
        }
    }

    impl std::error::Error for ParseRecordTypeError {}

    /// DNS记录类型
    #[derive(Debug, Clone, Copy)]
    pub enum RecordType {
        A = 1,
        NS = 2,
        CNAME = 5,
        SOA = 6,
        PTR = 12,
        MX = 15,
        TXT = 16,
        AAAA = 28,
        SRV = 33,
    }

    impl FromStr for RecordType {
        type Err = ParseRecordTypeError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s.to_uppercase().as_str() {
                "A" => Ok(Self::A),
                "AAAA" => Ok(Self::AAAA),
                "MX" => Ok(Self::MX),
                "CNAME" => Ok(Self::CNAME),
                "NS" => Ok(Self::NS),
                "TXT" => Ok(Self::TXT),
                "PTR" => Ok(Self::PTR),
                "SOA" => Ok(Self::SOA),
                "SRV" => Ok(Self::SRV),
                _ => Err(ParseRecordTypeError {
                    message: format!("不支持的记录类型: {}", s),
                }),
            }
        }
    }

    impl RecordType {
        /// 获取记录类型的数值
        pub fn as_u16(&self) -> u16 {
            *self as u16
        }

    
    }

    /// DNS端口号
    pub const PORT: u16 = 53;
    /// DNS Internet类
    pub const CLASS_IN: u16 = 1;
}

#[derive(Parser, Debug)]
#[command(version, about = "一个简单的DNS查询工具")]
struct Args {
    /// 要查询的域名列表
    #[arg(required = true)]
    domains: Vec<String>,

    /// DNS服务器地址
    #[arg(long, default_value = "8.8.8.8")]
    dns: String,

    /// 记录类型
    #[arg(long, value_enum, default_value_t = QueryType::A)]
    record_type: QueryType,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum QueryType {
    A,
    AAAA,
    MX,
    CNAME,
    NS,
    TXT,
    PTR,
    SOA,
    SRV,
}

impl std::fmt::Display for QueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

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
    query.extend_from_slice(&dns::CLASS_IN.to_be_bytes());
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
            (t, 4) if t == dns::RecordType::A.as_u16() => {
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
            (t, 16) if t == dns::RecordType::AAAA.as_u16() => {
                let Some(ip_bytes) = response.get(offset..offset + 16) else {
                    continue;
                };
                let ipv6 = Ipv6Addr::from(<[u8; 16]>::try_from(ip_bytes).unwrap());
                records.push(DnsRecord::AAAA(ipv6));
            }
            (t, _) if t == dns::RecordType::MX.as_u16() && data_len >= 3 => {
                let Some(mx_bytes) = response.get(offset..offset + data_len) else {
                    continue;
                };
                let pref = u16::from_be_bytes([mx_bytes[0], mx_bytes[1]]);
                let (mx_domain, _) = parse_domain(mx_bytes, 2);
                records.push(DnsRecord::MX(pref, mx_domain));
            }
            (t, _)
                if matches!(t, t if t == dns::RecordType::CNAME.as_u16() 
                              || t == dns::RecordType::NS.as_u16() 
                              || t == dns::RecordType::PTR.as_u16()) =>
            {
                let Some(data) = response.get(offset..offset + data_len) else {
                    continue;
                };
                let (name, _) = parse_domain(data, 0);
                if t == dns::RecordType::CNAME.as_u16() {
                    records.push(DnsRecord::CNAME(name));
                } else if t == dns::RecordType::NS.as_u16() {
                    records.push(DnsRecord::NS(name));
                } else if t == dns::RecordType::PTR.as_u16() {
                    records.push(DnsRecord::PTR(name));
                }
            }
            (t, _) if t == dns::RecordType::TXT.as_u16() => {
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
            (t, _) if t == dns::RecordType::SOA.as_u16() => {
                let Some(data) = response.get(offset..offset + data_len) else {
                    continue;
                };
                let (mname, off1) = parse_domain(data, 0);
                let (rname, _off2) = parse_domain(data, off1);
                records.push(DnsRecord::SOA(format!("mname={}, rname={}", mname, rname)));
            }
            (t, _) if t == dns::RecordType::SRV.as_u16() && data_len >= 7 => {
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
    let dns_addr: SocketAddr = format!("{}:{}", dns_server, dns::PORT)
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
    // 使用clap解析命令行参数
    let args = Args::parse();

    // 转换记录类型为DNS类型值
    let record_type = match args.record_type {
        QueryType::A => dns::RecordType::A,
        QueryType::AAAA => dns::RecordType::AAAA,
        QueryType::MX => dns::RecordType::MX,
        QueryType::CNAME => dns::RecordType::CNAME,
        QueryType::NS => dns::RecordType::NS,
        QueryType::TXT => dns::RecordType::TXT,
        QueryType::PTR => dns::RecordType::PTR,
        QueryType::SOA => dns::RecordType::SOA,
        QueryType::SRV => dns::RecordType::SRV,
    };

    println!(
        "使用DNS服务器: {}，记录类型: {}\n",
        args.dns, args.record_type
    );

    let mut tasks = Vec::new();
    for domain in &args.domains {
        let dns_server = args.dns.clone();
        let domain = domain.clone();
        tasks.push(tokio::spawn(async move {
            match resolve_domain(&domain, &dns_server, record_type.as_u16()).await {
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
