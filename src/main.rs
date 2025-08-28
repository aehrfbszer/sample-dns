use rand::TryRngCore;
use rand::rngs::OsRng;
use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket; // 使用OsRng替代thread_rng，它实现了Send
// DNS协议常量
const DNS_PORT: u16 = 53;
const TYPE_A: u16 = 1; // IPv4地址记录
const CLASS_IN: u16 = 1; // Internet类

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
fn build_query(domain: &str, query_id: u16) -> Vec<u8> {
    let mut query = Vec::new();

    // 构建头部：标准查询，递归请求
    let header = DnsHeader {
        id: query_id,
        flags: 0x0100, // 标准查询 + 递归请求
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };

    // 添加头部
    query.extend_from_slice(&header.to_bytes());

    // 构建问题部分：域名
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
    query.push(0); // 域名结束标记

    // 添加类型和类
    query.extend_from_slice(&TYPE_A.to_be_bytes());
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

// 解析DNS响应
fn parse_response(response: &[u8], query_id: u16) -> Option<Vec<Ipv4Addr>> {
    // 检查响应长度至少包含头部
    if response.len() < 12 {
        return None;
    }

    // 解析头部
    let header = DnsHeader::from_bytes(response);

    // 验证ID匹配
    if header.id != query_id {
        return None;
    }

    // 检查响应标志
    if (header.flags & 0x8000) == 0 {
        // 不是响应
        return None;
    }

    if (header.flags & 0x000F) != 0 {
        // 有错误
        return None;
    }

    // 跳过问题部分
    let mut offset = 12;

    // 解析问题部分以获取域名
    for _ in 0..header.qdcount {
        let (_, new_offset) = parse_domain(response, offset);
        offset = new_offset;
        offset += 4; // 跳过类型和类
    }

    println!("header: {:?}", header);

    // 解析回答部分
    let mut ips = Vec::new();
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
        // 如果是A记录，解析IPv4地址
        if type_ == TYPE_A && data_len == 4 {
            let Some(ip_bytes) = response.get(offset..offset + 4) else {
                continue;
            };
            let ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            ips.push(ip);
        }
        offset += data_len;
    }

    Some(ips)
}

// 异步解析域名
async fn resolve_domain(
    domain: &str,
    dns_server: &str,
) -> Result<Vec<Ipv4Addr>, Box<dyn std::error::Error>> {
    // 创建UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    // 解析DNS服务器地址
    let dns_addr: SocketAddr = format!("{}:{}", dns_server, DNS_PORT)
        .parse()
        .map_err(|_| format!("无效的DNS服务器地址: {}", dns_server))?;

    // 生成随机查询ID
    let mut rng = OsRng;
    let query_id: u16 = rng.try_next_u32().unwrap() as u16; // 使用try_next_u32并转换为u16

    // 构建查询包
    let query = build_query(domain, query_id);

    // 发送查询
    socket.send_to(&query, &dns_addr).await?;

    // 接收响应（设置超时）
    let mut buf = [0u8; 512]; // DNS响应通常不超过512字节
    let timeout = tokio::time::Duration::from_secs(5);
    let (len, _) = tokio::time::timeout(timeout, socket.recv_from(&mut buf))
        .await
        .map_err(|_| "DNS查询超时")?
        .map_err(|e| format!("接收数据失败: {}", e))?;

    // 解析响应
    let ips = parse_response(&buf[..len], query_id).ok_or("解析DNS响应失败")?;

    if ips.is_empty() {
        return Err("未找到A记录".into());
    }

    Ok(ips)
}

#[tokio::main]
async fn main() {
    // 获取命令行参数
    let args: Vec<String> = env::args().collect();

    // 解析参数：支持指定DNS服务器，默认为8.8.8.8
    let (domains, dns_server) = if args.len() >= 2 && args[1].starts_with("--dns=") {
        // 使用let-else简化模式匹配（2024特性）
        let Some(server) = args[1].split('=').nth(1) else {
            eprintln!("无效的--dns参数格式，应为--dns=服务器地址");
            std::process::exit(1);
        };
        (
            args.iter().skip(2).cloned().collect::<Vec<String>>(),
            server,
        )
    } else {
        (args.iter().skip(1).cloned().collect(), "8.8.8.8")
    };

    // 使用let-else简化条件判断（2024特性）
    if domains.is_empty() {
        eprintln!("用法: {} [--dns=服务器地址] <域名1> <域名2> ...", args[0]);
        eprintln!(
            "示例: {} --dns=114.114.114.114 example.com google.com",
            args[0]
        );
        std::process::exit(1);
    }

    println!("使用DNS服务器: {}\n", dns_server);

    // 并发解析所有域名
    let mut tasks = Vec::new();
    for domain in domains {
        let dns_server = dns_server.to_string();
        // 使用2024版更简洁的闭包语法
        tasks.push(tokio::spawn(async move {
            match resolve_domain(&domain, &dns_server).await {
                Ok(ips) => {
                    println!("{} 的解析结果:", domain);
                    for ip in ips {
                        println!("  {}", ip);
                    }
                }
                Err(e) => eprintln!("解析 {} 失败: {}", domain, e),
            }
        }));
    }

    // 等待所有任务完成
    for task in tasks {
        let _ = task.await;
    }
}
