pub mod cache;
pub mod header;
pub mod parser;
pub mod record;
pub mod types;

use rand::TryRngCore;
use rand::rngs::OsRng;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::Duration;

use self::cache::DnsCache;
use self::parser::{build_query, parse_response};
use self::record::DnsRecord;
use self::types::PORT;

static DNS_CACHE: once_cell::sync::Lazy<DnsCache> = once_cell::sync::Lazy::new(DnsCache::new);

pub async fn resolve_domain(
    domain: &str,
    dns_server: &str,
    qtype: u16,
    use_cache: bool,
) -> Result<Vec<DnsRecord>, Box<dyn std::error::Error>> {
    // 如果启用缓存，首先检查缓存
    if use_cache {
        if let Some(records) = DNS_CACHE.get(domain, qtype) {
            return Ok(records);
        }
    }

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let dns_addr: SocketAddr = format!("{}:{}", dns_server, PORT)
        .parse()
        .map_err(|_| format!("无效的DNS服务器地址: {}", dns_server))?;

    let mut rng = OsRng;
    let query_id: u16 = rng.try_next_u32()? as u16;
    let query = build_query(domain, query_id, qtype);

    socket.send_to(&query, &dns_addr).await?;

    let mut buf = [0u8; 512];
    let timeout = Duration::from_secs(5);
    let (len, _) = tokio::time::timeout(timeout, socket.recv_from(&mut buf))
        .await
        .map_err(|_| "DNS查询超时")?
        .map_err(|e| format!("接收数据失败: {}", e))?;

    let (records, ttl) = parse_response(&buf[..len], query_id).ok_or("解析DNS响应失败")?;
    if records.is_empty() {
        return Err("未找到相关记录".into());
    }

    // 如果启用缓存，将结果存入缓存
    if use_cache {
        DNS_CACHE.insert(domain.to_string(), qtype, records.clone(), ttl);
    }
    Ok(records)
}

pub fn clear_dns_cache() {
    DNS_CACHE.clear_all();
}
