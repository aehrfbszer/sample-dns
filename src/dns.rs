pub mod header;
pub mod parser;
pub mod record;
pub mod types;

use rand::rngs::OsRng;
use rand::TryRngCore;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::Duration;

use self::parser::{build_query, parse_response};
use self::record::DnsRecord;
use self::types::PORT;

pub async fn resolve_domain(
    domain: &str,
    dns_server: &str,
    qtype: u16,
) -> Result<Vec<DnsRecord>, Box<dyn std::error::Error>> {
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

    let records = parse_response(&buf[..len], query_id).ok_or("解析DNS响应失败")?;
    if records.is_empty() {
        return Err("未找到相关记录".into());
    }
    Ok(records)
}
