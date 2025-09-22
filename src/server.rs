use crate::dns::{
    self,
    header::DnsHeader,
    parser::{self, build_query},
    record::DnsRecord,
    types::CLASS_IN,
};
use log::{error, info, warn};
use rand::random;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

const MAX_DNS_PACKET_SIZE: usize = 512;
const DNS_HEADER_SIZE: usize = 12;

/// DNS服务器结构
pub struct DnsServer {
    socket: Arc<UdpSocket>,
}

impl DnsServer {
    /// 创建一个新的 DNS 服务器实例
    pub async fn new(addr: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        info!("DNS服务器启动于: {}", socket.local_addr()?);
        Ok(Self { socket })
    }

    /// 运行服务器
    pub async fn run(&self, dns_server: String, no_cache: bool) {
        let mut buf = vec![0u8; MAX_DNS_PACKET_SIZE];

        loop {
            let dns_server = dns_server.clone();
            match self.socket.recv_from(&mut buf).await {
                Ok((size, src)) => {
                    let query_data = buf[..size].to_vec();
                    let socket = self.socket.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_request(socket, query_data, src, dns_server, no_cache)
                                .await
                        {
                            error!("处理请求失败: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("接收请求失败: {}", e);
                }
            }
        }
    }

    /// 从查询报文中提取域名和查询类型
    fn parse_query(query: &[u8]) -> Option<(u16, String, u16)> {
        if query.len() < DNS_HEADER_SIZE {
            return None;
        }

        // 解析 DNS 头部
        let header = DnsHeader::from_bytes(query)?;
        if header.qdcount != 1 {
            return None;
        }

        // 解析查询的域名
        let (domain, offset) = parser::parse_domain(query, DNS_HEADER_SIZE)?;

        // 确保剩余至少4字节（查询类型和类）
        if query.len() < offset + 4 {
            return None;
        }

        // 获取查询类型
        let qtype = u16::from_be_bytes([query[offset], query[offset + 1]]);
        Some((header.id, domain, qtype))
    }

    /// 构建DNS响应报文
    fn build_response(id: u16, domain: &str, records: &[DnsRecord]) -> Vec<u8> {
        let mut response = Vec::with_capacity(MAX_DNS_PACKET_SIZE);

        // 构建响应头
        let mut header = DnsHeader::new(id);
        header.flags |= 0x8000; // 设置QR位为1，表示这是一个响应
        header.ancount = records.len() as u16;
        response.extend_from_slice(&header.to_bytes());

        // 添加查询部分
        for label in domain.split('.') {
            response.push(label.len() as u8);
            response.extend_from_slice(label.as_bytes());
        }
        response.push(0);

        // 添加原始查询类型和类
        let qtype = records.first().map(|r| r.record_type()).unwrap_or(1);
        response.extend_from_slice(&qtype.to_be_bytes());
        response.extend_from_slice(&CLASS_IN.to_be_bytes());

        // 添加回答部分
        for record in records {
            // 添加域名（使用压缩，指向查询部分）
            response.extend_from_slice(&[0xC0, 0x0C]); // 指向查询部分的域名

            // 添加记录类型和类
            response.extend_from_slice(&record.record_type().to_be_bytes());
            response.extend_from_slice(&CLASS_IN.to_be_bytes());

            // TTL（300秒）
            response.extend_from_slice(&300u32.to_be_bytes());

            // 添加记录数据
            let rdata = record.to_bytes();
            response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            response.extend_from_slice(&rdata);
        }

        response
    }

    /// 构建错误响应报文
    fn build_error_response(id: u16, domain: &str, rcode: u8) -> Vec<u8> {
        let mut response = Vec::with_capacity(MAX_DNS_PACKET_SIZE);

        // 构建错误响应头
        let mut header = DnsHeader::new(id);
        header.flags = 0x8000 | ((rcode as u16) & 0xF); // QR=1，设置错误码
        response.extend_from_slice(&header.to_bytes());

        // 添加查询部分
        for label in domain.split('.') {
            response.push(label.len() as u8);
            response.extend_from_slice(label.as_bytes());
        }
        response.push(0);

        // 添加查询类型(A)和类(IN)
        response.extend_from_slice(&1u16.to_be_bytes()); // A记录
        response.extend_from_slice(&CLASS_IN.to_be_bytes());

        response
    }

    /// 处理单个DNS请求
    async fn handle_request(
        socket: Arc<UdpSocket>,
        query: Vec<u8>,
        src: SocketAddr,
        dns_server: String,
        no_cache: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // 解析请求
        let (id, domain, qtype) = match Self::parse_query(&query) {
            Some(query_info) => query_info,
            None => {
                warn!("无效的DNS查询");
                let response = Self::build_error_response(0, "", 1); // FORMERR
                socket.send_to(&response, src).await?;
                return Ok(());
            }
        };

        info!("收到查询: {} (type={})", domain, qtype);

        match dns::resolve_domain(&domain, &dns_server, qtype, !no_cache).await {
            Ok(records) => {
                info!("解析成功: {} -> {} 条记录", domain, records.len());
                let response = if records.is_empty() {
                    Self::build_error_response(id, &domain, 3) // NXDOMAIN
                } else {
                    Self::build_response(id, &domain, &records)
                };

                socket.send_to(&response, src).await?;
            }
            Err(e) => {
                warn!("解析失败 {}: {}", domain, e);
                let response = Self::build_error_response(id, &domain, 2); // SERVFAIL
                socket.send_to(&response, src).await?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
#[tokio::test]
async fn test_dns_server_creation() {
    let server = DnsServer::new("127.0.0.1:0").await;
    assert!(server.is_ok());
}

#[tokio::test]
async fn test_parse_query() {
    // 构建一个简单的 DNS 查询数据包
    let mut query = Vec::new();

    // 添加 DNS 头部
    let header = DnsHeader::new(1234);
    query.extend_from_slice(&header.to_bytes());

    // 添加查询域名 "example.com"
    for label in "example.com".split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);

    // 添加查询类型(A记录)和类(IN)
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&CLASS_IN.to_be_bytes());

    // 测试解析
    let result = DnsServer::parse_query(&query);
    assert!(result.is_some());

    let (id, domain, qtype) = result.unwrap();
    assert_eq!(id, 1234);
    assert_eq!(domain, "example.com");
    assert_eq!(qtype, 1);
}

#[tokio::test]
async fn test_build_response() {
    let domain = "example.com";
    let id = 1234;
    let records = vec![DnsRecord::A(std::net::Ipv4Addr::new(93, 184, 216, 34))];

    let response = DnsServer::build_response(id, domain, &records);

    // 验证响应长度
    assert!(response.len() > 12); // DNS 头部长度为 12 字节

    // 验证响应头部
    let header = DnsHeader::from_bytes(&response).unwrap();
    assert_eq!(header.id, id);
    assert_eq!(header.ancount, 1);
    assert!(header.flags & 0x8000 != 0); // QR 位应该为 1
}

#[tokio::test]
async fn test_error_response() {
    let domain = "example.com";
    let id = 1234;
    let rcode = 3; // NXDOMAIN

    let response = DnsServer::build_error_response(id, domain, rcode);

    // 验证响应头部
    let header = DnsHeader::from_bytes(&response).unwrap();
    assert_eq!(header.id, id);
    assert_eq!(header.flags & 0xF, rcode as u16);
    assert!(header.flags & 0x8000 != 0); // QR 位应该为 1
}

#[tokio::test]
async fn test_resolve_domain() {
    // 测试解析 example.com 的 A 记录
    let result = dns::resolve_domain(
        "example.com",
        "8.8.8.8",
        1,     // A 记录
        false, // 不使用缓存
    )
    .await;

    assert!(result.is_ok());
    let records = result.unwrap();
    assert!(!records.is_empty());
}

#[tokio::test]
async fn test_handle_request() {
    // 创建一对 UDP socket 用于测试
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // 构建一个简单的 DNS 查询
    let mut query = Vec::new();
    let header = DnsHeader::new(1234);
    query.extend_from_slice(&header.to_bytes());
    for label in "example.com".split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1u16.to_be_bytes()); // A 记录
    query.extend_from_slice(&CLASS_IN.to_be_bytes());

    // 发送查询
    let server_addr = server_socket.local_addr().unwrap();
    client_socket.send_to(&query, server_addr).await.unwrap();

    // 处理请求
    let result = DnsServer::handle_request(
        Arc::new(server_socket),
        query,
        client_socket.local_addr().unwrap(),
        "8.8.8.8:53".to_string(),
        false,
    )
    .await;

    assert!(result.is_ok());
}
