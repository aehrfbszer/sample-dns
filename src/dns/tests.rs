#[cfg(test)]
mod tests {
    use crate::dns::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_dns_header() {
        // 创建一个标准的查询头部
        let mut header = header::DnsHeader::new(0x1234);
        assert_eq!(header.id, 0x1234);
        assert!(header.recursion_desired());
        assert!(!header.is_response());

        // 测试响应头部
        header.set_response(true);
        header.set_recursion_available(true);
        assert!(header.is_response());
        assert!(header.recursion_available());

        // 测试错误码
        header.set_response_code(header::RCODE_NXDOMAIN);
        assert_eq!(header.response_code(), header::RCODE_NXDOMAIN);

        // 测试序列化和反序列化
        let bytes = header.to_bytes();
        let decoded = header::DnsHeader::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.id, header.id);
        assert_eq!(decoded.flags, header.flags);
    }

    #[test]
    fn test_record_types() {
        use types::RecordType;

        // 测试从字符串解析
        assert_eq!(RecordType::from_str("A").unwrap(), RecordType::A);
        assert_eq!(RecordType::from_str("AAAA").unwrap(), RecordType::AAAA);
        assert_eq!(RecordType::from_str("MX").unwrap(), RecordType::MX);
        assert_eq!(RecordType::from_str("NS").unwrap(), RecordType::NS);
        assert_eq!(RecordType::from_str("CNAME").unwrap(), RecordType::CNAME);

        // 测试错误情况
        assert!(RecordType::from_str("INVALID").is_err());

        // 测试转换为数字类型
        assert_eq!(RecordType::A as u16, 1);
        assert_eq!(RecordType::AAAA as u16, 28);
        assert_eq!(RecordType::MX as u16, 15);
    }

    #[test]
    fn test_domain_name_parsing() {
        // 测试域名解析
        let domain = "www.example.com";
        let mut query = vec![];

        // 构建域名查询部分
        for label in domain.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);

        // 测试解析
        let (parsed_domain, offset) = parser::parse_domain(&query, 0).unwrap();
        assert_eq!(parsed_domain, domain);
        assert_eq!(offset, domain.len() + 2); // +2 for length bytes and null terminator
    }

    #[test]
    fn test_dns_record() {
        use record::DnsRecord;
        use types::RecordType;

        // 测试 A 记录
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let data = ip.octets().to_vec();
        // let record = DnsRecord::new(RecordType::A, data.clone());
        let record = DnsRecord::A(ip);

        assert_eq!(record.record_type(), RecordType::A as u16);
        assert_eq!(record.to_bytes(), data);
    }

    #[tokio::test]
    async fn test_query_building() {
        let domain = "example.com";
        let id = 0x1234;
        let record_type = types::RecordType::A;

        // 构建查询
        let query = parser::build_query(domain, id, record_type as u16);

        // 验证查询长度（至少包含头部12字节 + 域名长度 + 查询类型和类）
        assert!(query.len() > 12);

        // 验证头部
        let header = header::DnsHeader::from_bytes(&query).unwrap();
        assert_eq!(header.id, id);
        assert_eq!(header.qdcount, 1);
        assert!(!header.is_response());
        assert!(header.recursion_desired());

        // 验证域名部分
        let offset = 12;
        let (parsed_domain, _) = parser::parse_domain(&query, offset).unwrap();
        assert_eq!(parsed_domain, domain);
    }

    #[tokio::test]
    async fn test_response_parsing() {
        // 构建一个模拟的 DNS 响应
        let mut response = vec![];

        // 添加头部
        let mut header = header::DnsHeader::new(0x1234);
        header.set_response(true);
        header.set_recursion_available(true);
        header.ancount = 1;
        response.extend_from_slice(&header.to_bytes());

        // 添加查询部分
        let domain = "example.com";
        for label in domain.split('.') {
            response.push(label.len() as u8);
            response.extend_from_slice(label.as_bytes());
        }
        response.push(0);

        // 添加查询类型和类
        response.extend_from_slice(&(types::RecordType::A as u16).to_be_bytes());
        response.extend_from_slice(&types::CLASS_IN.to_be_bytes());

        // 添加应答部分
        response.extend_from_slice(&[0xC0, 0x0C]); // 压缩的域名指针
        response.extend_from_slice(&(types::RecordType::A as u16).to_be_bytes());
        response.extend_from_slice(&types::CLASS_IN.to_be_bytes());
        response.extend_from_slice(&300u32.to_be_bytes()); // TTL
        response.extend_from_slice(&4u16.to_be_bytes()); // 数据长度
        response.extend_from_slice(&[192, 168, 1, 1]); // IP地址

        // 测试响应解析
        let header = header::DnsHeader::from_bytes(&response).unwrap();
        assert!(header.is_response());
        assert_eq!(header.ancount, 1);

        let mut offset = 12;
        let (parsed_domain, new_offset) = parser::parse_domain(&response, offset).unwrap();
        assert_eq!(parsed_domain, domain);
        offset = new_offset + 4; // 跳过类型和类

        // 解析答案部分
        assert_eq!(response[offset], 0xC0);
        assert_eq!(response[offset + 1], 0x0C);
    }

    #[tokio::test]
    async fn test_cache() {
        use cache::DnsCache;
        use std::time::Duration;

        let cache = DnsCache::new();
        let domain = "example.com";
        let record_type = types::RecordType::A;
        let ip: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
        let ttl = 300;

        let record = record::DnsRecord::A(ip);

        // 添加记录到缓存
        cache.insert(domain.to_string(), record_type.as_u16(), vec![record], ttl);

        // 立即查询
        let cached = cache.get(domain, record_type.as_u16());
        assert!(cached.is_some());

        // 等待一小段时间
        tokio::time::sleep(Duration::from_secs(1)).await;

        // 记录应该还在
        let cached = cache.get(domain, record_type.as_u16());
        assert!(cached.is_some());
    }

    #[tokio::test]
    async fn test_error_handling() {
        // 测试格式错误的域名
        let result = parser::parse_domain(&[0xFF], 0);
        assert!(result.is_none());

        // 测试无效的记录类型
        let invalid_type = "INVALID";
        assert!(types::RecordType::from_str(invalid_type).is_err());

        // 测试头部解析错误
        let invalid_header = &[0u8; 11]; // 头部太短
        assert!(header::DnsHeader::from_bytes(invalid_header).is_none());
    }
}
