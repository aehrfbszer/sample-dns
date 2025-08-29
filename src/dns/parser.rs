use super::header::DnsHeader;
use super::record::DnsRecord;
use super::types::{RecordType, CLASS_IN};
use std::net::{Ipv4Addr, Ipv6Addr};

pub fn build_query(domain: &str, query_id: u16, qtype: u16) -> Vec<u8> {
    let mut query = Vec::new();
    let header = DnsHeader::new(query_id);
    query.extend_from_slice(&header.to_bytes());

    // 添加域名标签
    for label in domain.split('.') {
        if !label.is_empty() {
            if label.len() > 63 {
                panic!("标签长度不能超过63字节: {}", label);
            }
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
    }
    query.push(0);

    // 添加查询类型和类
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&CLASS_IN.to_be_bytes());
    query
}

pub fn parse_domain(response: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut domain = String::new();
    let mut jumped = false;
    let mut original_offset = offset;
    let mut pointer_count = 0;

    while offset < response.len() {
        let len = response[offset] as usize;

        // 检查是否是指针（前两位为1）
        if (len & 0xC0) == 0xC0 {
            // 指针占2字节
            if offset + 1 >= response.len() {
                return None;
            }
            let pointer = (((response[offset] & 0x3F) as u16) << 8) | response[offset + 1] as u16;
            if !jumped {
                original_offset = offset + 2;
            }
            offset = pointer as usize;
            jumped = true;
            pointer_count += 1;
            if pointer_count > 5 {
                return None;
            }
        } else if len == 0 {
            offset += 1;
            break;
        } else {
            offset += 1;
            let label_bytes = response.get(offset..offset + len)?;
            if !domain.is_empty() {
                domain.push('.');
            }
            domain.push_str(&String::from_utf8_lossy(label_bytes));
            offset += len;
        }
    }

    Some((domain, if jumped { original_offset } else { offset }))
}

pub fn parse_response(response: &[u8], query_id: u16) -> Option<(Vec<DnsRecord>, u32)> {
    let header = DnsHeader::from_bytes(response)?;
    if header.id != query_id || !header.is_response() || header.is_error() {
        return None;
    }

    let mut offset = 12;
    for _ in 0..header.qdcount {
        let (_, new_offset) = parse_domain(response, offset)?;
        offset = new_offset + 4; // 跳过类型和类字段
    }

    let mut records = Vec::new();
    let mut min_ttl = u32::MAX;
    for _ in 0..header.ancount {
        let (_, new_offset) = parse_domain(response, offset)?;
        offset = new_offset;

        let metadata = response.get(offset..offset + 10)?;
        let type_ = u16::from_be_bytes(metadata[0..2].try_into().ok()?);
        let ttl = u32::from_be_bytes(metadata[4..8].try_into().ok()?);
        let data_len = u16::from_be_bytes(metadata[8..10].try_into().ok()?) as usize;
        min_ttl = min_ttl.min(ttl);
        offset += 10;

        match (type_, data_len) {
            (t, 4) if t == RecordType::A.as_u16() => {
                let ip_bytes = response.get(offset..offset + 4)?;
                records.push(DnsRecord::A(Ipv4Addr::new(
                    ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                )));
            }
            (t, 16) if t == RecordType::AAAA.as_u16() => {
                let ip_bytes = response.get(offset..offset + 16)?;
                let ipv6 = Ipv6Addr::from(<[u8; 16]>::try_from(ip_bytes).ok()?);
                records.push(DnsRecord::AAAA(ipv6));
            }
            (t, _) if t == RecordType::MX.as_u16() && data_len >= 3 => {
                let mx_bytes = response.get(offset..offset + data_len)?;
                let pref = u16::from_be_bytes([mx_bytes[0], mx_bytes[1]]);
                let (mx_domain, _) = parse_domain(mx_bytes, 2)?;
                records.push(DnsRecord::MX(pref, mx_domain));
            }
            (t, _)
                if matches!(t,
                    t if t == RecordType::CNAME.as_u16()
                        || t == RecordType::NS.as_u16()
                        || t == RecordType::PTR.as_u16()) =>
            {
                let data = response.get(offset..offset + data_len)?;
                let (name, _) = parse_domain(data, 0)?;
                let record = match t {
                    t if t == RecordType::CNAME.as_u16() => DnsRecord::CNAME(name),
                    t if t == RecordType::NS.as_u16() => DnsRecord::NS(name),
                    t if t == RecordType::PTR.as_u16() => DnsRecord::PTR(name),
                    _ => unreachable!(),
                };
                records.push(record);
            }
            (t, _) if t == RecordType::TXT.as_u16() => {
                let data = response.get(offset..offset + data_len)?;
                let txt_len = data.get(0).copied().unwrap_or(0) as usize;
                let txt = if txt_len > 0 && txt_len + 1 <= data.len() {
                    String::from_utf8_lossy(&data[1..1 + txt_len]).to_string()
                } else {
                    String::new()
                };
                records.push(DnsRecord::TXT(txt));
            }
            (t, _) if t == RecordType::SOA.as_u16() => {
                let data = response.get(offset..offset + data_len)?;
                let (mname, off1) = parse_domain(data, 0)?;
                let (rname, _) = parse_domain(data, off1)?;
                records.push(DnsRecord::SOA(format!("mname={}, rname={}", mname, rname)));
            }
            (t, _) if t == RecordType::SRV.as_u16() && data_len >= 7 => {
                let data = response.get(offset..offset + data_len)?;
                let priority = u16::from_be_bytes([data[0], data[1]]);
                let weight = u16::from_be_bytes([data[2], data[3]]);
                let port = u16::from_be_bytes([data[4], data[5]]);
                let (target, _) = parse_domain(data, 6)?;
                records.push(DnsRecord::SRV(priority, weight, port, target));
            }
            (t, _) => {
                let data = response.get(offset..offset + data_len)?.to_vec();
                records.push(DnsRecord::Other(t, data));
            }
        }
        offset += data_len;
    }
    Some((records, if min_ttl == u32::MAX { 300 } else { min_ttl }))
}
