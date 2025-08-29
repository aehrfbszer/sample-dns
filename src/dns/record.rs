use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub enum DnsRecord {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    MX(u16, String),
    CNAME(String),
    NS(String),
    TXT(String),
    PTR(String),
    SOA(String),
    SRV(u16, u16, u16, String),
    Other(u16, Vec<u8>),
}

impl DnsRecord {
    pub fn record_type(&self) -> u16 {
        match self {
            DnsRecord::A(_) => 1,
            DnsRecord::AAAA(_) => 28,
            DnsRecord::MX(_, _) => 15,
            DnsRecord::CNAME(_) => 5,
            DnsRecord::NS(_) => 2,
            DnsRecord::TXT(_) => 16,
            DnsRecord::PTR(_) => 12,
            DnsRecord::SOA(_) => 6,
            DnsRecord::SRV(_, _, _, _) => 33,
            DnsRecord::Other(type_, _) => *type_,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            DnsRecord::A(ip) => ip.octets().to_vec(),
            DnsRecord::AAAA(ip) => ip.octets().to_vec(),
            DnsRecord::MX(pref, mx) => {
                let mut data = Vec::new();
                data.extend_from_slice(&pref.to_be_bytes());
                for label in mx.split('.') {
                    data.push(label.len() as u8);
                    data.extend_from_slice(label.as_bytes());
                }
                data.push(0);
                data
            }
            DnsRecord::CNAME(name) | DnsRecord::NS(name) | DnsRecord::PTR(name) => {
                let mut data = Vec::new();
                for label in name.split('.') {
                    data.push(label.len() as u8);
                    data.extend_from_slice(label.as_bytes());
                }
                data.push(0);
                data
            }
            DnsRecord::TXT(txt) => {
                let mut data = Vec::new();
                data.push(txt.len() as u8);
                data.extend_from_slice(txt.as_bytes());
                data
            }
            DnsRecord::SOA(data) => {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(data.as_bytes());
                bytes.push(0);
                bytes
            }
            DnsRecord::SRV(priority, weight, port, target) => {
                let mut data = Vec::new();
                data.extend_from_slice(&priority.to_be_bytes());
                data.extend_from_slice(&weight.to_be_bytes());
                data.extend_from_slice(&port.to_be_bytes());
                for label in target.split('.') {
                    data.push(label.len() as u8);
                    data.extend_from_slice(label.as_bytes());
                }
                data.push(0);
                data
            }
            DnsRecord::Other(_, data) => data.clone(),
        }
    }

    pub fn format(&self) -> String {
        match self {
            DnsRecord::A(ip) => format!("A: {}", ip),
            DnsRecord::AAAA(ipv6) => format!("AAAA: {}", ipv6),
            DnsRecord::MX(pref, mx) => format!("MX: 优先级={} 域名={}", pref, mx),
            DnsRecord::CNAME(name) => format!("CNAME: {}", name),
            DnsRecord::NS(name) => format!("NS: {}", name),
            DnsRecord::TXT(txt) => format!("TXT: {}", txt),
            DnsRecord::PTR(name) => format!("PTR: {}", name),
            DnsRecord::SOA(soa) => format!("SOA: {}", soa),
            DnsRecord::SRV(priority, weight, port, target) => {
                format!(
                    "SRV: 优先级={} 权重={} 端口={} 目标={}",
                    priority, weight, port, target
                )
            }
            DnsRecord::Other(t, data) => format!("其他类型 {}: {:?}", t, data),
        }
    }
}
