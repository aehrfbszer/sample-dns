use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
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
