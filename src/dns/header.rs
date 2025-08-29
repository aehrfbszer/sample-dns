#[derive(Debug)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16, // 问题数
    pub ancount: u16, // 回答数
    pub nscount: u16, // 权威记录数
    pub arcount: u16, // 附加记录数
}

impl DnsHeader {
    pub fn new(id: u16) -> Self {
        DnsHeader {
            id,
            flags: 0x0100, // 标准查询
            qdcount: 1,    // 一个问题
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    // 序列化头部为字节数组
    pub fn to_bytes(&self) -> [u8; 12] {
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
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let header_bytes = bytes.get(0..12)?;

        Some(DnsHeader {
            id: u16::from_be_bytes(header_bytes[0..2].try_into().ok()?),
            flags: u16::from_be_bytes(header_bytes[2..4].try_into().ok()?),
            qdcount: u16::from_be_bytes(header_bytes[4..6].try_into().ok()?),
            ancount: u16::from_be_bytes(header_bytes[6..8].try_into().ok()?),
            nscount: u16::from_be_bytes(header_bytes[8..10].try_into().ok()?),
            arcount: u16::from_be_bytes(header_bytes[10..12].try_into().ok()?),
        })
    }

    pub fn is_response(&self) -> bool {
        (self.flags & 0x8000) != 0
    }

    pub fn is_error(&self) -> bool {
        (self.flags & 0x000F) != 0
    }
}
