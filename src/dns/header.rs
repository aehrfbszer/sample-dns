#[derive(Debug)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16, // 问题数
    pub ancount: u16, // 回答数
    pub nscount: u16, // 权威记录数
    pub arcount: u16, // 附加记录数
}

// DNS Header Flags
pub const QR_MASK: u16 = 0x8000; // Query/Response Flag
pub const OPCODE_MASK: u16 = 0x7800; // Operation Code
pub const AA_MASK: u16 = 0x0400; // Authoritative Answer Flag
pub const TC_MASK: u16 = 0x0200; // Truncation Flag
pub const RD_MASK: u16 = 0x0100; // Recursion Desired
pub const RA_MASK: u16 = 0x0080; // Recursion Available
pub const Z_MASK: u16 = 0x0070; // Reserved for future use
pub const RCODE_MASK: u16 = 0x000F; // Response Code

// Operation Codes
pub const OPCODE_QUERY: u16 = 0 << 11; // Standard query
pub const OPCODE_IQUERY: u16 = 1 << 11; // Inverse query
pub const OPCODE_STATUS: u16 = 2 << 11; // Server status request

// Response Codes
pub const RCODE_NOERROR: u8 = 0; // No error condition
pub const RCODE_FORMERR: u8 = 1; // Format error
pub const RCODE_SERVFAIL: u8 = 2; // Server failure
pub const RCODE_NXDOMAIN: u8 = 3; // Name Error
pub const RCODE_NOTIMP: u8 = 4; // Not Implemented
pub const RCODE_REFUSED: u8 = 5; // Refused

impl DnsHeader {
    pub fn new(id: u16) -> Self {
        DnsHeader {
            id,
            flags: RD_MASK, // 标准查询，要求递归
            qdcount: 1,     // 一个问题
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    pub fn new_response(request: &DnsHeader) -> Self {
        DnsHeader {
            id: request.id,
            flags: QR_MASK | RD_MASK | RA_MASK, // 响应，支持递归
            qdcount: request.qdcount,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    // Flag getters
    pub fn is_response(&self) -> bool {
        (self.flags & QR_MASK) != 0
    }

    pub fn opcode(&self) -> u8 {
        ((self.flags & OPCODE_MASK) >> 11) as u8
    }

    pub fn is_authoritative(&self) -> bool {
        (self.flags & AA_MASK) != 0
    }

    pub fn is_truncated(&self) -> bool {
        (self.flags & TC_MASK) != 0
    }

    pub fn recursion_desired(&self) -> bool {
        (self.flags & RD_MASK) != 0
    }

    pub fn recursion_available(&self) -> bool {
        (self.flags & RA_MASK) != 0
    }

    pub fn response_code(&self) -> u8 {
        (self.flags & RCODE_MASK) as u8
    }

    // Flag setters
    pub fn set_response(&mut self, value: bool) {
        if value {
            self.flags |= QR_MASK;
        } else {
            self.flags &= !QR_MASK;
        }
    }

    pub fn set_opcode(&mut self, opcode: u8) {
        self.flags &= !OPCODE_MASK;
        self.flags |= (opcode as u16 & 0x0F) << 11;
    }

    pub fn set_authoritative(&mut self, value: bool) {
        if value {
            self.flags |= AA_MASK;
        } else {
            self.flags &= !AA_MASK;
        }
    }

    pub fn set_truncated(&mut self, value: bool) {
        if value {
            self.flags |= TC_MASK;
        } else {
            self.flags &= !TC_MASK;
        }
    }

    pub fn set_recursion_desired(&mut self, value: bool) {
        if value {
            self.flags |= RD_MASK;
        } else {
            self.flags &= !RD_MASK;
        }
    }

    pub fn set_recursion_available(&mut self, value: bool) {
        if value {
            self.flags |= RA_MASK;
        } else {
            self.flags &= !RA_MASK;
        }
    }

    pub fn set_response_code(&mut self, rcode: u8) {
        self.flags &= !RCODE_MASK;
        self.flags |= rcode as u16 & 0x0F;
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

    pub fn is_error(&self) -> bool {
        (self.flags & 0x000F) != 0
    }
}
