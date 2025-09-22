use std::str::FromStr;

/// DNS记录类型解析错误
#[derive(Debug)]
pub struct ParseRecordTypeError {
    message: String,
}

impl std::fmt::Display for ParseRecordTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ParseRecordTypeError {}

/// DNS记录类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
}

impl FromStr for RecordType {
    type Err = ParseRecordTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::AAAA),
            "MX" => Ok(Self::MX),
            "CNAME" => Ok(Self::CNAME),
            "NS" => Ok(Self::NS),
            "TXT" => Ok(Self::TXT),
            "PTR" => Ok(Self::PTR),
            "SOA" => Ok(Self::SOA),
            "SRV" => Ok(Self::SRV),
            _ => Err(ParseRecordTypeError {
                message: format!("不支持的记录类型: {}", s),
            }),
        }
    }
}

impl RecordType {
    /// 获取记录类型的数值
    pub fn as_u16(&self) -> u16 {
        *self as u16
    }
}

/// DNS协议常量
pub const PORT: u16 = 53;
pub const CLASS_IN: u16 = 1;
