use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about = "一个简单的DNS查询工具")]
pub struct Args {
    /// 要查询的域名列表
    #[arg(required = true)]
    pub domains: Vec<String>,

    /// DNS服务器地址
    #[arg(long, default_value = "8.8.8.8")]
    pub dns: String,

    /// 记录类型
    #[arg(long, value_enum, default_value_t = QueryType::A)]
    pub record_type: QueryType,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum QueryType {
    A,
    AAAA,
    MX,
    CNAME,
    NS,
    TXT,
    PTR,
    SOA,
    SRV,
}

impl std::fmt::Display for QueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
