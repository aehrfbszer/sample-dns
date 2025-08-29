use clap::Parser;
use tokio::task;

mod cli;
mod dns;

use cli::{Args, QueryType};
use dns::types::RecordType;

#[tokio::main]
async fn main() {
    // 解析命令行参数
    let args = Args::parse();

    // 转换记录类型
    let record_type = match args.record_type {
        QueryType::A => RecordType::A,
        QueryType::AAAA => RecordType::AAAA,
        QueryType::MX => RecordType::MX,
        QueryType::CNAME => RecordType::CNAME,
        QueryType::NS => RecordType::NS,
        QueryType::TXT => RecordType::TXT,
        QueryType::PTR => RecordType::PTR,
        QueryType::SOA => RecordType::SOA,
        QueryType::SRV => RecordType::SRV,
    };

    println!(
        "使用DNS服务器: {}，记录类型: {}\n",
        args.dns, args.record_type
    );

    let mut tasks = Vec::new();
    for domain in &args.domains {
        let dns_server = args.dns.clone();
        let domain = domain.clone();
        let use_cache = !args.no_cache;
        tasks.push(task::spawn(async move {
            match dns::resolve_domain(&domain, &dns_server, record_type.as_u16(), use_cache).await {
                Ok(records) => {
                    println!("{} 的解析结果:", domain);
                    for record in records {
                        println!("  {}", record.format());
                    }
                }
                Err(e) => eprintln!("解析 {} 失败: {}", domain, e),
            }
        }));
    }

    for task in tasks {
        let _ = task.await;
    }
}
