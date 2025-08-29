use clap::Parser;
use tokio::task;
use log::info;

mod cli;
mod dns;
mod logging;
mod server;

use cli::{Args, QueryType};
use dns::types::RecordType;
use server::DnsServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    // 如果是守护进程模式，初始化日志并启动服务器
    if args.daemon {
        logging::init_logger();
        info!("DNS服务启动中...");
        
        let server = DnsServer::new(&args.listen).await?;
        server.run(args.dns, args.no_cache).await;
        Ok(())
    } else {
        // 命令行模式
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
        Ok(())
    }
}
