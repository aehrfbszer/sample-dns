use chrono::Local;
use env_logger::{Builder, WriteStyle};
use log::LevelFilter;
use std::io::Write;

pub fn init_logger() {
    Builder::new()
        .write_style(WriteStyle::Always)
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .filter(None, LevelFilter::Info)
        .init();
}
