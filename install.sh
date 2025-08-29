#!/bin/bash

# 编译项目
cargo build --release

# 创建用户和组
sudo useradd -r -s /sbin/nologin dns

# 复制二进制文件
sudo cp target/release/sample-dns /usr/local/bin/
sudo chown dns:dns /usr/local/bin/sample-dns
sudo chmod 755 /usr/local/bin/sample-dns

# 复制 systemd 服务文件
sudo cp systemd/sample-dns.service /etc/systemd/system/

# 重新加载 systemd
sudo systemctl daemon-reload

# 启用并启动服务
sudo systemctl enable sample-dns
sudo systemctl start sample-dns

echo "安装完成！"
echo "使用以下命令查看服务状态："
echo "sudo systemctl status sample-dns"
