# 部署指南（Deployment）

本文档用于将 `trojan-rust` 部署到 Linux VPS（推荐 2C2G 起步），并覆盖本地运行、Docker 运行与常见故障排查。

## 1. 环境要求

- 操作系统：Ubuntu 20.04+ / Debian 11+ / 其他主流 Linux
- 端口：`443/tcp` 与 `443/udp` 可被外网访问
- 时间同步：建议启用 NTP
- 证书：生产环境使用可信证书（例如 Let’s Encrypt）

## 2. 准备配置与证书

### 2.1 生成或准备证书

测试环境可使用项目脚本生成自签证书：

```bash
bash scripts/gen-certs.sh
```

脚本默认生成：

- `certs/cert.pem`
- `certs/key.pem`

### 2.2 生成 Trojan 密码哈希（SHA-224）

```bash
echo -n "your_password" | sha224sum
```

得到 56 位十六进制字符串后，填入 `config/config.toml` 的 `passwords`。

### 2.3 修改配置文件

编辑 `config/config.toml`：

- `bind_addr = "0.0.0.0:443"`
- `tls_cert` / `tls_key` 指向有效证书
- `passwords` 为 56 位十六进制 SHA-224 列表
- `udp_bind_addr = "0.0.0.0:0"`（推荐）
- `udp_timeout` 依据业务场景调整（手游建议适当提高）

## 3. 裸机运行（Rust）

### 3.1 编译

```bash
cargo build --release
```

### 3.2 启动

```bash
./target/release/trojan-rust -c config/config.toml
```

### 3.3 systemd（推荐）

创建 `/etc/systemd/system/trojan-rust.service`：

```ini
[Unit]
Description=trojan-rust server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/trojan-rust
ExecStart=/opt/trojan-rust/target/release/trojan-rust -c /opt/trojan-rust/config/config.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

启用并启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable trojan-rust
sudo systemctl start trojan-rust
sudo systemctl status trojan-rust
```

## 4. Docker 部署

### 4.1 构建镜像

```bash
docker build -t trojan-rust:test .
```

### 4.2 运行容器

```bash
docker run -d --name trojan-rust \
  -p 443:443/tcp -p 443:443/udp \
  -v $(pwd)/config/config.toml:/etc/trojan-rust/config.toml:ro \
  -v $(pwd)/certs:/etc/trojan-rust/certs:ro \
  trojan-rust:test
```

### 4.3 使用 docker-compose

```bash
docker compose up -d
```

查看日志：

```bash
docker compose logs -f trojan-rust
```

## 5. 验证与联调

- 检查监听：

```bash
ss -lntup | grep 443
```

- 检查容器状态：

```bash
docker ps --filter name=trojan-rust
```

- 客户端（Clash / v2rayN / Shadowrocket）配置需与服务端一致：
  - 地址/域名
  - 端口 `443`
  - Trojan 密码（原文密码，客户端会处理；服务端是 hash）
  - TLS/SNI

## 6. 常见问题

### 6.1 TLS 证书加载失败

- 检查证书路径是否存在且可读
- 证书与私钥是否匹配
- 容器挂载路径是否正确

### 6.2 认证失败（Authentication failed）

- 服务端 `passwords` 必须为 SHA-224 hex（56位）
- 客户端密码需与生成 hash 对应原文一致

### 6.3 UDP 不通

- 放行 `443/udp`
- 检查云厂商安全组 + 本机防火墙
- 适当调大 `udp_timeout`

### 6.4 容器启动后即退出

- 配置文件路径错误
- 证书未挂载
- 配置内容校验不通过（可先本地运行排错）

## 7. 生产建议

- 使用真实域名与有效证书
- 建议前置 CDN / WAF 时充分测试 TCP/UDP 行为
- 开启日志轮转，避免磁盘打满
- 使用最小权限运行（compose 已包含 `no-new-privileges`、`cap_drop`）
