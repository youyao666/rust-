# trojan-rust

一个基于 Rust + Tokio 实现的轻量级、高性能 Trojan 协议服务端，面向低资源 VPS 场景（如 2C2G）。

## 特性

- 严格的 Trojan 协议头解析（密码哈希、CRLF、TCP/UDP 指令、目标地址）
- TLS 终止（`rustls` + `tokio-rustls`）
- TCP 双向流式转发（`copy_bidirectional`）
- UDP Associate 转发（含超时控制、域名解析、异常处理）
- 强化错误处理与配置校验（避免运行时 panic）
- 云原生交付：多阶段构建 + `scratch` 运行时镜像
- CI 工作流（fmt / clippy / test / docker build-push）

## 目录结构

```text
.
├── src/
├── tests/
├── benches/
├── config/
├── Dockerfile
├── docker-compose.yml
└── .github/workflows/docker-publish.yml
```

## 快速开始

### 1) 准备证书

测试环境可使用自签证书：

```bash
bash scripts/gen-certs.sh
```

生产环境建议改用可信证书（例如 Let’s Encrypt），并更新配置中的证书路径。

### 2) 生成 Trojan 密码哈希（SHA-224）

Linux/macOS/WSL:

```bash
echo -n "your_password" | sha224sum
```

OpenSSL（跨平台可用，需安装 OpenSSL）:

```bash
echo -n "your_password" | openssl dgst -sha224
```

Python（跨平台）:

```bash
python -c "import hashlib; print(hashlib.sha224(b'your_password').hexdigest())"
```

> 注：配置中 `passwords` 字段必须是 56 位十六进制 SHA-224 字符串。

### 3) 修改配置

编辑 `config/config.toml`，至少确认以下字段：

- `bind_addr`
- `tls_cert`
- `tls_key`
- `passwords`（56位十六进制 SHA-224）
- `udp_timeout`
- `udp_bind_addr`

### 4) 本地运行

```bash
cargo run --release -- -c config/config.toml
```

## Docker 运行

### 构建镜像

```bash
docker build -t trojan-rust:test .
```

### 启动容器

```bash
docker run -d --name trojan-rust \
  -p 443:443/tcp -p 443:443/udp \
  -v $(pwd)/config/config.toml:/etc/trojan-rust/config.toml:ro \
  -v $(pwd)/certs:/etc/trojan-rust/certs:ro \
  trojan-rust:test
```

或使用：

```bash
docker compose up -d
```

## 质量验证

```bash
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --verbose
cargo bench --bench throughput
```

## 客户端兼容性

- Clash
- v2rayN
- Shadowrocket

客户端需配置为 Trojan 协议，并与服务端证书/域名、端口、密码哈希对应。

## 文档

- [部署指南](docs/DEPLOYMENT.md)
- [配置说明](docs/CONFIGURATION.md)
- [发布清单](docs/RELEASE_CHECKLIST.md)

## 许可证

`MIT OR Apache-2.0`

## 免责声明

本项目仅用于合法合规的网络安全与隐私保护用途。使用者应自行确保遵守所在地区法律法规。
