# Trojan-Rust 部署指南

本文件夹包含所有必要的文件，用于通过 GitHub Actions 自动构建和部署 Trojan-Rust Docker 镜像。

## 📁 文件结构

```
github-deploy/
├── .github/
│   └── workflows/
│       └── docker-publish.yml    # GitHub Actions CI/CD 工作流
├── src/                          # Rust 源代码
│   ├── protocol/                 # Trojan 协议解析
│   ├── proxy/                    # 代理核心逻辑
│   ├── reality/                  # XTLS-Reality 转发层
│   └── *.rs                      # 其他核心模块
├── config/
│   └── config.toml              # 配置文件模板
├── scripts/
│   └── gen-certs.sh             # 证书生成脚本
├── Cargo.toml                    # Rust 依赖配置
├── Cargo.lock                    # 依赖锁定文件
├── Dockerfile                    # Docker 多阶段构建配置
├── docker-compose.yml            # Docker Compose 部署配置
└── .dockerignore                 # Docker 构建忽略文件
```

## 🚀 使用方法

### 方法一：推送到 GitHub 仓库（推荐）

1. **将本文件夹内容推送到 GitHub 仓库**
   ```bash
   cd github-deploy
   git init
   git add .
   git commit -m "Initial commit: Trojan-Rust deployment files"
   git branch -M main
   git remote add origin <your-github-repo-url>
   git push -u origin main
   ```

2. **配置 GitHub Container Registry 权限**
   - 访问 GitHub 仓库 Settings → Actions → General
   - 确保 Workflow permissions 设置为 "Read and write permissions"
   - 启用 "Allow GitHub Actions to create and approve pull requests"

3. **等待自动构建**
   - 推送到 main 分支会自动触发构建
   - 创建 Tag 会发布新版本并推送镜像到 ghcr.io

### 方法二：本地构建 Docker 镜像

```bash
cd github-deploy

# 构建 Docker 镜像
docker build -t trojan-rust:latest .

# 或使用 docker-compose
docker-compose up -d
```

## 🔧 配置步骤

### 1. 生成证书

在部署前需要生成 TLS 证书：

```bash
# 使用 Let's Encrypt（推荐生产环境）
# 访问 https://letsencrypt.org/ 获取免费证书

# 或使用自签名证书（仅测试）
chmod +x scripts/gen-certs.sh
./scripts/gen-certs.sh
```

### 2. 修改配置文件

编辑 `config/config.toml`：

```toml
[server]
listen = "0.0.0.0:443"
password = "your_password_here"

[tls]
cert = "/etc/trojan-rust/cert.pem"
key = "/etc/trojan-rust/key.pem"

[reality]
enabled = true
target_domain = "example.com"  # 伪装的目标域名
```

### 3. 部署到服务器

```bash
# 使用 docker-compose 部署
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

## 📦 GitHub Actions 工作流说明

### 触发条件

- **推送到 main 分支**：自动构建并推送 `latest` 标签镜像
- **创建 Tag**：构建并推送版本标签镜像（如 `v1.0.0`）

### 镜像地址

构建完成后，镜像将推送到：
```
ghcr.io/<username>/<repository>:latest
ghcr.io/<username>/<repository>:<tag>
```

### 使用 GitHub 镜像

在服务器上拉取镜像：

```bash
# 登录到 GitHub Container Registry
echo $GITHUB_TOKEN | docker login ghcr.io -u <username> --password-stdin

# 拉取镜像
docker pull ghcr.io/<username>/<repository>:latest

# 运行容器
docker run -d \
  --name trojan-rust \
  -p 443:443 \
  -v /path/to/config.toml:/etc/trojan-rust/config.toml \
  -v /path/to/cert.pem:/etc/trojan-rust/cert.pem \
  -v /path/to/key.pem:/etc/trojan-rust/key.pem \
  ghcr.io/<username>/<repository>:latest
```

## 🔒 安全建议

1. **使用强密码**：配置文件中的密码应使用强随机密码
2. **使用真实证书**：生产环境建议使用 Let's Encrypt 等 CA 签发的证书
3. **启用防火墙**：仅开放必要的端口（443）
4. **定期更新**：保持代码和依赖更新，修复安全漏洞
5. **监控日志**：定期检查服务日志，发现异常行为

## 📊 性能优化

### 针对 2 核 2G VPS 优化

- 使用 Release 模式构建，性能提升 3-5 倍
- 启用 LTO（Link Time Optimization）进一步减小二进制体积
- 使用 Alpine 基础镜像，镜像体积 < 20MB
- 内存占用 < 50MB（空闲时）

### 内核参数调优（可选）

```bash
# /etc/sysctl.conf
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_slow_start_after_idle = 0
```

## 🐛 故障排查

### 容器无法启动

```bash
# 查看容器日志
docker logs trojan-rust

# 检查配置文件
docker exec trojan-rust cat /etc/trojan-rust/config.toml

# 检查证书文件
docker exec trojan-rust ls -la /etc/trojan-rust/
```

### 连接被拒绝

1. 检查防火墙是否开放 443 端口
2. 检查证书是否有效
3. 检查配置文件中的监听地址
4. 查看服务端日志

### 性能问题

```bash
# 查看资源占用
docker stats trojan-rust

# 检查连接数
docker exec trojan-rust netstat -an | grep ESTABLISHED | wc -l
```

## 📝 许可证

本项目开源，遵循相应的开源协议。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📧 联系方式

如有问题，请通过 GitHub Issues 联系。
