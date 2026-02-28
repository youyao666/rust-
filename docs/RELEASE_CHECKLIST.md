# 发布清单（Release Checklist）

用于 GitHub 开源发布与版本上线前的最终核对。

## 1. 代码与质量门禁

- [ ] `cargo fmt -- --check` 通过
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` 通过
- [ ] `cargo test --all-targets --verbose` 通过
- [ ] `cargo bench --bench throughput` 可运行并记录结果
- [ ] 无 `unwrap` / `expect` 的关键路径风险点（已审查）

## 2. 协议与功能验证

- [ ] Trojan 头解析符合规范（密码 hash / CRLF / CMD / 地址）
- [ ] TCP 转发双向可用
- [ ] UDP Associate 转发稳定（长时间场景）
- [ ] 认证失败行为正确（拒绝并记录日志）
- [ ] 关键日志具备可观测性（连接、认证、异常）

## 3. 配置与安全

- [ ] 默认配置文件可用（`config/config.toml`）
- [ ] 配置字段校验有效（证书路径、hash、socket addr）
- [ ] 生产证书已替换测试证书
- [ ] 密码 hash 非示例值，且妥善保管原文密码
- [ ] 防火墙/安全组放行 `443/tcp` 与 `443/udp`

## 4. 容器与部署

- [ ] `docker build -t trojan-rust:test .` 成功
- [ ] `docker run --rm trojan-rust:test --help` 成功
- [ ] `docker compose up -d` 可启动
- [ ] 容器日志正常，无启动错误
- [ ] `read_only`、`cap_drop`、`no-new-privileges` 等安全选项有效

## 5. CI/CD 与供应链

- [ ] GitHub Actions 工作流执行成功
- [ ] GHCR 镜像可拉取
- [ ] 多架构镜像（amd64/arm64）构建成功
- [ ] SBOM / provenance 已启用
- [ ] Release tag（如 `v0.1.0`）触发发布流程

## 6. 文档完整性

- [ ] README 覆盖快速开始、Docker、验证、兼容客户端
- [ ] 部署指南完整（`docs/DEPLOYMENT.md`）
- [ ] 配置说明完整（`docs/CONFIGURATION.md`）
- [ ] 发布清单完整（本文件）
- [ ] LICENSE 与仓库元信息（描述、标签）完善

## 7. 发布动作建议

1. 更新版本号（`Cargo.toml`）
2. 提交变更并打 Tag：

```bash
git add .
git commit -m "release: v0.1.0"
git tag v0.1.0
git push origin main --tags
```

3. 在 GitHub Release 补充：
   - 变更摘要（新增/修复/破坏性变更）
   - 部署提示
   - 已知限制

## 8. 回滚预案

- 保留上一个稳定版本镜像 tag
- 保留上一个稳定配置备份
- 若出现严重异常，先回滚镜像与配置，再排查问题
