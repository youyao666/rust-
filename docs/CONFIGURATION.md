# 配置说明（Configuration）

本文档说明 `trojan-rust` 的配置文件字段、校验规则和推荐值。

默认配置文件路径：`config/config.toml`

## 完整示例

```toml
bind_addr = "0.0.0.0:443"
tls_cert = "/etc/trojan-rust/certs/cert.pem"
tls_key = "/etc/trojan-rust/certs/key.pem"
passwords = [
  "5fd924625f6ab16a19cc9807c7c506ae1813490e4ba675f843d5a10e",
]
log_level = "info"
tcp_timeout = 300
udp_timeout = 60
udp_bind_addr = "0.0.0.0:0"
max_connections = 1024
```

## 字段说明

### `bind_addr`

- 类型：`string`
- 默认值：`"0.0.0.0:443"`
- 作用：TCP 监听地址（Trojan over TLS 入口）
- 建议：生产通常使用 `0.0.0.0:443`

### `tls_cert`

- 类型：`string`
- 必填
- 作用：TLS 证书路径（PEM）
- 校验：文件必须存在

### `tls_key`

- 类型：`string`
- 必填
- 作用：TLS 私钥路径（PEM）
- 校验：文件必须存在

### `passwords`

- 类型：`array[string]`
- 必填，至少一个元素
- 作用：Trojan 用户密码哈希列表
- 校验：
  - 每个元素长度必须为 56
  - 必须为十六进制字符（SHA-224）

> 服务端保存的是哈希值，不是明文密码。

### `log_level`

- 类型：`string`
- 默认值：`"info"`
- 作用：日志级别
- 常用值：`trace` / `debug` / `info` / `warn` / `error`

### `tcp_timeout`

- 类型：`integer`（秒）
- 默认值：`300`
- 作用：TCP 相关超时参数（当前用于连接阶段）
- 建议：
  - 常规网页：`120~300`
  - 高延迟线路：可适度增大

### `udp_timeout`

- 类型：`integer`（秒）
- 默认值：`60`
- 作用：UDP Associate 会话空闲超时
- 建议：
  - 普通场景：`60`
  - 手游/语音长会话：`120~300`

### `udp_bind_addr`

- 类型：`string`
- 默认值：`"0.0.0.0:0"`
- 作用：服务端 UDP relay socket 本地绑定地址
- 校验：必须可解析为 `SocketAddr`
- 建议：保持 `0.0.0.0:0` 由系统自动分配端口

### `max_connections`

- 类型：`integer`
- 默认值：`1024`
- 作用：最大并发连接限制（通过信号量控制）
- 建议：根据 VPS 内存与 fd 限制调优

## 多用户配置

`passwords` 支持多个 hash：

```toml
passwords = [
  "hash_user_a_56_hex_chars_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "hash_user_b_56_hex_chars_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
]
```

## 安全建议

- 不要提交真实证书与私钥到仓库
- 不要提交真实生产密码 hash 到公开仓库
- 建议通过环境隔离（不同配置文件）管理测试与生产

## 常见配置错误

1. `passwords` 填了明文密码而非 SHA-224 hash
2. `tls_cert` / `tls_key` 路径不存在
3. `udp_bind_addr` 不是合法地址（如缺少端口）
4. `bind_addr` 端口被占用（443 常见）
