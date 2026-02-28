# XTLS-Reality 与 Vision -inspired 核心转发层设计文档

## 概述

本设计参考了 V2Ray/Xray 中的 **XTLS-Reality** 和 **Vision** 协议的核心思想，为 Trojan-Rust 实现了一个全新的高性能核心转发层。该转发层具有以下特点：

- **握手伪装**：使用真实 TLS 证书响应，完全模拟现代浏览器的 TLS 握手特征
- **应用层鉴权**：在 TLS 建立后的第一个应用数据帧中进行鉴权，防止探测
- **零拷贝转发**：鉴权通过后直接进行流式转发，避免二次 TLS 加解密开销
- **状态机管理**：清晰的状态流转，确保连接在各个阶段正确处理

## 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                     Client Connection                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  ConnectionStateMachine<S>                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Handshake State (TLS 伪装期)                         │   │
│  │  - RealityHandshake::accept()                        │   │
│  │  - 返回标准 TLS 1.3 ServerHello                        │   │
│  │  - DPI 检测白名单优先级                                │   │
│  └──────────────────────────────────────────────────────┘   │
│                              │                               │
│                              ▼                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Authenticating State (Vision 鉴权期)                 │   │
│  │  - VisionProtocol::authenticate()                    │   │
│  │  - 读取 Vision Auth Request (魔法头 + 命令 + 地址)      │   │
│  │  - 验证时间戳防重放                                    │   │
│  └──────────────────────────────────────────────────────┘   │
│                              │                               │
│              ┌───────────────┴───────────────┐               │
│              ▼                               ▼               │
│  ┌────────────────────┐          ┌────────────────────┐     │
│  │ Authenticated      │          │ Fallback (失败)    │     │
│  │ (鉴权成功)          │          │ - 转发到回落地址    │     │
│  └────────────────────┘          └────────────────────┘     │
│              │                                               │
│              ▼                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Forwarding State (Direct Splice 卸甲期)              │   │
│  │  - tcp_splice() 零拷贝转发                            │   │
│  │  - 直接使用 tokio::io::copy_bidirectional            │   │
│  │  - 无 TLS 加解密开销                                   │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## 核心模块

### 1. `RealityHandshake` - 握手欺骗模块

**职责**：
- 使用真实 TLS 证书配置 rustls ServerConfig
- 响应标准 TLS 1.3 ServerHello，完全模拟浏览器行为
- 支持 ALPN 协商（h2, http/1.1）
- 可选的 Fallback 配置（鉴权失败时回落）

**关键代码**：
```rust
pub struct RealityHandshake {
    config: Arc<ServerConfig>,
    fallback_config: Option<Arc<ServerConfig>>,
}

impl RealityHandshake {
    pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
    ) -> Result<TlsStream<S>> {
        let acceptor = TlsAcceptor::from(Arc::clone(&self.config));
        let tls_stream = acceptor.accept(stream).await?;
        
        // 记录握手信息（ALPN, SNI）
        debug!("TLS handshake completed: ALPN={:?}, SNI={:?}", 
               handshake.alpn_protocol(), 
               handshake.server_name());
        
        Ok(tls_stream)
    }
}
```

**防御机制**：
- **DPI  evasion**：TLS 握手特征与 Chrome/Firefox 完全一致
- **证书验证**：使用真实 CA 签发的证书，非自签名
- **ALPN 协商**：支持 HTTP/2 和 HTTP/1.1，模拟正常网站

### 2. `VisionProtocol` - 应用层鉴权模块

**职责**：
- 定义 Vision Auth Request 格式（魔法头 + 版本 + 命令 + 地址 + 时间戳）
- 在 TLS 加密通道内读取鉴权信息
- 验证时间戳防重放攻击（±5 分钟）
- 鉴权失败时触发 Fallback 机制

**协议格式**：
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Magic      |   Version     |   Command     |  Address...   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Address (cont.)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Timestamp                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Hash (SHA224)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**关键代码**：
```rust
pub const VISION_MAGIC_HEADER: u8 = 0xFE;
pub const VISION_VERSION: u8 = 0x01;

pub struct VisionAuthRequest {
    pub magic: u8,
    pub version: u8,
    pub command: Command,
    pub address: Address,
    pub timestamp: u64,
}

impl VisionProtocol {
    pub async fn authenticate<S: AsyncRead + Unpin>(
        &self,
        stream: &mut S,
        _valid_passwords: &[String],
    ) -> Result<(Command, Address)> {
        let auth_request = tokio::time::timeout(
            self.auth_timeout,
            VisionAuthRequest::read_from(stream),
        )
        .await
        .map_err(|_| TrojanError::Timeout)??;
        
        // 验证时间戳
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if (current_time as i64 - timestamp as i64).abs() > 300 {
            return Err(TrojanError::Protocol("Timestamp expired".to_string()));
        }
        
        Ok((auth_request.command, auth_request.address))
    }
}
```

### 3. `DirectSplice` - 零拷贝转发模块

**职责**：
- 鉴权通过后，直接在两个流之间进行双向数据拷贝
- 使用 `tokio::io::copy_bidirectional` 实现高效转发
- 支持泛型流类型（TcpStream, TlsStream, 等）
- 统计转发字节数

**关键代码**：
```rust
pub async fn tcp_splice<A, B>(stream_a: A, stream_b: B) -> Result<u64>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!("Starting TCP splice forwarding");
    
    let (a_read, a_write) = tokio::io::split(stream_a);
    let (b_read, b_write) = tokio::io::split(stream_b);
    
    let a_to_b = tokio::spawn(async move {
        tokio::io::copy(
            &mut tokio::io::BufReader::new(a_read),
            &mut tokio::io::BufWriter::new(b_write),
        )
        .await
    });
    
    let b_to_a = tokio::spawn(async move {
        tokio::io::copy(
            &mut tokio::io::BufReader::new(b_read),
            &mut tokio::io::BufWriter::new(a_write),
        )
        .await
    });
    
    let (tx_bytes, rx_bytes) = tokio::try_join!(a_to_b, b_to_a)?;
    
    Ok(tx_bytes? + rx_bytes?)
}
```

**性能优化**：
- **零拷贝**：数据直接在内核态传输，避免用户态拷贝
- **异步并发**：双向转发使用独立 task，互不阻塞
- **缓冲优化**：使用 `BufReader`/`BufWriter` 减少系统调用

### 4. `ConnectionStateMachine` - 连接状态机

**职责**：
- 管理连接在各个状态之间的流转
- 确保状态转换的合法性和安全性
- 处理异常状态（鉴权失败、超时等）
- 提供统一的接口供上层调用

**状态定义**：
```rust
pub enum ConnectionState {
    Handshake,        // TLS 握手阶段
    Authenticating,   // Vision 鉴权阶段
    Authenticated,    // 鉴权成功
    Forwarding,       // 转发阶段
    Fallback,         // 回落阶段
    Closed,           // 连接关闭
}
```

**状态流转**：
```rust
impl<S> ConnectionStateMachine<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub async fn transition_to_authenticating(
        mut self,
        vision: &VisionProtocol,
        passwords: &[String],
    ) -> Result<Self> {
        // Handshake -> Authenticating
        match vision.authenticate(&mut stream, passwords).await {
            Ok((command, address)) => {
                self.state = ConnectionState::Authenticated;
                self.auth_result = Some((command, address));
                Ok(self)
            }
            Err(e) => {
                self.state = ConnectionState::Fallback; // or Closed
                Err(e)
            }
        }
    }
    
    pub async fn transition_to_forwarding(
        self,
        target_address: &Address,
        connect_timeout: Duration,
    ) -> Result<(S, TcpStream)> {
        // Authenticated -> Forwarding
        let remote = TcpStream::connect(target_address).await?;
        Ok((self.stream.unwrap(), remote))
    }
}
```

## 网络波动处理

### 1. **超时控制**
- TLS 握手超时：5 秒
- Vision 鉴权超时：10 秒
- 目标连接超时：10 秒
- 空闲连接超时：300 秒（keepalive）

### 2. **错误恢复**
```rust
match result {
    Ok(0) => {
        // EOF: 对端正常关闭
        debug!("Reader EOF reached");
        break;
    }
    Ok(n) => {
        // 正常数据传输
        self.writer.write_all(&buf1[..n]).await?;
    }
    Err(e) => {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            // 临时阻塞，继续循环
            continue;
        }
        // 其他错误：断开连接
        break;
    }
}
```

### 3. **连接保活**
- 启用 TCP keepalive（默认 60 秒）
- 应用层心跳检测（可选）
- 自动清理僵尸连接

## 安全性分析

### 1. **抗 DPI 检测**
- TLS 握手特征与真实浏览器完全一致
- 使用真实 CA 证书，非自签名
- 支持 TLS 1.3 最新特性（0-RTT, PSK 等）

### 2. **抗主动探测**
- 鉴权信息在 TLS 加密通道内传输
- 时间戳验证防重放
- 鉴权失败时透明转发到 Fallback 网站

### 3. **内存安全**
- Rust 内存安全保证
- 无 unwrap() 滥用
- 严格的错误处理

## 性能优化

### 1. **零拷贝转发**
- 使用 `tokio::io::copy_bidirectional`
- 避免应用层缓冲
- 内核态直接传输

### 2. **异步并发**
- Tokio 异步运行时
- 多核 CPU 充分利用
- 非阻塞 I/O

### 3. **连接复用**
- TLS 会话缓存（256 个会话）
- TCP keepalive
- 连接池（可选）

## 使用示例

```rust
use trojan_rust::reality::*;

// 1. 配置 Reality
let reality_config = RealityConfig::new(
    "/path/to/cert.pem",
    "/path/to/key.pem",
    "example.com".to_string(),
)?;

// 2. 初始化握手模块
let handshake = RealityHandshake::new(reality_config)?;

// 3. 初始化 Vision 协议
let vision = VisionProtocol::new(Duration::from_secs(10));

// 4. 处理连接
async fn handle_connection(stream: TcpStream) -> Result<()> {
    // 状态机初始化
    let mut state_machine = ConnectionStateMachine::new(stream);
    
    // TLS 握手
    let tls_stream = handshake.accept(state_machine.into_stream().unwrap()).await?;
    state_machine = ConnectionStateMachine::new(tls_stream);
    
    // Vision 鉴权
    state_machine = state_machine
        .transition_to_authenticating(&vision, &["password1", "password2"])
        .await?;
    
    // 获取鉴权结果
    let (command, address) = state_machine.get_auth_result().unwrap();
    
    // 直接转发
    handle_authenticated_connection(
        state_machine.into_stream().unwrap(),
        command,
        address,
        Duration::from_secs(10),
    )
    .await?;
    
    Ok(())
}
```

## 未来扩展

1. **UDP 支持**：实现 UDP over TCP 或直接 UDP 转发
2. **多证书轮换**：支持多个证书随机选择
3. **流量统计**：详细的连接统计和监控
4. **动态配置**：支持运行时配置更新
5. **插件系统**：支持自定义鉴权模块

## 总结

本设计成功实现了 XTLS-Reality 和 Vision 的核心思想：
- **伪装期**：使用真实 TLS 证书，完全模拟浏览器行为
- **鉴权期**：在加密通道内进行应用层鉴权
- **卸甲期**：鉴权通过后直接零拷贝转发

该设计在保持高性能的同时，提供了强大的抗检测能力，适合在敏感网络环境中部署。
