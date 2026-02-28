use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::server::TlsStream;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::error::Result;
use crate::protocol::{Command, Header, PEEK_SIZE};
use crate::proxy::{
    handle_fallback, handle_tcp, handle_udp, peek_client_data, PrefixedStream, Session,
};
use crate::tls::TlsConfig;

pub struct Server {
    config: Arc<Config>,
    tls_config: TlsConfig,
    connection_limit: Arc<Semaphore>,
}

impl Server {
    pub fn new(config: Config, tls_config: TlsConfig) -> Self {
        let connection_limit = Arc::new(Semaphore::new(config.max_connections));
        Self {
            config: Arc::new(config),
            tls_config,
            connection_limit,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.config.bind_addr).await?;
        info!("Server listening on {}", self.config.bind_addr);
        info!(
            "Fallback backend: {} (activated on auth/protocol failure)",
            self.config.fallback_addr
        );

        let acceptor = self.tls_config.acceptor();

        loop {
            let permit = match self.connection_limit.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(e) => {
                    error!("Failed to acquire connection permit: {}", e);
                    continue;
                }
            };

            let (stream, peer_addr) = match listener.accept().await {
                Ok((s, a)) => (s, a),
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            debug!("New connection from {}", peer_addr);

            let acceptor = acceptor.clone();
            let config = Arc::clone(&self.config);

            tokio::spawn(async move {
                let _permit = permit;

                let tls_stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        // TLS 握手失败不记录 warn，避免暴露服务存在
                        debug!("TLS handshake failed for {}: {}", peer_addr, e);
                        return;
                    }
                };

                if let Err(e) = handle_connection(tls_stream, peer_addr, config).await {
                    debug!("Connection from {} ended: {}", peer_addr, e);
                }
            });
        }
    }
}

/// 处理单个 TLS 连接的核心调度逻辑：
///
/// 1. **Peek**：从 TLS 流中读取首批数据到内存缓冲（不消耗流语义）。
/// 2. **校验**：用 `Header::try_parse_from_buf` 在内存中解析 Trojan 协议头，
///    同时验证密码——全程不触发额外 IO。
/// 3. **分发**：
///    - 校验成功 → 用 `PrefixedStream` 将 peeked buf 中 header 后的载荷
///      与原始流拼接，传入正常的 TCP/UDP 代理流程。
///    - 校验失败（密码错误 / 格式非法 / HTTP 探测等）→ 将 peeked 数据原样
///      重放到 fallback 后端，启动双向零拷贝透明转发，绝不向客户端返回错误。
async fn handle_connection<S>(
    mut stream: TlsStream<S>,
    peer_addr: SocketAddr,
    config: Arc<Config>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // ── 步骤 1：增量 Peek 首批数据（应对首包分片）───────────────────────────
    let mut peeked = Vec::with_capacity(PEEK_SIZE);

    let header = loop {
        if peeked.len() >= PEEK_SIZE {
            warn!(
                "[{}] Incomplete header after {} bytes → fallback to {}",
                peer_addr,
                peeked.len(),
                config.fallback_addr
            );
            return handle_fallback(stream, peeked, &config.fallback_addr).await;
        }

        let mut chunk = peek_client_data(&mut stream, PEEK_SIZE - peeked.len()).await?;
        if chunk.is_empty() {
            if peeked.is_empty() {
                debug!("[{}] Client sent no data, dropping silently", peer_addr);
                return Ok(());
            }

            warn!(
                "[{}] Client closed before complete header ({} bytes) → fallback to {}",
                peer_addr,
                peeked.len(),
                config.fallback_addr
            );
            return handle_fallback(stream, peeked, &config.fallback_addr).await;
        }

        peeked.append(&mut chunk);

        // ── 步骤 2：非消耗式协议/密码校验 ─────────────────────────────────
        match Header::try_parse_from_buf(&peeked) {
            // 格式合法且密码正确 → 正常代理
            Ok(Some(h)) if h.verify_password(&config.passwords) => {
                info!(
                    "[{}] Authenticated ✓  cmd={:?}  target={}",
                    peer_addr, h.command, h.address
                );
                break h;
            }

            // 格式合法但密码错误 → fallback（防主动探测，不暴露服务）
            Ok(Some(_)) => {
                warn!(
                    "[{}] Auth failed (wrong password) → fallback to {}",
                    peer_addr, config.fallback_addr
                );
                return handle_fallback(stream, peeked, &config.fallback_addr).await;
            }

            // 数据不足，继续读取
            Ok(None) => continue,

            // 格式非法（HTTP 探测 / 扫描器 / 非 Trojan 流量）→ fallback
            Err(e) => {
                debug!(
                    "[{}] Protocol mismatch ({}) → fallback to {}",
                    peer_addr, e, config.fallback_addr
                );
                return handle_fallback(stream, peeked, &config.fallback_addr).await;
            }
        }
    };

    // ── 步骤 3：计算 Header 在 peeked buf 中的结束偏移 ───────────────────
    let header_end = compute_header_end(&header, &peeked);

    // 将 peeked buf 中 header 之后的残余载荷与原始 TLS 流组合成新的客户端流。
    // PrefixedStream：读取时先输出 prefix（残余载荷），耗尽后再读底层流；
    // 写入时直接透传到底层流。完整实现 AsyncRead + AsyncWrite，可直接用于 relay。
    let leftover = peeked[header_end..].to_vec();
    let client_stream = PrefixedStream::new(leftover, stream);

    // ── 步骤 4：分发到 TCP / UDP 代理 ─────────────────────────────────────
    let session = Session::new(peer_addr, header.address.clone(), header.command);
    let tcp_timeout = Duration::from_secs(config.tcp_timeout);

    match header.command {
        Command::Connect => handle_tcp(client_stream, header.address, session, tcp_timeout).await,
        Command::UdpAssociate => {
            let udp_timeout = Duration::from_secs(config.udp_timeout);
            handle_udp(client_stream, session, udp_timeout, &config.udp_bind_addr).await
        }
    }
}

/// 精确计算 Trojan Header 在 peeked 缓冲区中的结束字节偏移。
///
/// Header 结构：
/// `[56 hex hash][CRLF][1 cmd byte][address bytes][CRLF]`
///
/// 通过 `Address::parse_from_buf` 重新解析地址长度来精确定位。
fn compute_header_end(_header: &Header, buf: &[u8]) -> usize {
    use crate::protocol::Address;

    // 地址字段起始位置 = 56(hash) + 2(CRLF) + 1(cmd)
    let addr_start = Header::PASSWORD_HEX_LEN + 2 + 1;

    if buf.len() <= addr_start {
        // 防御：buf 不足（正常情况不会发生，已通过 try_parse 验证过）
        return buf.len();
    }

    match Address::parse_from_buf(&buf[addr_start..]) {
        Ok((_, Some(addr_len))) => {
            addr_start + addr_len + 2 // +2 for trailing CRLF
        }
        _ => {
            // 防御性回退：不应到达此处（header 已通过 try_parse 验证）
            buf.len()
        }
    }
}
