use std::io::Cursor;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::error::{Result, TrojanError};

/// `PrefixedStream<S>` 包装一个底层异步流 `S`，在读取时先返回 `prefix` 中的数据，
/// 耗尽后再读取 `S`。写操作直接透传到 `S`。
///
/// 用于正常代理路径：Trojan Header 已从 peek buf 中解析完毕，buf 末尾可能残留
/// 载荷数据，需要将这部分数据"还给"流，再与原始流合并供后续 relay 使用。
pub struct PrefixedStream<S> {
    /// 残留的前缀数据（Header 之后的载荷部分）
    prefix: Cursor<Vec<u8>>,
    /// 底层 TLS / TCP 流
    inner: S,
}

impl<S> PrefixedStream<S> {
    /// 创建一个新的 `PrefixedStream`。
    ///
    /// - `prefix`：已从流中读取但尚未处理的字节（例如 peek buf 中 header 之后的载荷）
    /// - `inner`：底层流（原始 TLS stream）
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix: Cursor::new(prefix),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // 先消耗 prefix
        let prefix_remaining = self.prefix.get_ref().len() as u64 - self.prefix.position();
        if prefix_remaining > 0 {
            return Pin::new(&mut self.prefix).poll_read(cx, buf);
        }
        // prefix 耗尽后，读底层流
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 将客户端连接无缝回落到 fallback 后端，实现完全透明代理。
///
/// 工作流程：
/// 1. 连接到 `fallback_addr`（通常为 127.0.0.1:80）。
/// 2. 先将已 peek 读取的 `peeked_buf` 写入后端（重放已读数据）。
/// 3. 再启动异步双向零拷贝转发，直到连接关闭。
///
/// 绝不向客户端返回任何错误，完全透明。
pub async fn handle_fallback<S>(
    mut client_stream: S,
    peeked_buf: Vec<u8>,
    fallback_addr: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    debug!(
        "Initiating fallback to {} (replaying {} peeked bytes)",
        fallback_addr,
        peeked_buf.len()
    );

    let mut fallback_stream = TcpStream::connect(fallback_addr).await.map_err(|e| {
        warn!("Failed to connect to fallback {}: {}", fallback_addr, e);
        TrojanError::RemoteConnectFailed(format!("fallback {}: {}", fallback_addr, e))
    })?;

    // 步骤 1：将已 peek 的数据重放写入 fallback 后端
    if !peeked_buf.is_empty() {
        fallback_stream.write_all(&peeked_buf).await?;
    }

    // 步骤 2：双向零拷贝转发（client_stream ↔ fallback_stream）
    let (up, down) =
        tokio::io::copy_bidirectional(&mut client_stream, &mut fallback_stream).await?;

    debug!(
        "Fallback relay finished: client→fallback={} bytes, fallback→client={} bytes",
        up, down
    );

    Ok(())
}

/// 从异步流中读取最多 `capacity` 字节到内存缓冲区（模拟 peek 语义）。
///
/// Tokio 的 TLS 流不支持真正的内核级 `peek()`，因此用普通 `read()` 把首批数据
/// 读入 Vec，上层再决定走正常代理还是 fallback。
///
/// 返回读取到的字节缓冲区。
pub async fn peek_client_data<R>(reader: &mut R, capacity: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; capacity];
    let n = reader.read(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn test_peek_client_data_reads_bytes() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut reader = &data[..];

        let buf = peek_client_data(&mut reader, 512)
            .await
            .expect("peek should succeed");

        assert!(!buf.is_empty());
        assert_eq!(buf.as_slice(), data);
    }

    #[tokio::test]
    async fn test_prefixed_stream_reads_prefix_then_inner() {
        let prefix = b"PREFIX".to_vec();
        let inner_data = b"INNER".as_ref();

        let mut stream = PrefixedStream::new(prefix, inner_data);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();

        assert_eq!(out, b"PREFIXINNER");
    }

    #[tokio::test]
    async fn test_prefixed_stream_empty_prefix() {
        let inner_data = b"INNER".as_ref();
        let mut stream = PrefixedStream::new(vec![], inner_data);
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"INNER");
    }
}
