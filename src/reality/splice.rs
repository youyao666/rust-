use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info};

use crate::error::Result;

pub struct DirectSplice<R, W> {
    reader: R,
    writer: W,
    bytes_transferred: u64,
}

impl<R, W> DirectSplice<R, W>
where
    R: AsyncRead + AsyncWrite + Unpin,
    W: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            bytes_transferred: 0,
        }
    }

    pub async fn splice(&mut self) -> Result<u64> {
        let buffer_size = 65536;
        let mut buf1 = vec![0u8; buffer_size];
        let mut buf2 = vec![0u8; buffer_size];

        loop {
            tokio::select! {
                result = self.reader.read(&mut buf1) => {
                    match result {
                        Ok(0) => {
                            debug!("Reader EOF reached");
                            break;
                        }
                        Ok(n) => {
                            self.writer.write_all(&buf1[..n]).await?;
                            self.writer.flush().await?;
                            self.bytes_transferred += n as u64;
                        }
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                continue;
                            }
                            break;
                        }
                    }
                }
                result = self.writer.read(&mut buf2) => {
                    match result {
                        Ok(0) => {
                            debug!("Writer EOF reached");
                            break;
                        }
                        Ok(n) => {
                            self.reader.write_all(&buf2[..n]).await?;
                            self.reader.flush().await?;
                            self.bytes_transferred += n as u64;
                        }
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                continue;
                            }
                            break;
                        }
                    }
                }
            }
        }

        Ok(self.bytes_transferred)
    }
}

pub struct UnwrapStream<S> {
    inner: S,
    decrypted: bool,
}

impl<S> UnwrapStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            decrypted: false,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    pub fn is_decrypted(&self) -> bool {
        self.decrypted
    }

    pub fn mark_decrypted(&mut self) {
        self.decrypted = true;
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for UnwrapStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for UnwrapStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

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
