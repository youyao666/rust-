use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

use crate::error::Result;

pub async fn relay<S1, S2>(mut client_stream: S1, mut remote_stream: S2) -> Result<(u64, u64)>
where
    S1: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S2: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (upstream, downstream) =
        tokio::io::copy_bidirectional(&mut client_stream, &mut remote_stream).await?;

    debug!(
        "Relay finished, upstream={} bytes, downstream={} bytes",
        upstream, downstream
    );

    Ok((upstream, downstream))
}
