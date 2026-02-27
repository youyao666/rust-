use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::error::{Result, TrojanError};
use crate::protocol::Address;
use crate::proxy::relay;
use crate::proxy::session::Session;

pub async fn handle_tcp<S>(
    client_stream: S,
    target: Address,
    session: Session,
    connect_timeout: Duration,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!(
        "[Session {}] Connecting to TCP target: {}",
        session.id, target
    );

    let remote_stream = match &target {
        Address::IPv4(addr) | Address::IPv6(addr) => {
            timeout(connect_timeout, TcpStream::connect(addr)).await
        }
        Address::Domain(domain, port) => {
            timeout(
                connect_timeout,
                TcpStream::connect(format!("{}:{}", domain, port)),
            )
            .await
        }
    };

    let remote_stream = match remote_stream {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            warn!(
                "[Session {}] Failed to connect to {}: {}",
                session.id, target, e
            );
            return Err(TrojanError::RemoteConnectFailed(e.to_string()));
        }
        Err(_) => {
            warn!(
                "[Session {}] Connection to {} timed out",
                session.id, target
            );
            return Err(TrojanError::Timeout);
        }
    };

    info!("[Session {}] Connected to {}", session.id, target);

    let (upstream, downstream) = match relay(client_stream, remote_stream).await {
        Ok(v) => v,
        Err(e) => {
            debug!("[Session {}] Relay ended: {}", session.id, e);
            return Err(e);
        }
    };

    session.add_sent(upstream);
    session.add_received(downstream);

    info!(
        "[Session {}] Relay completed, upstream={} bytes, downstream={} bytes, duration={:?}",
        session.id,
        upstream,
        downstream,
        session.duration()
    );

    Ok(())
}
