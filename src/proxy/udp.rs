use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{lookup_host, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::error::{Result, TrojanError};
use crate::protocol::Address;
use crate::proxy::session::Session;

const UDP_BUFFER_SIZE: usize = 65_535;
const UDP_MAX_PAYLOAD_LEN: usize = u16::MAX as usize;
const CRLF: [u8; 2] = [0x0d, 0x0a];

#[derive(Debug)]
struct UdpFrame {
    address: Address,
    payload: Vec<u8>,
}

enum UdpEvent {
    Client(Result<Option<UdpFrame>>),
    Remote(std::io::Result<(usize, SocketAddr)>),
}

pub async fn handle_udp<S>(
    client_stream: S,
    session: Session,
    udp_timeout: Duration,
    udp_bind_addr: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!("[Session {}] Starting UDP associate", session.id);

    let udp_socket = UdpSocket::bind(udp_bind_addr).await.map_err(|e| {
        TrojanError::Config(format!(
            "Failed to bind UDP socket on {}: {}",
            udp_bind_addr, e
        ))
    })?;
    let local_addr = udp_socket.local_addr()?;
    info!(
        "[Session {}] UDP relay socket bound to {}",
        session.id, local_addr
    );

    let (mut client_reader, mut client_writer) = tokio::io::split(client_stream);
    let mut udp_recv_buf = vec![0u8; UDP_BUFFER_SIZE];

    loop {
        let event = timeout(udp_timeout, async {
            tokio::select! {
                frame = read_udp_frame(&mut client_reader) => UdpEvent::Client(frame),
                recv = udp_socket.recv_from(&mut udp_recv_buf) => UdpEvent::Remote(recv),
            }
        })
        .await;

        let event = match event {
            Ok(ev) => ev,
            Err(_) => {
                debug!(
                    "[Session {}] UDP associate idle timeout reached",
                    session.id
                );
                break;
            }
        };

        match event {
            UdpEvent::Client(Ok(Some(frame))) => {
                let target = match resolve_target(&frame.address).await {
                    Ok(target) => target,
                    Err(e) => {
                        warn!(
                            "[Session {}] Failed to resolve UDP target {}: {}",
                            session.id, frame.address, e
                        );
                        continue;
                    }
                };

                if let Err(e) = udp_socket.send_to(&frame.payload, target).await {
                    warn!(
                        "[Session {}] Failed to send UDP packet to {}: {}",
                        session.id, target, e
                    );
                    continue;
                }

                session.add_sent(frame.payload.len() as u64);
            }
            UdpEvent::Client(Ok(None)) => {
                debug!("[Session {}] UDP client stream closed", session.id);
                break;
            }
            UdpEvent::Client(Err(e)) => {
                warn!("[Session {}] Invalid UDP frame: {}", session.id, e);
                return Err(e);
            }
            UdpEvent::Remote(Ok((len, source_addr))) => {
                let frame = build_udp_frame(source_addr, &udp_recv_buf[..len])?;
                client_writer.write_all(&frame).await?;
                session.add_received(len as u64);
            }
            UdpEvent::Remote(Err(e)) => {
                return Err(e.into());
            }
        }
    }

    info!(
        "[Session {}] UDP associate ended, duration={:?}",
        session.id,
        session.duration()
    );
    Ok(())
}

async fn read_udp_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<UdpFrame>> {
    let atyp = match reader.read_u8().await {
        Ok(atyp) => atyp,
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    let address = read_target_address(reader, atyp).await?;
    let payload_len = reader.read_u16().await? as usize;

    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).await?;
    if crlf != CRLF {
        return Err(TrojanError::Protocol(
            "Invalid UDP CRLF delimiter".to_string(),
        ));
    }

    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;

    Ok(Some(UdpFrame { address, payload }))
}

async fn read_target_address<R: AsyncRead + Unpin>(reader: &mut R, atyp: u8) -> Result<Address> {
    match atyp {
        Address::TYPE_IPV4 => {
            let mut octets = [0u8; 4];
            reader.read_exact(&mut octets).await?;
            let port = reader.read_u16().await?;
            Ok(Address::IPv4(SocketAddr::new(
                Ipv4Addr::from(octets).into(),
                port,
            )))
        }
        Address::TYPE_DOMAIN => {
            let len = reader.read_u8().await? as usize;
            if len == 0 {
                return Err(TrojanError::Protocol(
                    "Invalid domain length in UDP frame".to_string(),
                ));
            }

            let mut domain_buf = vec![0u8; len];
            reader.read_exact(&mut domain_buf).await?;
            let domain = String::from_utf8(domain_buf).map_err(|_| TrojanError::InvalidUtf8)?;
            let port = reader.read_u16().await?;

            Ok(Address::Domain(domain, port))
        }
        Address::TYPE_IPV6 => {
            let mut octets = [0u8; 16];
            reader.read_exact(&mut octets).await?;
            let port = reader.read_u16().await?;
            Ok(Address::IPv6(SocketAddr::new(
                Ipv6Addr::from(octets).into(),
                port,
            )))
        }
        _ => Err(TrojanError::InvalidAddressType(atyp)),
    }
}

fn build_udp_frame(addr: SocketAddr, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > UDP_MAX_PAYLOAD_LEN {
        return Err(TrojanError::Protocol(
            "UDP payload exceeds protocol limit".to_string(),
        ));
    }

    let mut frame = Vec::with_capacity(1 + 16 + 2 + 2 + 2 + payload.len());

    match addr {
        SocketAddr::V4(v4) => {
            frame.push(Address::TYPE_IPV4);
            frame.extend_from_slice(&v4.ip().octets());
            frame.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            frame.push(Address::TYPE_IPV6);
            frame.extend_from_slice(&v6.ip().octets());
            frame.extend_from_slice(&v6.port().to_be_bytes());
        }
    }

    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(&CRLF);
    frame.extend_from_slice(payload);

    Ok(frame)
}

async fn resolve_target(address: &Address) -> Result<SocketAddr> {
    match address {
        Address::IPv4(addr) | Address::IPv6(addr) => Ok(*addr),
        Address::Domain(domain, port) => {
            let mut addrs = lookup_host((domain.as_str(), *port)).await.map_err(|e| {
                TrojanError::RemoteConnectFailed(format!(
                    "failed to resolve {}:{} ({})",
                    domain, port, e
                ))
            })?;

            addrs.next().ok_or_else(|| {
                TrojanError::RemoteConnectFailed(format!(
                    "DNS resolved no addresses for {}:{}",
                    domain, port
                ))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test_read_udp_frame_ipv4() {
        let mut raw = Vec::new();
        raw.push(Address::TYPE_IPV4);
        raw.extend_from_slice(&[8, 8, 8, 8]);
        raw.extend_from_slice(&53u16.to_be_bytes());
        raw.extend_from_slice(&4u16.to_be_bytes());
        raw.extend_from_slice(&CRLF);
        raw.extend_from_slice(b"ping");

        let mut reader = Builder::new().read(&raw).build();
        let frame = read_udp_frame(&mut reader)
            .await
            .expect("frame parse should succeed")
            .expect("frame should not be eof");

        assert_eq!(
            frame.address,
            Address::IPv4(SocketAddr::new(Ipv4Addr::new(8, 8, 8, 8).into(), 53))
        );
        assert_eq!(frame.payload, b"ping");
    }

    #[tokio::test]
    async fn test_read_udp_frame_eof() {
        let mut reader = Builder::new().build();
        let frame = read_udp_frame(&mut reader)
            .await
            .expect("eof without data should not error");
        assert!(frame.is_none());
    }

    #[tokio::test]
    async fn test_read_udp_frame_invalid_crlf() {
        let mut raw = Vec::new();
        raw.push(Address::TYPE_IPV4);
        raw.extend_from_slice(&[1, 1, 1, 1]);
        raw.extend_from_slice(&53u16.to_be_bytes());
        raw.extend_from_slice(&1u16.to_be_bytes());
        raw.extend_from_slice(&[0x00, 0x00]);

        let mut reader = Builder::new().read(&raw).build();
        let err = read_udp_frame(&mut reader)
            .await
            .expect_err("invalid CRLF should fail");

        assert!(matches!(
            err,
            TrojanError::Protocol(message) if message.contains("Invalid UDP CRLF")
        ));
    }

    #[test]
    fn test_build_udp_frame_ipv6() {
        let source = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 5353);
        let frame = build_udp_frame(source, b"pong").expect("frame build should succeed");

        assert_eq!(frame[0], Address::TYPE_IPV6);

        let len_offset = 1 + 16 + 2;
        assert_eq!(&frame[len_offset..len_offset + 2], &4u16.to_be_bytes());
        assert_eq!(&frame[len_offset + 2..len_offset + 4], &CRLF);
        assert_eq!(&frame[len_offset + 4..], b"pong");
    }
}
