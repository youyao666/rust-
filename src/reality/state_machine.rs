use tokio::net::TcpStream;
use tracing::info;

use crate::error::{Result, TrojanError};
use crate::protocol::{Address, Command};
use crate::reality::splice::tcp_splice;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Handshake,
    Authenticating,
    Authenticated,
    Forwarding,
    Fallback,
    Closed,
}

pub struct ConnectionStateMachine<S> {
    stream: Option<S>,
    state: ConnectionState,
    auth_result: Option<(Command, Address)>,
    fallback_address: Option<Address>,
}

impl<S> ConnectionStateMachine<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    pub fn new(stream: S) -> Self {
        Self {
            stream: Some(stream),
            state: ConnectionState::Handshake,
            auth_result: None,
            fallback_address: None,
        }
    }

    pub fn set_fallback(&mut self, address: Address) {
        self.fallback_address = Some(address);
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn into_stream(self) -> Option<S> {
        self.stream
    }

    pub async fn transition_to_authenticating(
        mut self,
        vision: &crate::reality::vision::VisionProtocol,
        passwords: &[String],
    ) -> Result<Self> {
        if self.state != ConnectionState::Handshake {
            return Err(TrojanError::Protocol(
                "Invalid state transition".to_string(),
            ));
        }

        let stream = self
            .stream
            .take()
            .ok_or_else(|| TrojanError::Protocol("Missing stream in state machine".to_string()))?;
        let mut stream = stream;

        match vision.authenticate(&mut stream, passwords).await {
            Ok((command, address)) => {
                info!("Authentication successful: {:?} -> {}", command, address);

                self.stream = Some(stream);
                self.state = ConnectionState::Authenticated;
                self.auth_result = Some((command, address));

                Ok(self)
            }
            Err(e) => {
                if let Some(_fallback) = &self.fallback_address {
                    info!("Would redirect to fallback (not implemented)");
                    self.state = ConnectionState::Fallback;
                } else {
                    self.state = ConnectionState::Closed;
                }

                self.stream = Some(stream);
                Err(e)
            }
        }
    }

    pub async fn transition_to_forwarding(
        self,
        target_address: &Address,
        connect_timeout: std::time::Duration,
    ) -> Result<(S, TcpStream)> {
        if self.state != ConnectionState::Authenticated {
            return Err(TrojanError::Protocol(
                "Cannot forward without authentication".to_string(),
            ));
        }

        let stream = self.stream.ok_or_else(|| {
            TrojanError::Protocol("Missing stream in authenticated state".to_string())
        })?;

        info!("Connecting to target: {}", target_address);

        let remote = match target_address {
            Address::IPv4(addr) | Address::IPv6(addr) => {
                tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
                    .await
                    .map_err(|_| TrojanError::Timeout)?
            }
            Address::Domain(domain, port) => tokio::time::timeout(
                connect_timeout,
                TcpStream::connect(format!("{}:{}", domain, port)),
            )
            .await
            .map_err(|_| TrojanError::Timeout)?,
        }?;

        info!("Target connection established: {}", target_address);

        Ok((stream, remote))
    }

    pub fn get_auth_result(&self) -> Option<(Command, Address)> {
        self.auth_result.clone()
    }
}

pub async fn handle_authenticated_connection<S>(
    stream: S,
    command: Command,
    address: Address,
    connect_timeout: std::time::Duration,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    match command {
        Command::Connect => {
            info!("TCP Connect to {}", address);

            let remote = match &address {
                Address::IPv4(addr) | Address::IPv6(addr) => {
                    tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
                        .await
                        .map_err(|_| TrojanError::Timeout)?
                }
                Address::Domain(domain, port) => tokio::time::timeout(
                    connect_timeout,
                    TcpStream::connect(format!("{}:{}", domain, port)),
                )
                .await
                .map_err(|_| TrojanError::Timeout)?,
            }?;

            info!("Direct splice active for TCP connection");

            let total_bytes = tcp_splice(stream, remote).await?;
            info!("Connection closed, total bytes: {}", total_bytes);

            Ok(())
        }
        Command::UdpAssociate => Err(TrojanError::Protocol(
            "UDP not supported in direct mode".to_string(),
        )),
    }
}
