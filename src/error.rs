use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TrojanError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Authentication failed: invalid password")]
    #[allow(dead_code)]
    AuthenticationFailed,

    #[error("Invalid address type: {0}")]
    InvalidAddressType(u8),

    #[error("Invalid command: {0}")]
    InvalidCommand(u8),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Connection timeout")]
    Timeout,

    #[error("Invalid UTF-8 sequence")]
    InvalidUtf8,

    #[error("Remote connection failed: {0}")]
    RemoteConnectFailed(String),

    #[error("Task join error: {0}")]
    Join(String),
}

impl From<tokio::task::JoinError> for TrojanError {
    fn from(e: tokio::task::JoinError) -> Self {
        TrojanError::Join(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, TrojanError>;
