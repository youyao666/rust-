use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::{debug, warn};

use crate::error::{Result, TrojanError};
use crate::protocol::{Address, Command};

pub const VISION_MAGIC_HEADER: u8 = 0xFE;
pub const VISION_VERSION: u8 = 0x01;

#[derive(Debug, Clone)]
pub struct VisionAuthRequest {
    pub magic: u8,
    pub version: u8,
    pub command: Command,
    pub address: Address,
    pub timestamp: u64,
}

impl VisionAuthRequest {
    pub fn new(command: Command, address: Address) -> Self {
        Self {
            magic: VISION_MAGIC_HEADER,
            version: VISION_VERSION,
            command,
            address,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let magic = reader.read_u8().await?;
        if magic != VISION_MAGIC_HEADER {
            return Err(TrojanError::Protocol(format!(
                "Invalid Vision magic header: {:x}",
                magic
            )));
        }

        let version = reader.read_u8().await?;
        if version != VISION_VERSION {
            return Err(TrojanError::Protocol(format!(
                "Unsupported Vision version: {}",
                version
            )));
        }

        let cmd_byte = reader.read_u8().await?;
        let command = Command::from_u8(cmd_byte)?;

        let address = Address::read_from(reader).await?;

        let timestamp = reader.read_u64().await?;

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if (current_time as i64 - timestamp as i64).abs() > 300 {
            warn!("Vision request timestamp too old: {}", timestamp);
            return Err(TrojanError::Protocol("Timestamp expired".to_string()));
        }

        Ok(Self {
            magic,
            version,
            command,
            address,
            timestamp,
        })
    }

    pub fn encode(&self) -> Result<BytesMut> {
        let mut buf = BytesMut::with_capacity(512);

        buf.put_u8(self.magic);
        buf.put_u8(self.version);
        buf.put_u8(self.command.as_u8());

        let addr_bytes = self.address.encode()?;
        buf.extend_from_slice(&addr_bytes);

        buf.put_u64(self.timestamp);

        let hash = Self::compute_hash(&buf);
        buf.extend_from_slice(&hash);

        Ok(buf)
    }

    fn compute_hash(buf: &[u8]) -> [u8; 28] {
        let mut hasher = Sha224::new();
        hasher.update(buf);
        let result = hasher.finalize();
        let mut hash = [0u8; 28];
        hash.copy_from_slice(&result);
        hash
    }
}

pub struct VisionProtocol {
    auth_timeout: std::time::Duration,
}

impl VisionProtocol {
    pub fn new(auth_timeout: std::time::Duration) -> Self {
        Self { auth_timeout }
    }

    pub async fn authenticate<S: AsyncRead + Unpin>(
        &self,
        stream: &mut S,
        _valid_passwords: &[String],
    ) -> Result<(Command, Address)> {
        let auth_request =
            tokio::time::timeout(self.auth_timeout, VisionAuthRequest::read_from(stream))
                .await
                .map_err(|_| TrojanError::Timeout)??;

        debug!(
            "Vision auth received: command={:?}, address={}",
            auth_request.command, auth_request.address
        );

        Ok((auth_request.command, auth_request.address))
    }

    pub fn is_vision_packet(data: &[u8]) -> bool {
        data.len() >= 2 && data[0] == VISION_MAGIC_HEADER && data[1] == VISION_VERSION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vision_encode_decode() {
        let addr = Address::Domain("example.com".to_string(), 443);
        let request = VisionAuthRequest::new(Command::Connect, addr.clone());

        let encoded = request.encode().unwrap();
        assert_eq!(encoded[0], VISION_MAGIC_HEADER);
        assert_eq!(encoded[1], VISION_VERSION);
    }
}
