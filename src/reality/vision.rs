use bytes::{BufMut, BytesMut};
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::{debug, warn};

use crate::error::{Result, TrojanError};
use crate::protocol::{Address, Command};

pub const VISION_MAGIC_HEADER: u8 = 0xFE;
pub const VISION_VERSION: u8 = 0x01;
pub const VISION_PASSWORD_HEX_LEN: usize = 56;
pub const VISION_HASH_LEN: usize = 28;

#[derive(Debug, Clone)]
pub struct VisionAuthRequest {
    pub magic: u8,
    pub version: u8,
    pub command: Command,
    pub address: Address,
    pub timestamp: u64,
    pub password_hash: [u8; VISION_PASSWORD_HEX_LEN],
    pub integrity_hash: [u8; VISION_HASH_LEN],
}

impl VisionAuthRequest {
    pub fn new(command: Command, address: Address, password_hash_hex: &str) -> Result<Self> {
        let password_hash = parse_password_hash(password_hash_hex)?;

        Self {
            magic: VISION_MAGIC_HEADER,
            version: VISION_VERSION,
            command,
            address,
            timestamp: current_unix_timestamp()?,
            password_hash,
            integrity_hash: [0u8; VISION_HASH_LEN],
        }
        .with_integrity_hash()
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
        let mut password_hash = [0u8; VISION_PASSWORD_HEX_LEN];
        reader.read_exact(&mut password_hash).await?;
        if !password_hash.iter().all(u8::is_ascii_hexdigit) {
            return Err(TrojanError::Protocol(
                "Invalid Vision password hash format".to_string(),
            ));
        }

        let mut integrity_hash = [0u8; VISION_HASH_LEN];
        reader.read_exact(&mut integrity_hash).await?;

        let current_time = current_unix_timestamp()?;

        if (current_time as i64 - timestamp as i64).abs() > 300 {
            warn!("Vision request timestamp too old: {}", timestamp);
            return Err(TrojanError::Protocol("Timestamp expired".to_string()));
        }

        let request = Self {
            magic,
            version,
            command,
            address,
            timestamp,
            password_hash,
            integrity_hash,
        };

        request.verify_integrity()?;

        Ok(request)
    }

    pub fn encode(&self) -> Result<BytesMut> {
        let request = self.clone().with_integrity_hash()?;
        request.encode_with_integrity_hash()
    }

    fn encode_with_integrity_hash(&self) -> Result<BytesMut> {
        let mut buf = self.encoded_without_integrity_hash()?;
        buf.extend_from_slice(&self.integrity_hash);
        Ok(buf)
    }

    fn encoded_without_integrity_hash(&self) -> Result<BytesMut> {
        let mut buf = BytesMut::with_capacity(512);

        buf.put_u8(self.magic);
        buf.put_u8(self.version);
        buf.put_u8(self.command.as_u8());

        let addr_bytes = self.address.encode()?;
        buf.extend_from_slice(&addr_bytes);

        buf.put_u64(self.timestamp);
        buf.extend_from_slice(&self.password_hash);

        Ok(buf)
    }

    fn compute_hash(buf: &[u8]) -> [u8; VISION_HASH_LEN] {
        let mut hasher = Sha224::new();
        hasher.update(buf);
        let result = hasher.finalize();
        let mut hash = [0u8; VISION_HASH_LEN];
        hash.copy_from_slice(&result);
        hash
    }

    fn with_integrity_hash(mut self) -> Result<Self> {
        let base = self.encoded_without_integrity_hash()?;
        self.integrity_hash = Self::compute_hash(&base);
        Ok(self)
    }

    fn verify_integrity(&self) -> Result<()> {
        let expected = Self::compute_hash(&self.encoded_without_integrity_hash()?);
        if expected != self.integrity_hash {
            return Err(TrojanError::Protocol(
                "Vision integrity check failed".to_string(),
            ));
        }

        Ok(())
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
        valid_passwords: &[String],
    ) -> Result<(Command, Address)> {
        let auth_request =
            tokio::time::timeout(self.auth_timeout, VisionAuthRequest::read_from(stream))
                .await
                .map_err(|_| TrojanError::Timeout)??;

        let password_hash = std::str::from_utf8(&auth_request.password_hash).map_err(|_| {
            TrojanError::Protocol("Invalid Vision password hash encoding".to_string())
        })?;

        if !valid_passwords
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(password_hash))
        {
            return Err(TrojanError::AuthenticationFailed);
        }

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

fn current_unix_timestamp() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| TrojanError::Protocol("System clock before UNIX_EPOCH".to_string()))
}

fn parse_password_hash(value: &str) -> Result<[u8; VISION_PASSWORD_HEX_LEN]> {
    if value.len() != VISION_PASSWORD_HEX_LEN || !value.as_bytes().iter().all(u8::is_ascii_hexdigit)
    {
        return Err(TrojanError::Protocol(
            "Vision password hash must be 56 hex characters".to_string(),
        ));
    }

    let mut out = [0u8; VISION_PASSWORD_HEX_LEN];
    out.copy_from_slice(value.as_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncWriteExt};

    #[test]
    fn test_vision_encode_decode() {
        let addr = Address::Domain("example.com".to_string(), 443);
        let password_hash = hex::encode(Sha224::digest(b"secret"));
        let request = VisionAuthRequest::new(Command::Connect, addr.clone(), &password_hash)
            .expect("vision request should be created");

        let encoded = request.encode().expect("vision request should encode");
        assert_eq!(encoded[0], VISION_MAGIC_HEADER);
        assert_eq!(encoded[1], VISION_VERSION);
    }

    #[tokio::test]
    async fn test_vision_authenticate_valid_password() {
        let addr = Address::Domain("example.com".to_string(), 443);
        let password_hash = hex::encode(Sha224::digest(b"secret"));
        let request = VisionAuthRequest::new(Command::Connect, addr.clone(), &password_hash)
            .expect("request should build");

        let (mut client, mut server) = duplex(1024);
        let encoded = request.encode().expect("request should encode");
        client
            .write_all(&encoded)
            .await
            .expect("request should write");

        let vision = VisionProtocol::new(std::time::Duration::from_secs(1));
        let result = vision
            .authenticate(&mut server, &[password_hash])
            .await
            .expect("authentication should succeed");

        assert_eq!(result.0, Command::Connect);
        assert_eq!(result.1, addr);
    }

    #[tokio::test]
    async fn test_vision_authenticate_wrong_password() {
        let addr = Address::Domain("example.com".to_string(), 443);
        let password_hash = hex::encode(Sha224::digest(b"secret"));
        let request = VisionAuthRequest::new(Command::Connect, addr, &password_hash)
            .expect("request should build");

        let (mut client, mut server) = duplex(1024);
        let encoded = request.encode().expect("request should encode");
        client
            .write_all(&encoded)
            .await
            .expect("request should write");

        let vision = VisionProtocol::new(std::time::Duration::from_secs(1));
        let err = vision
            .authenticate(
                &mut server,
                &["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()],
            )
            .await
            .expect_err("authentication should fail");

        assert!(matches!(err, TrojanError::AuthenticationFailed));
    }

    #[tokio::test]
    async fn test_vision_authenticate_tampered_integrity() {
        let addr = Address::Domain("example.com".to_string(), 443);
        let password_hash = hex::encode(Sha224::digest(b"secret"));
        let request = VisionAuthRequest::new(Command::Connect, addr, &password_hash)
            .expect("request should build");

        let mut encoded = request.encode().expect("request should encode");
        let last = encoded
            .len()
            .checked_sub(1)
            .expect("encoded payload should be non-empty");
        encoded[last] ^= 0x01;

        let (mut client, mut server) = duplex(1024);
        client
            .write_all(&encoded)
            .await
            .expect("request should write");

        let vision = VisionProtocol::new(std::time::Duration::from_secs(1));
        let err = vision
            .authenticate(&mut server, &[password_hash])
            .await
            .expect_err("tampered request should fail");

        assert!(matches!(
            err,
            TrojanError::Protocol(message) if message.contains("integrity")
        ));
    }
}
