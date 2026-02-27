use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{Result, TrojanError};
use crate::protocol::{Address, Command};

/// 嗅探 peek 时读取的最大字节数。
/// 足以覆盖 56 字节密码 + CRLF + 1 字节命令 + 最长 SOCKS5 地址（域名 255 + 2 端口 + 2 CRLF）
/// 取 512 字节作为 peek 窗口，远大于最大合法头部。
pub const PEEK_SIZE: usize = 512;

#[derive(Debug, Clone)]
pub struct Header {
    pub password_hash: [u8; Self::PASSWORD_HEX_LEN],
    pub command: Command,
    pub address: Address,
}

impl Header {
    pub const CRLF: [u8; 2] = [0x0d, 0x0a];
    pub const PASSWORD_HEX_LEN: usize = 56;

    /// 从异步读取器中完整解析 Header（保留供测试使用）。
    #[allow(dead_code)]
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let mut password_hash = [0u8; Self::PASSWORD_HEX_LEN];
        reader.read_exact(&mut password_hash).await?;

        if !password_hash.iter().all(u8::is_ascii_hexdigit) {
            return Err(TrojanError::Protocol(
                "Invalid password hash format: expected 56-byte hex string".to_string(),
            ));
        }

        expect_crlf(reader, "password hash").await?;

        let cmd_byte = reader.read_u8().await?;
        let command = Command::from_u8(cmd_byte)?;

        let address = Address::read_from(reader).await?;

        expect_crlf(reader, "target address").await?;

        Ok(Header {
            password_hash,
            command,
            address,
        })
    }

    /// 非消耗式探测：从一段已 peek 的字节 buffer 中尝试解析 Header。
    ///
    /// 该函数不触及任何 IO，仅对内存切片进行解析。
    /// 调用方应先用 `AsyncReadExt::read_buf` / `peek` 手段把数据读入 buffer，
    /// 再调用此函数，失败时将 buffer 原样拼接回流中进行 fallback。
    ///
    /// 返回 `Ok(Some(header))` 表示解析成功；
    /// 返回 `Ok(None)` 表示 buffer 不足（应继续读取）；
    /// 返回 `Err(_)` 表示格式非法（直接 fallback）。
    pub fn try_parse_from_buf(buf: &[u8]) -> Result<Option<Self>> {
        // 最少需要：56(hash) + 2(CRLF) + 1(cmd) + 最短地址(IPv4=7) + 2(CRLF) = 68 字节
        if buf.len() < Self::PASSWORD_HEX_LEN + 2 {
            return Ok(None); // 数据不足，继续读取
        }

        // 1. 校验 56 字节密码 hex 格式
        let password_hash_slice = &buf[..Self::PASSWORD_HEX_LEN];
        if !password_hash_slice.iter().all(u8::is_ascii_hexdigit) {
            return Err(TrojanError::Protocol(
                "Invalid password hash: not hex digits".to_string(),
            ));
        }

        let mut password_hash = [0u8; Self::PASSWORD_HEX_LEN];
        password_hash.copy_from_slice(password_hash_slice);

        // 2. 校验第一个 CRLF
        let pos = Self::PASSWORD_HEX_LEN;
        if buf.len() < pos + 2 {
            return Ok(None);
        }
        if buf[pos] != 0x0d || buf[pos + 1] != 0x0a {
            return Err(TrojanError::Protocol(
                "Missing CRLF after password hash".to_string(),
            ));
        }
        let pos = pos + 2;

        // 3. 命令字节
        if buf.len() < pos + 1 {
            return Ok(None);
        }
        let command = Command::from_u8(buf[pos])?;
        let pos = pos + 1;

        // 4. 解析地址（非消耗式，从 buf 切片解析）
        let (address, addr_consumed) = Address::parse_from_buf(&buf[pos..])?;
        let addr_end = match addr_consumed {
            Some(len) => len,
            None => return Ok(None), // 地址数据不足
        };
        let pos = pos + addr_end;

        // 5. 校验结尾 CRLF
        if buf.len() < pos + 2 {
            return Ok(None);
        }
        if buf[pos] != 0x0d || buf[pos + 1] != 0x0a {
            return Err(TrojanError::Protocol(
                "Missing CRLF after target address".to_string(),
            ));
        }

        Ok(Some(Header {
            password_hash,
            command,
            address,
        }))
    }

    pub fn verify_password(&self, password_hashes: &[String]) -> bool {
        password_hashes.iter().any(|expected| {
            expected.len() == Self::PASSWORD_HEX_LEN
                && expected
                    .as_bytes()
                    .eq_ignore_ascii_case(&self.password_hash)
        })
    }

    #[allow(dead_code)]
    pub fn hash_password(password: &str) -> String {
        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[allow(dead_code)]
async fn expect_crlf<R: AsyncRead + Unpin>(reader: &mut R, field: &str) -> Result<()> {
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).await?;

    if crlf != Header::CRLF {
        return Err(TrojanError::Protocol(format!(
            "Invalid CRLF after {}",
            field
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test::io::Builder;

    #[test]
    fn test_password_hash() {
        let password = "test_password";
        let hash = Header::hash_password(password);
        assert_eq!(hash.len(), Header::PASSWORD_HEX_LEN);
    }

    #[tokio::test]
    async fn test_parse_valid_header() {
        let password_hash = Header::hash_password("secret");
        let mut raw = Vec::new();

        raw.extend_from_slice(password_hash.as_bytes());
        raw.extend_from_slice(&Header::CRLF);
        raw.push(Command::Connect.as_u8());
        raw.push(Address::TYPE_DOMAIN);
        raw.push(11);
        raw.extend_from_slice(b"example.com");
        raw.extend_from_slice(&443u16.to_be_bytes());
        raw.extend_from_slice(&Header::CRLF);

        let mut reader = Builder::new().read(&raw).build();
        let header = Header::read_from(&mut reader)
            .await
            .expect("header should parse");

        assert_eq!(header.command, Command::Connect);
        assert_eq!(
            header.address,
            Address::Domain("example.com".to_string(), 443)
        );
        assert!(header.verify_password(&[password_hash]));
    }

    #[tokio::test]
    async fn test_invalid_password_hash_format() {
        let raw = vec![b'z'; Header::PASSWORD_HEX_LEN];

        let mut reader = Builder::new().read(&raw).build();
        let err = Header::read_from(&mut reader)
            .await
            .expect_err("invalid hash should fail");

        assert!(matches!(
            err,
            TrojanError::Protocol(message)
            if message.contains("Invalid password hash format")
        ));
    }

    #[test]
    fn test_try_parse_from_buf_valid() {
        let password_hash = Header::hash_password("secret");
        let mut raw = Vec::new();

        raw.extend_from_slice(password_hash.as_bytes());
        raw.extend_from_slice(&Header::CRLF);
        raw.push(Command::Connect.as_u8());
        raw.push(Address::TYPE_DOMAIN);
        raw.push(11);
        raw.extend_from_slice(b"example.com");
        raw.extend_from_slice(&443u16.to_be_bytes());
        raw.extend_from_slice(&Header::CRLF);
        // 后面跟随任意载荷
        raw.extend_from_slice(b"GET / HTTP/1.1\r\n");

        let header = Header::try_parse_from_buf(&raw)
            .expect("should not error")
            .expect("should parse successfully");

        assert_eq!(header.command, Command::Connect);
        assert!(header.verify_password(&[password_hash]));
    }

    #[test]
    fn test_try_parse_from_buf_bad_hash() {
        let mut raw = vec![b'z'; Header::PASSWORD_HEX_LEN]; // 非 hex 字符
        raw.extend_from_slice(&Header::CRLF);
        raw.push(Command::Connect.as_u8());

        let result = Header::try_parse_from_buf(&raw);
        assert!(result.is_err(), "bad hex should return Err");
    }

    #[test]
    fn test_try_parse_from_buf_too_short() {
        let raw = vec![b'a'; 10]; // 不足 58 字节
        let result = Header::try_parse_from_buf(&raw).expect("should not error on short buf");
        assert!(result.is_none(), "short buf should return None");
    }
}
