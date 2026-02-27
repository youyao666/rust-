use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{Result, TrojanError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    IPv4(SocketAddr),
    IPv6(SocketAddr),
    Domain(String, u16),
}

impl Address {
    pub const TYPE_IPV4: u8 = 0x01;
    pub const TYPE_DOMAIN: u8 = 0x03;
    pub const TYPE_IPV6: u8 = 0x04;

    #[allow(dead_code)]
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let addr_type = reader.read_u8().await?;

        match addr_type {
            Self::TYPE_IPV4 => {
                let mut buf = [0u8; 4];
                reader.read_exact(&mut buf).await?;
                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = reader.read_u16().await?;
                Ok(Address::IPv4(SocketAddr::new(ip.into(), port)))
            }
            Self::TYPE_DOMAIN => {
                let len = reader.read_u8().await? as usize;
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf).await?;
                let domain = String::from_utf8(buf).map_err(|_| TrojanError::InvalidUtf8)?;
                let port = reader.read_u16().await?;
                Ok(Address::Domain(domain, port))
            }
            Self::TYPE_IPV6 => {
                let mut buf = [0u8; 16];
                reader.read_exact(&mut buf).await?;
                let ip = Ipv6Addr::new(
                    u16::from_be_bytes([buf[0], buf[1]]),
                    u16::from_be_bytes([buf[2], buf[3]]),
                    u16::from_be_bytes([buf[4], buf[5]]),
                    u16::from_be_bytes([buf[6], buf[7]]),
                    u16::from_be_bytes([buf[8], buf[9]]),
                    u16::from_be_bytes([buf[10], buf[11]]),
                    u16::from_be_bytes([buf[12], buf[13]]),
                    u16::from_be_bytes([buf[14], buf[15]]),
                );
                let port = reader.read_u16().await?;
                Ok(Address::IPv6(SocketAddr::new(ip.into(), port)))
            }
            _ => Err(TrojanError::InvalidAddressType(addr_type)),
        }
    }

    /// 从字节切片中解析地址（不消耗 IO 流）。
    ///
    /// 返回 `Ok((address, consumed_bytes))` 或
    ///       `Ok` 下 `None` 表示数据不足需要更多字节，
    ///       `Err` 表示格式非法。
    /// 实际上返回 `Result<Option<(Address, usize)>>`：
    ///   - `Ok(Some((addr, n)))` — 成功，消耗了 n 字节
    ///   - `Ok(None)`           — 数据不足
    ///   - `Err(_)`             — 格式错误
    pub fn parse_from_buf(buf: &[u8]) -> Result<(Address, Option<usize>)> {
        if buf.is_empty() {
            return Ok((Address::Domain(String::new(), 0), None));
        }

        let addr_type = buf[0];
        let payload = &buf[1..];

        match addr_type {
            Self::TYPE_IPV4 => {
                // 需要 4 字节 IP + 2 字节端口 = 6 字节
                if payload.len() < 6 {
                    return Ok((Address::Domain(String::new(), 0), None));
                }
                let ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
                let port = u16::from_be_bytes([payload[4], payload[5]]);
                let addr = Address::IPv4(SocketAddr::new(ip.into(), port));
                Ok((addr, Some(1 + 6))) // type(1) + ip(4) + port(2)
            }
            Self::TYPE_DOMAIN => {
                if payload.is_empty() {
                    return Ok((Address::Domain(String::new(), 0), None));
                }
                let domain_len = payload[0] as usize;
                // 需要 1(len) + domain_len + 2(port)
                if payload.len() < 1 + domain_len + 2 {
                    return Ok((Address::Domain(String::new(), 0), None));
                }
                let domain_bytes = &payload[1..1 + domain_len];
                let domain = String::from_utf8(domain_bytes.to_vec())
                    .map_err(|_| TrojanError::InvalidUtf8)?;
                let port =
                    u16::from_be_bytes([payload[1 + domain_len], payload[1 + domain_len + 1]]);
                let addr = Address::Domain(domain, port);
                Ok((addr, Some(1 + 1 + domain_len + 2))) // type(1) + len(1) + domain + port(2)
            }
            Self::TYPE_IPV6 => {
                // 需要 16 字节 IP + 2 字节端口 = 18 字节
                if payload.len() < 18 {
                    return Ok((Address::Domain(String::new(), 0), None));
                }
                let ip = Ipv6Addr::new(
                    u16::from_be_bytes([payload[0], payload[1]]),
                    u16::from_be_bytes([payload[2], payload[3]]),
                    u16::from_be_bytes([payload[4], payload[5]]),
                    u16::from_be_bytes([payload[6], payload[7]]),
                    u16::from_be_bytes([payload[8], payload[9]]),
                    u16::from_be_bytes([payload[10], payload[11]]),
                    u16::from_be_bytes([payload[12], payload[13]]),
                    u16::from_be_bytes([payload[14], payload[15]]),
                );
                let port = u16::from_be_bytes([payload[16], payload[17]]);
                let addr = Address::IPv6(SocketAddr::new(ip.into(), port));
                Ok((addr, Some(1 + 18))) // type(1) + ip(16) + port(2)
            }
            _ => Err(TrojanError::InvalidAddressType(addr_type)),
        }
    }

    #[allow(dead_code)]
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(1 + 16 + 2);

        match self {
            Address::IPv4(addr) => {
                result.push(Self::TYPE_IPV4);
                match addr {
                    SocketAddr::V4(v4) => result.extend_from_slice(&v4.ip().octets()),
                    SocketAddr::V6(_) => {
                        return Err(TrojanError::Protocol(
                            "Address::IPv4 variant contains non-IPv4 socket address".to_string(),
                        ))
                    }
                }
                result.extend_from_slice(&addr.port().to_be_bytes());
            }
            Address::Domain(domain, port) => {
                if domain.is_empty() || domain.len() > u8::MAX as usize {
                    return Err(TrojanError::Protocol(
                        "Domain length must be between 1 and 255 bytes".to_string(),
                    ));
                }

                result.push(Self::TYPE_DOMAIN);
                result.push(domain.len() as u8);
                result.extend_from_slice(domain.as_bytes());
                result.extend_from_slice(&port.to_be_bytes());
            }
            Address::IPv6(addr) => {
                result.push(Self::TYPE_IPV6);
                match addr {
                    SocketAddr::V6(v6) => result.extend_from_slice(&v6.ip().octets()),
                    SocketAddr::V4(_) => {
                        return Err(TrojanError::Protocol(
                            "Address::IPv6 variant contains non-IPv6 socket address".to_string(),
                        ))
                    }
                }
                result.extend_from_slice(&addr.port().to_be_bytes());
            }
        }

        Ok(result)
    }

    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        match self {
            Address::IPv4(addr) => addr.port(),
            Address::IPv6(addr) => addr.port(),
            Address::Domain(_, port) => *port,
        }
    }

    #[allow(dead_code)]
    pub fn host(&self) -> String {
        match self {
            Address::IPv4(addr) => addr.ip().to_string(),
            Address::IPv6(addr) => addr.ip().to_string(),
            Address::Domain(domain, _) => domain.clone(),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::IPv4(addr) => write!(f, "{}", addr),
            Address::IPv6(addr) => write!(f, "{}", addr),
            Address::Domain(domain, port) => write!(f, "{}:{}", domain, port),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    #[test]
    fn test_address_ipv4() {
        let addr = Address::IPv4(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            8080,
        )));
        assert_eq!(addr.port(), 8080);
        assert_eq!(addr.host(), "127.0.0.1");
    }

    #[test]
    fn test_address_domain() {
        let addr = Address::Domain("example.com".to_string(), 443);
        assert_eq!(addr.port(), 443);
        assert_eq!(addr.host(), "example.com");
    }
}
