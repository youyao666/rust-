use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use tracing::info;

use crate::error::{Result, TrojanError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    pub tls_cert: String,
    pub tls_key: String,

    pub passwords: Vec<String>,

    #[serde(default = "default_udp_bind_addr")]
    pub udp_bind_addr: String,

    #[serde(default = "default_log_level")]
    pub log_level: String,

    #[serde(default = "default_tcp_timeout")]
    pub tcp_timeout: u64,

    #[serde(default = "default_udp_timeout")]
    pub udp_timeout: u64,

    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// 回落地址：当协议校验失败时，将原始数据透明转发到此地址（通常为本地 Web 服务）
    #[serde(default = "default_fallback_addr")]
    pub fallback_addr: String,
}

fn default_bind_addr() -> String {
    "0.0.0.0:443".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_tcp_timeout() -> u64 {
    300
}

fn default_udp_timeout() -> u64 {
    60
}

fn default_udp_bind_addr() -> String {
    "0.0.0.0:0".to_string()
}

fn default_max_connections() -> usize {
    1024
}

fn default_fallback_addr() -> String {
    "127.0.0.1:80".to_string()
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| TrojanError::Config(format!("Failed to read config file: {}", e)))?;

        let config: Config = toml::from_str(&content)
            .map_err(|e| TrojanError::Config(format!("Failed to parse config: {}", e)))?;

        config.validate()?;
        info!("Configuration loaded successfully");
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.passwords.is_empty() {
            return Err(TrojanError::Config(
                "At least one password must be configured".to_string(),
            ));
        }

        if !Path::new(&self.tls_cert).exists() {
            return Err(TrojanError::Config(format!(
                "TLS certificate file not found: {}",
                self.tls_cert
            )));
        }

        if !Path::new(&self.tls_key).exists() {
            return Err(TrojanError::Config(format!(
                "TLS key file not found: {}",
                self.tls_key
            )));
        }

        if !self
            .passwords
            .iter()
            .all(|p| p.len() == 56 && p.as_bytes().iter().all(u8::is_ascii_hexdigit))
        {
            return Err(TrojanError::Config(
                "All passwords must be SHA-224 hex strings (56 hex chars)".to_string(),
            ));
        }

        if self.udp_bind_addr.parse::<SocketAddr>().is_err() {
            return Err(TrojanError::Config(format!(
                "Invalid udp_bind_addr socket address: {}",
                self.udp_bind_addr
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config {
            bind_addr: default_bind_addr(),
            tls_cert: "certs/cert.pem".to_string(),
            tls_key: "certs/key.pem".to_string(),
            passwords: vec!["5fd924625f6ab16a19cc9807c7c506ae1813490e4ba675f843d5a10e".to_string()],
            udp_bind_addr: default_udp_bind_addr(),
            log_level: default_log_level(),
            tcp_timeout: default_tcp_timeout(),
            udp_timeout: default_udp_timeout(),
            max_connections: default_max_connections(),
            fallback_addr: default_fallback_addr(),
        };

        assert_eq!(config.bind_addr, "0.0.0.0:443");
        assert_eq!(config.log_level, "info");
        assert_eq!(config.tcp_timeout, 300);
        assert_eq!(config.udp_timeout, 60);
        assert_eq!(config.max_connections, 1024);
        assert_eq!(config.udp_bind_addr, "0.0.0.0:0");
    }
}
