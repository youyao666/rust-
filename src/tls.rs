use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::info;

use crate::error::{Result, TrojanError};

pub struct TlsConfig {
    acceptor: TlsAcceptor,
}

impl TlsConfig {
    /// 初始化 TLS 配置。
    ///
    /// 安全策略（与 Chrome/Firefox 现代握手特征对齐）：
    /// - **仅支持 TLS 1.3**：消除 TLS 1.2 降级特征，与现代浏览器行为一致。
    ///   TLS 1.2 在主动探测中会暴露更多握手特征（cipher suite 列表等）。
    /// - **ALPN 协商**：优先 h2（HTTP/2），其次 http/1.1，与真实 HTTPS 服务器完全一致。
    /// - **服务端不强制 cipher 顺序**：`ignore_client_order = true`，
    ///   让客户端选择 cipher，进一步模拟正常 Web 服务器行为。
    /// - **Session ticket 启用**：TLS 1.3 session resumption 特征。
    ///
    /// 注：rustls 0.22 在 TLS 1.3 中自动选择 X25519 key share，
    /// 与 Chrome 的 key_share 扩展顺序一致（X25519 优先）。
    pub fn new(cert_path: &str, key_path: &str) -> Result<Self> {
        let certs = load_certs(cert_path)?;
        let key = load_key(key_path)?;

        // TLS 1.3 Only — 消除 TLS 1.2 指纹特征
        let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| TrojanError::Tls(format!("Failed to create TLS config: {}", e)))?;

        // ALPN：h2 优先，兼容 http/1.1 —— 与 Nginx/Caddy 默认配置完全一致
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        // 允许客户端选择 cipher suite 顺序，模拟真实 Web 服务器
        config.ignore_client_order = true;

        // TLS 1.3 session ticket（0-RTT 特征）：rustls 默认启用，无需额外配置
        // 这与 Chrome 的 session ticket 行为（early_data hint）保持一致

        // 最大帧大小：16 KB = TLS 记录层最大值
        // rustls 默认使用此值，与 Chrome 的 max_fragment_length 扩展行为一致
        // （注：rustls 0.22 通过 max_fragment_size 字段配置，默认已是 16384）

        let acceptor = TlsAcceptor::from(Arc::new(config));
        info!("TLS configuration initialized (TLS 1.3 only, ALPN: h2/http1.1)");
        Ok(Self { acceptor })
    }

    pub fn acceptor(&self) -> TlsAcceptor {
        self.acceptor.clone()
    }
}

fn load_certs<P: AsRef<Path>>(path: P) -> Result<Vec<CertificateDer<'static>>> {
    let file = fs::File::open(path)
        .map_err(|e| TrojanError::Tls(format!("Failed to open certificate file: {}", e)))?;

    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| TrojanError::Tls(format!("Failed to parse certificate chain: {}", e)))?;

    if certs.is_empty() {
        return Err(TrojanError::Tls(
            "No certificates found in file".to_string(),
        ));
    }

    Ok(certs)
}

fn load_key<P: AsRef<Path>>(path: P) -> Result<PrivateKeyDer<'static>> {
    let file = fs::File::open(path)
        .map_err(|e| TrojanError::Tls(format!("Failed to open key file: {}", e)))?;

    let mut reader = BufReader::new(file);

    if let Some(key) = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| TrojanError::Tls(format!("Failed to parse private key: {}", e)))?
    {
        Ok(key)
    } else {
        Err(TrojanError::Tls("No private key found in file".to_string()))
    }
}
