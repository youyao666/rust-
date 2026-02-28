use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ResolvesServerCert, ServerConfig, WebPkiClientVerifier};
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::debug;

use crate::error::{Result, TrojanError};

pub struct RealityConfig {
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
    pub target_domain: String,
    pub alpn_protocols: Vec<Vec<u8>>,
}

impl RealityConfig {
    pub fn new(cert_path: &str, key_path: &str, target_domain: String) -> Result<Self> {
        let cert_chain = load_certs(cert_path)?;
        let private_key = load_private_key(key_path)?;

        Ok(Self {
            cert_chain,
            private_key,
            target_domain,
            alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        })
    }

    pub fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert_chain
    }

    pub fn private_key(&self) -> &PrivateKeyDer<'static> {
        &self.private_key
    }
}

pub struct RealityHandshake {
    config: Arc<ServerConfig>,
    fallback_config: Option<Arc<ServerConfig>>,
}

impl RealityHandshake {
    pub fn new(config: RealityConfig) -> Result<Self> {
        let server_config = Self::build_server_config(&config)?;

        Ok(Self {
            config: Arc::new(server_config),
            fallback_config: None,
        })
    }

    pub fn with_fallback(mut self, fallback_config: RealityConfig) -> Result<Self> {
        let fallback = Self::build_server_config(&fallback_config)?;
        self.fallback_config = Some(Arc::new(fallback));
        Ok(self)
    }

    fn build_server_config(config: &RealityConfig) -> Result<ServerConfig> {
        let mut server_config = ServerConfig::builder()
            .with_client_cert_verifier(WebPkiClientVerifier::no_client_auth())
            .with_cert_resolver(Arc::new(CertResolver::new(
                config.cert_chain.clone(),
                config.private_key.clone_key(),
            )?));

        server_config.alpn_protocols = config.alpn_protocols.clone();
        server_config.session_storage = rustls::server::ServerSessionMemoryCache::new(256);

        Ok(server_config)
    }

    pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
    ) -> Result<TlsStream<S>> {
        let acceptor = TlsAcceptor::from(Arc::clone(&self.config));
        let tls_stream = acceptor.accept(stream).await?;

        let handshake = tls_stream.get_ref().1;
        debug!(
            "TLS handshake completed: ALPN={:?}, SNI={:?}",
            handshake.alpn_protocol(),
            handshake.server_name()
        );

        Ok(tls_stream)
    }

    pub fn get_browsersim_config() -> ClientConfig {
        let mut config = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        config
    }
}

#[derive(Debug)]
struct CertResolver {
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

impl CertResolver {
    fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self> {
        Ok(Self {
            cert_chain,
            private_key,
        })
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        use rustls::crypto::ring::sign::any_supported_type;

        let certified_key = any_supported_type(&self.private_key)
            .ok()
            .map(|key| rustls::sign::CertifiedKey::new(self.cert_chain.clone(), key))?;

        Some(Arc::new(certified_key))
    }
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .map_err(|e| TrojanError::Tls(format!("Failed to open cert file: {}", e)))?;

    let mut reader = std::io::BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .filter_map(|c| c.ok())
        .collect();

    if certs.is_empty() {
        return Err(TrojanError::Tls("No certificates found".to_string()));
    }

    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .map_err(|e| TrojanError::Tls(format!("Failed to open key file: {}", e)))?;

    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| TrojanError::Tls(format!("Failed to parse key: {}", e)))?
        .ok_or_else(|| TrojanError::Tls("No private key found".to_string()))
}
