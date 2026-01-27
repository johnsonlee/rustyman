use crate::cert::CertifiedKey;
use crate::proxy::ProxyError;
use rustls::server::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor as TokioTlsAcceptor;

/// TLS acceptor wrapper for MITM
pub struct TlsAcceptor {
    inner: TokioTlsAcceptor,
}

impl TlsAcceptor {
    /// Create TLS acceptor from a certified key
    pub fn from_certified_key(certified_key: &CertifiedKey) -> Result<Self, ProxyError> {
        let config = Self::create_server_config(
            certified_key.cert_chain.clone(),
            certified_key.private_key.clone_key(),
        )?;

        Ok(Self {
            inner: TokioTlsAcceptor::from(Arc::new(config)),
        })
    }

    /// Create TLS server config
    fn create_server_config(
        cert_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<ServerConfig, ProxyError> {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| ProxyError::TlsError(format!("Failed to create TLS config: {}", e)))?;

        Ok(config)
    }

    /// Accept TLS connection
    pub async fn accept<IO>(&self, stream: IO) -> Result<tokio_rustls::server::TlsStream<IO>, ProxyError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.inner
            .accept(stream)
            .await
            .map_err(|e| ProxyError::TlsError(format!("TLS accept failed: {}", e)))
    }
}
