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
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| ProxyError::TlsError(format!("Failed to create TLS config: {}", e)))?;

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

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

    /// Accept TLS connection and return the negotiated ALPN protocol
    pub async fn accept_with_alpn<IO>(
        &self,
        stream: IO,
    ) -> Result<(tokio_rustls::server::TlsStream<IO>, Option<Vec<u8>>), ProxyError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let tls_stream = self.inner
            .accept(stream)
            .await
            .map_err(|e| ProxyError::TlsError(format!("TLS accept failed: {}", e)))?;

        let alpn = tls_stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        Ok((tls_stream, alpn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::CertificateAuthority;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::DigitallySignedStruct;
    use tokio::net::{TcpListener, TcpStream};

    #[derive(Debug)]
    struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }

    #[tokio::test]
    async fn test_alpn_h2_negotiation() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let ca = CertificateAuthority::new(
            temp_dir.path().join("ca.crt").to_str().unwrap(),
            temp_dir.path().join("ca.key").to_str().unwrap(),
            true,
            3650,
            365,
        )
        .unwrap();

        let cert = ca.get_cert_for_domain("localhost").await.unwrap();
        let acceptor = TlsAcceptor::from_certified_key(&cert).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server: accept TLS with ALPN
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (_, alpn) = acceptor.accept_with_alpn(stream).await.unwrap();
            alpn
        });

        // Client: connect with ALPN [h2, http/1.1]
        let mut config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let stream = TcpStream::connect(addr).await.unwrap();
        let server_name = ServerName::try_from("localhost").unwrap();
        let tls_stream = connector.connect(server_name, stream).await.unwrap();

        let client_alpn = tls_stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        let server_alpn = server.await.unwrap();

        assert_eq!(server_alpn, Some(b"h2".to_vec()));
        assert_eq!(client_alpn, Some(b"h2".to_vec()));
    }
}
