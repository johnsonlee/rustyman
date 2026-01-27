use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use tokio::sync::RwLock;
use tracing::{debug, info};

#[derive(Error, Debug)]
pub enum CertError {
    #[error("Failed to generate certificate: {0}")]
    GenerationError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Certificate error: {0}")]
    RcgenError(#[from] rcgen::Error),
    #[error("Failed to parse certificate: {0}")]
    ParseError(String),
}

/// Certificate Authority for MITM
pub struct CertificateAuthority {
    /// CA certificate (for signing)
    ca_cert: Certificate,
    /// CA certificate in DER format
    ca_cert_der: CertificateDer<'static>,
    /// CA certificate in PEM format
    ca_cert_pem: String,
    /// Cache for generated certificates
    cert_cache: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
    /// Certificate validity in days
    cert_validity_days: u32,
}

/// A certified key pair
pub struct CertifiedKey {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
}

impl CertificateAuthority {
    /// Create a new CA or load from files
    pub fn new(
        ca_cert_path: &str,
        ca_key_path: &str,
        auto_generate: bool,
        ca_validity_days: u32,
        cert_validity_days: u32,
    ) -> Result<Self, CertError> {
        let ca_cert_path = Path::new(ca_cert_path);
        let ca_key_path = Path::new(ca_key_path);

        if ca_cert_path.exists() && ca_key_path.exists() {
            info!("Loading existing CA certificate from {:?}", ca_cert_path);
            Self::load_ca(ca_cert_path, ca_key_path, cert_validity_days)
        } else if auto_generate {
            info!("Generating new CA certificate");
            Self::generate_ca(ca_cert_path, ca_key_path, ca_validity_days, cert_validity_days)
        } else {
            Err(CertError::GenerationError(
                "CA certificate not found and auto_generate is disabled".to_string(),
            ))
        }
    }

    /// Generate a new CA certificate
    fn generate_ca(
        ca_cert_path: &Path,
        ca_key_path: &Path,
        ca_validity_days: u32,
        cert_validity_days: u32,
    ) -> Result<Self, CertError> {
        let mut params = CertificateParams::default();

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "Rustyman CA");
        distinguished_name.push(DnType::OrganizationName, "Rustyman");
        distinguished_name.push(DnType::CountryName, "US");
        params.distinguished_name = distinguished_name;

        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + Duration::days(ca_validity_days as i64);
        params.alg = &PKCS_ECDSA_P256_SHA256;

        // Create the CA certificate
        let ca_cert = Certificate::from_params(params)?;

        // Create parent directories if they don't exist
        if let Some(parent) = ca_cert_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Save CA certificate
        let cert_pem = ca_cert.serialize_pem()?;
        fs::write(ca_cert_path, &cert_pem)?;
        info!("CA certificate saved to {:?}", ca_cert_path);

        // Save CA private key
        let key_pem = ca_cert.serialize_private_key_pem();
        fs::write(ca_key_path, &key_pem)?;
        info!("CA private key saved to {:?}", ca_key_path);

        let ca_cert_der = CertificateDer::from(ca_cert.serialize_der()?);

        Ok(Self {
            ca_cert,
            ca_cert_der,
            ca_cert_pem: cert_pem,
            cert_cache: Arc::new(RwLock::new(HashMap::new())),
            cert_validity_days,
        })
    }

    /// Load CA from existing files
    fn load_ca(
        ca_cert_path: &Path,
        ca_key_path: &Path,
        cert_validity_days: u32,
    ) -> Result<Self, CertError> {
        let cert_pem_content = fs::read_to_string(ca_cert_path)?;
        let key_pem = fs::read_to_string(ca_key_path)?;

        // Load the key pair
        let key_pair = KeyPair::from_pem(&key_pem)?;

        // Create new CA params with the loaded key
        let mut params = CertificateParams::default();

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "Rustyman CA");
        distinguished_name.push(DnType::OrganizationName, "Rustyman");
        distinguished_name.push(DnType::CountryName, "US");
        params.distinguished_name = distinguished_name;

        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + Duration::days(3650);
        params.key_pair = Some(key_pair);

        let ca_cert = Certificate::from_params(params)?;

        // Parse PEM to DER for the original cert
        let pem = pem::parse(&cert_pem_content).map_err(|e| CertError::ParseError(e.to_string()))?;
        let ca_cert_der = CertificateDer::from(pem.contents().to_vec());

        Ok(Self {
            ca_cert,
            ca_cert_der,
            ca_cert_pem: cert_pem_content,
            cert_cache: Arc::new(RwLock::new(HashMap::new())),
            cert_validity_days,
        })
    }

    /// Get CA certificate in DER format
    pub fn ca_cert_der(&self) -> &CertificateDer<'static> {
        &self.ca_cert_der
    }

    /// Get CA certificate in PEM format
    pub fn ca_cert_pem(&self) -> String {
        self.ca_cert_pem.clone()
    }

    /// Generate or retrieve a certificate for a domain
    pub async fn get_cert_for_domain(&self, domain: &str) -> Result<Arc<CertifiedKey>, CertError> {
        // Check cache first
        {
            let cache = self.cert_cache.read().await;
            if let Some(cert) = cache.get(domain) {
                debug!("Using cached certificate for {}", domain);
                return Ok(Arc::clone(cert));
            }
        }

        // Generate new certificate
        debug!("Generating certificate for {}", domain);
        let certified_key = self.generate_cert_for_domain(domain)?;
        let certified_key = Arc::new(certified_key);

        // Store in cache
        {
            let mut cache = self.cert_cache.write().await;
            cache.insert(domain.to_string(), Arc::clone(&certified_key));
        }

        Ok(certified_key)
    }

    /// Generate a certificate for a specific domain
    fn generate_cert_for_domain(&self, domain: &str) -> Result<CertifiedKey, CertError> {
        let mut params = CertificateParams::default();

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, domain);
        distinguished_name.push(DnType::OrganizationName, "Rustyman");
        params.distinguished_name = distinguished_name;

        params.subject_alt_names = vec![SanType::DnsName(domain.try_into().map_err(|e| {
            CertError::GenerationError(format!("Invalid domain name: {}", e))
        })?)];

        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + Duration::days(self.cert_validity_days as i64);
        params.alg = &PKCS_ECDSA_P256_SHA256;

        // Create the certificate
        let cert = Certificate::from_params(params)?;

        // Sign with CA
        let cert_der_bytes = cert.serialize_der_with_signer(&self.ca_cert)?;
        let cert_der = CertificateDer::from(cert_der_bytes);
        let ca_cert_der = self.ca_cert_der.clone();

        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            cert.serialize_private_key_der(),
        ));

        Ok(CertifiedKey {
            cert_chain: vec![cert_der, ca_cert_der],
            private_key,
        })
    }

    /// Clear certificate cache
    pub async fn clear_cache(&self) {
        let mut cache = self.cert_cache.write().await;
        cache.clear();
        info!("Certificate cache cleared");
    }

    /// Get cache size
    pub async fn cache_size(&self) -> usize {
        let cache = self.cert_cache.read().await;
        cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_ca_generation() {
        let temp_dir = TempDir::new().unwrap();
        let ca_cert_path = temp_dir.path().join("ca.crt");
        let ca_key_path = temp_dir.path().join("ca.key");

        let _ca = CertificateAuthority::new(
            ca_cert_path.to_str().unwrap(),
            ca_key_path.to_str().unwrap(),
            true,
            3650,
            365,
        )
        .unwrap();

        assert!(ca_cert_path.exists());
        assert!(ca_key_path.exists());
    }

    #[tokio::test]
    async fn test_domain_cert_generation() {
        let temp_dir = TempDir::new().unwrap();
        let ca_cert_path = temp_dir.path().join("ca.crt");
        let ca_key_path = temp_dir.path().join("ca.key");

        let ca = CertificateAuthority::new(
            ca_cert_path.to_str().unwrap(),
            ca_key_path.to_str().unwrap(),
            true,
            3650,
            365,
        )
        .unwrap();

        let cert = ca.get_cert_for_domain("example.com").await.unwrap();
        assert_eq!(cert.cert_chain.len(), 2);
    }
}
