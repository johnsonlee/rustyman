mod handler;
mod tls;

pub use handler::ProxyHandler;

use crate::cert::CertificateAuthority;
use crate::config::Config;
use crate::rules::RuleEngine;
use crate::traffic::TrafficStore;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    TlsError(String),
    #[error("Certificate error: {0}")]
    CertError(#[from] crate::cert::CertError),
    #[error("Rule error: {0}")]
    RuleError(#[from] crate::rules::RuleError),
    #[error("HTTP error: {0}")]
    HttpError(String),
}

/// Shared proxy state
pub struct ProxyState {
    pub config: RwLock<Config>,
    pub ca: Arc<CertificateAuthority>,
    pub rules: RwLock<RuleEngine>,
    pub traffic: Arc<TrafficStore>,
}

impl ProxyState {
    pub fn new(config: Config, ca: CertificateAuthority) -> Result<Self, ProxyError> {
        let rules = RuleEngine::new(
            config.map_remote.clone(),
            config.map_local.clone(),
            config.header_rules.clone(),
        )?;

        Ok(Self {
            config: RwLock::new(config),
            ca: Arc::new(ca),
            rules: RwLock::new(rules),
            traffic: Arc::new(TrafficStore::default()),
        })
    }

    /// Reload rules from config
    pub async fn reload_rules(&self) -> Result<(), ProxyError> {
        let config = self.config.read().await;
        let mut rules = self.rules.write().await;

        *rules = RuleEngine::new(
            config.map_remote.clone(),
            config.map_local.clone(),
            config.header_rules.clone(),
        )?;

        info!("Rules reloaded");
        Ok(())
    }
}

/// HTTP/HTTPS proxy server
pub struct ProxyServer {
    state: Arc<ProxyState>,
}

impl ProxyServer {
    pub fn new(config: Config, ca: CertificateAuthority) -> Result<Self, ProxyError> {
        let state = Arc::new(ProxyState::new(config, ca)?);
        Ok(Self { state })
    }

    pub fn state(&self) -> Arc<ProxyState> {
        Arc::clone(&self.state)
    }

    /// Start the proxy server
    pub async fn run(&self, cancel_token: CancellationToken) -> Result<(), ProxyError> {
        let config = self.state.config.read().await;
        let addr: SocketAddr = format!("{}:{}", config.proxy.host, config.proxy.port)
            .parse()
            .map_err(|e| ProxyError::IoError(std::io::Error::other(format!("Invalid address: {}", e))))?;
        drop(config);

        let listener = TcpListener::bind(addr).await?;
        info!("Proxy server listening on {}", addr);

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    info!("Proxy server shutting down...");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((stream, client_addr)) => {
                            let state = Arc::clone(&self.state);
                            let token = cancel_token.clone();
                            tokio::spawn(async move {
                                let handler = ProxyHandler::new(state, client_addr);
                                tokio::select! {
                                    _ = token.cancelled() => {}
                                    result = handler.handle(stream) => {
                                        if let Err(e) = result {
                                            error!("Error handling connection from {}: {}", client_addr, e);
                                        }
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept connection: {}", e);
                        }
                    }
                }
            }
        }

        info!("Proxy server stopped");
        Ok(())
    }
}
