use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Failed to parse YAML: {0}")]
    YamlError(#[from] serde_yaml::Error),
}

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Proxy server settings
    pub proxy: ProxyConfig,
    /// Web UI settings
    pub web_ui: WebUiConfig,
    /// Certificate settings
    pub cert: CertConfig,
    /// Logging settings
    pub logging: LoggingConfig,
    /// Map Remote rules
    pub map_remote: Vec<MapRemoteRule>,
    /// Map Local rules
    pub map_local: Vec<MapLocalRule>,
    /// Header rewrite rules
    pub header_rules: Vec<HeaderRule>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            proxy: ProxyConfig::default(),
            web_ui: WebUiConfig::default(),
            cert: CertConfig::default(),
            logging: LoggingConfig::default(),
            map_remote: Vec::new(),
            map_local: Vec::new(),
            header_rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// Proxy listen address
    pub host: String,
    /// Proxy listen port
    pub port: u16,
    /// Enable HTTPS MITM
    pub mitm_enabled: bool,
    /// Request timeout in seconds
    pub timeout: u64,
    /// Max concurrent connections
    pub max_connections: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            mitm_enabled: true,
            timeout: 30,
            max_connections: 1000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebUiConfig {
    /// Enable Web UI
    pub enabled: bool,
    /// Web UI listen address
    pub host: String,
    /// Web UI listen port
    pub port: u16,
}

impl Default for WebUiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            host: "127.0.0.1".to_string(),
            port: 8081,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CertConfig {
    /// CA certificate path
    pub ca_cert: String,
    /// CA private key path
    pub ca_key: String,
    /// Auto-generate CA if not found
    pub auto_generate: bool,
    /// CA certificate validity in days
    pub ca_validity_days: u32,
    /// Generated certificate validity in days
    pub cert_validity_days: u32,
}

impl Default for CertConfig {
    fn default() -> Self {
        Self {
            ca_cert: "~/.rustyman/ca.crt".to_string(),
            ca_key: "~/.rustyman/ca.key".to_string(),
            auto_generate: true,
            ca_validity_days: 3650,
            cert_validity_days: 365,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error
    pub level: String,
    /// Log format: text, json
    pub format: String,
    /// Log file path (optional)
    pub file: Option<String>,
    /// Enable request/response logging
    pub log_traffic: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "text".to_string(),
            file: None,
            log_traffic: false,
        }
    }
}

/// Map Remote rule - redirect requests to a different URL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapRemoteRule {
    /// Rule name for identification
    pub name: String,
    /// Enable/disable this rule
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// URL pattern to match (supports regex)
    pub pattern: String,
    /// Target URL to redirect to
    pub target: String,
    /// Preserve original path
    #[serde(default)]
    pub preserve_path: bool,
    /// Preserve original query string
    #[serde(default = "default_true")]
    pub preserve_query: bool,
}

/// Map Local rule - serve local files for matching requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapLocalRule {
    /// Rule name for identification
    pub name: String,
    /// Enable/disable this rule
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// URL pattern to match (supports regex)
    pub pattern: String,
    /// Local file or directory path
    pub local_path: String,
    /// MIME type override (optional)
    pub mime_type: Option<String>,
}

/// Header rewrite rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderRule {
    /// Rule name for identification
    pub name: String,
    /// Enable/disable this rule
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// URL pattern to match (supports regex)
    pub url_pattern: String,
    /// Apply to request headers
    #[serde(default = "default_true")]
    pub apply_to_request: bool,
    /// Apply to response headers
    #[serde(default = "default_true")]
    pub apply_to_response: bool,
    /// Header operations
    pub operations: Vec<HeaderOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderOperation {
    /// Operation type: add, remove, modify
    pub action: HeaderAction,
    /// Header name (supports regex for match)
    pub name: String,
    /// Header value (for add/modify)
    pub value: Option<String>,
    /// Value pattern for regex replacement in modify
    pub value_pattern: Option<String>,
    /// Replacement value for regex replacement
    pub replacement: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HeaderAction {
    Add,
    Remove,
    Modify,
}

fn default_true() -> bool {
    true
}

impl Config {
    /// Load configuration from a YAML file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to a YAML file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        let content = serde_yaml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Create a default configuration file
    pub fn create_default<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let config = Config::default();
        config.save(path)?;
        Ok(config)
    }

    /// Expand tilde in paths
    pub fn expand_paths(&mut self) {
        if let Some(home) = dirs_home() {
            self.cert.ca_cert = self.cert.ca_cert.replace('~', &home);
            self.cert.ca_key = self.cert.ca_key.replace('~', &home);
            if let Some(ref mut file) = self.logging.file {
                *file = file.replace('~', &home);
            }
        }
    }
}

fn dirs_home() -> Option<String> {
    std::env::var("HOME").ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.proxy.port, 8080);
        assert!(config.proxy.mitm_enabled);
        assert!(config.web_ui.enabled);
    }

    #[test]
    fn test_yaml_serialization() {
        let config = Config::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed: Config = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.proxy.port, config.proxy.port);
    }
}
