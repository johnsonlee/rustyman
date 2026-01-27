mod header;
mod map_local;
mod map_remote;

pub use header::HeaderRewriter;
pub use map_local::MapLocalHandler;
pub use map_remote::MapRemoteHandler;

use crate::config::{HeaderRule, MapLocalRule, MapRemoteRule};
use regex::Regex;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RuleError {
    #[error("Invalid regex pattern: {0}")]
    InvalidPattern(#[from] regex::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("URL parse error: {0}")]
    UrlError(#[from] url::ParseError),
}

/// Compiled rule with regex pattern
#[derive(Clone)]
pub struct CompiledRule<T: Clone> {
    pub rule: T,
    pub pattern: Arc<Regex>,
}

/// Rule engine that holds all compiled rules
pub struct RuleEngine {
    pub map_remote: MapRemoteHandler,
    pub map_local: MapLocalHandler,
    pub header_rewriter: HeaderRewriter,
}

impl RuleEngine {
    pub fn new(
        map_remote_rules: Vec<MapRemoteRule>,
        map_local_rules: Vec<MapLocalRule>,
        header_rules: Vec<HeaderRule>,
    ) -> Result<Self, RuleError> {
        Ok(Self {
            map_remote: MapRemoteHandler::new(map_remote_rules)?,
            map_local: MapLocalHandler::new(map_local_rules)?,
            header_rewriter: HeaderRewriter::new(header_rules)?,
        })
    }

    /// Update rules at runtime
    pub fn update_map_remote(&mut self, rules: Vec<MapRemoteRule>) -> Result<(), RuleError> {
        self.map_remote = MapRemoteHandler::new(rules)?;
        Ok(())
    }

    pub fn update_map_local(&mut self, rules: Vec<MapLocalRule>) -> Result<(), RuleError> {
        self.map_local = MapLocalHandler::new(rules)?;
        Ok(())
    }

    pub fn update_header_rules(&mut self, rules: Vec<HeaderRule>) -> Result<(), RuleError> {
        self.header_rewriter = HeaderRewriter::new(rules)?;
        Ok(())
    }
}
