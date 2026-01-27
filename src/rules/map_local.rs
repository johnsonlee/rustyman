use super::{CompiledRule, RuleError};
use crate::config::MapLocalRule;
use regex::Regex;
use std::path::Path;
use std::sync::Arc;
use tracing::debug;

/// Handler for Map Local rules
pub struct MapLocalHandler {
    rules: Vec<CompiledRule<MapLocalRule>>,
}

impl MapLocalHandler {
    pub fn new(rules: Vec<MapLocalRule>) -> Result<Self, RuleError> {
        let compiled: Result<Vec<CompiledRule<MapLocalRule>>, RuleError> = rules
            .into_iter()
            .filter(|r| r.enabled)
            .map(|rule| {
                let pattern = Regex::new(&rule.pattern)?;
                Ok(CompiledRule {
                    rule,
                    pattern: Arc::new(pattern),
                })
            })
            .collect();

        Ok(Self { rules: compiled? })
    }

    /// Check if a URL matches any map local rule
    pub fn match_url(&self, url: &str) -> Option<MapLocalMatch> {
        for compiled in &self.rules {
            if compiled.pattern.is_match(url) {
                debug!("Map Local rule '{}' matched: {}", compiled.rule.name, url);

                let local_path = self.resolve_path(url, &compiled.rule, &compiled.pattern);

                return Some(MapLocalMatch {
                    rule_name: compiled.rule.name.clone(),
                    original_url: url.to_string(),
                    local_path,
                    mime_type: compiled.rule.mime_type.clone(),
                });
            }
        }
        None
    }

    /// Resolve the local path for a matched URL
    fn resolve_path(&self, url: &str, rule: &MapLocalRule, pattern: &Regex) -> String {
        let local_path = &rule.local_path;

        // If the local path contains capture groups, use regex replacement
        if local_path.contains('$') {
            return pattern.replace(url, local_path).to_string();
        }

        // Check if local_path is a directory
        let path = Path::new(local_path);
        if path.is_dir() {
            // Extract the path component from the URL and append to local path
            if let Ok(parsed) = url::Url::parse(url) {
                let url_path = parsed.path().trim_start_matches('/');
                return path.join(url_path).to_string_lossy().to_string();
            }
        }

        local_path.clone()
    }

    /// Read file content from a local path
    pub async fn read_file(&self, path: &str) -> Result<MapLocalContent, RuleError> {
        let path = Path::new(path);

        if !path.exists() {
            return Ok(MapLocalContent {
                content: Vec::new(),
                mime_type: None,
                exists: false,
            });
        }

        let content = tokio::fs::read(path).await?;
        let mime_type = mime_guess::from_path(path)
            .first()
            .map(|m| m.to_string());

        Ok(MapLocalContent {
            content,
            mime_type,
            exists: true,
        })
    }

    /// Get all rules
    pub fn rules(&self) -> Vec<&MapLocalRule> {
        self.rules.iter().map(|r| &r.rule).collect()
    }

    /// Check if there are any active rules
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Result of a map local match
#[derive(Debug, Clone)]
pub struct MapLocalMatch {
    pub rule_name: String,
    pub original_url: String,
    pub local_path: String,
    pub mime_type: Option<String>,
}

/// Content read from local file
#[derive(Debug)]
pub struct MapLocalContent {
    pub content: Vec<u8>,
    pub mime_type: Option<String>,
    pub exists: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_simple_match() {
        let rules = vec![MapLocalRule {
            name: "test".to_string(),
            enabled: true,
            pattern: r"https://example\.com/static/(.*)".to_string(),
            local_path: "/var/www/static/$1".to_string(),
            mime_type: None,
        }];

        let handler = MapLocalHandler::new(rules).unwrap();
        let result = handler.match_url("https://example.com/static/js/app.js");

        assert!(result.is_some());
        let matched = result.unwrap();
        assert_eq!(matched.rule_name, "test");
        assert_eq!(matched.local_path, "/var/www/static/js/app.js");
    }

    #[tokio::test]
    async fn test_read_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "Hello, World!").unwrap();

        let rules = vec![MapLocalRule {
            name: "test".to_string(),
            enabled: true,
            pattern: r".*".to_string(),
            local_path: test_file.to_string_lossy().to_string(),
            mime_type: None,
        }];

        let handler = MapLocalHandler::new(rules).unwrap();
        let content = handler.read_file(test_file.to_str().unwrap()).await.unwrap();

        assert!(content.exists);
        assert_eq!(content.content, b"Hello, World!");
    }

    #[test]
    fn test_disabled_rule() {
        let rules = vec![MapLocalRule {
            name: "disabled".to_string(),
            enabled: false,
            pattern: r".*".to_string(),
            local_path: "/tmp/test".to_string(),
            mime_type: None,
        }];

        let handler = MapLocalHandler::new(rules).unwrap();
        let result = handler.match_url("https://any.url.com/path");

        assert!(result.is_none());
    }
}
