use super::{CompiledRule, RuleError};
use crate::config::MapRemoteRule;
use regex::Regex;
use std::sync::Arc;
use tracing::debug;
use url::Url;

/// Handler for Map Remote rules
pub struct MapRemoteHandler {
    rules: Vec<CompiledRule<MapRemoteRule>>,
}

impl MapRemoteHandler {
    pub fn new(rules: Vec<MapRemoteRule>) -> Result<Self, RuleError> {
        let compiled: Result<Vec<CompiledRule<MapRemoteRule>>, RuleError> = rules
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

    /// Check if a URL matches any map remote rule and return the target URL
    pub fn match_url(&self, url: &str) -> Option<MapRemoteMatch> {
        for compiled in &self.rules {
            if compiled.pattern.is_match(url) {
                debug!("Map Remote rule '{}' matched: {}", compiled.rule.name, url);

                let target_url = self.build_target_url(
                    url,
                    &compiled.rule.target,
                    &compiled.pattern,
                    compiled.rule.preserve_path,
                    compiled.rule.preserve_query,
                );

                if let Ok(target) = target_url {
                    return Some(MapRemoteMatch {
                        rule_name: compiled.rule.name.clone(),
                        original_url: url.to_string(),
                        target_url: target,
                    });
                }
            }
        }
        None
    }

    /// Build the target URL based on rule configuration
    fn build_target_url(
        &self,
        original_url: &str,
        target: &str,
        pattern: &Regex,
        preserve_path: bool,
        preserve_query: bool,
    ) -> Result<String, RuleError> {
        // If target contains capture groups, use regex replacement
        if target.contains('$') {
            let replaced = pattern.replace(original_url, target);
            return Ok(replaced.to_string());
        }

        let original = Url::parse(original_url)?;
        let mut target = Url::parse(target)?;

        if preserve_path {
            target.set_path(original.path());
        }

        if preserve_query {
            target.set_query(original.query());
        }

        Ok(target.to_string())
    }

    /// Get all rules
    pub fn rules(&self) -> Vec<&MapRemoteRule> {
        self.rules.iter().map(|r| &r.rule).collect()
    }

    /// Check if there are any active rules
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Result of a map remote match
#[derive(Debug, Clone)]
pub struct MapRemoteMatch {
    pub rule_name: String,
    pub original_url: String,
    pub target_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_match() {
        let rules = vec![MapRemoteRule {
            name: "test".to_string(),
            enabled: true,
            pattern: r"https://api\.example\.com/.*".to_string(),
            target: "https://staging.example.com".to_string(),
            preserve_path: true,
            preserve_query: true,
        }];

        let handler = MapRemoteHandler::new(rules).unwrap();
        let result = handler.match_url("https://api.example.com/users?id=1");

        assert!(result.is_some());
        let matched = result.unwrap();
        assert_eq!(matched.rule_name, "test");
        assert!(matched.target_url.contains("staging.example.com"));
        assert!(matched.target_url.contains("/users"));
    }

    #[test]
    fn test_regex_replacement() {
        let rules = vec![MapRemoteRule {
            name: "version-replace".to_string(),
            enabled: true,
            pattern: r"https://api\.example\.com/v(\d+)/(.*)".to_string(),
            target: "https://api.example.com/v2/$2".to_string(),
            preserve_path: false,
            preserve_query: true,
        }];

        let handler = MapRemoteHandler::new(rules).unwrap();
        let result = handler.match_url("https://api.example.com/v1/users");

        assert!(result.is_some());
        let matched = result.unwrap();
        assert!(matched.target_url.contains("/v2/users"));
    }

    #[test]
    fn test_disabled_rule() {
        let rules = vec![MapRemoteRule {
            name: "disabled".to_string(),
            enabled: false,
            pattern: r".*".to_string(),
            target: "https://example.com".to_string(),
            preserve_path: true,
            preserve_query: true,
        }];

        let handler = MapRemoteHandler::new(rules).unwrap();
        let result = handler.match_url("https://any.url.com/path");

        assert!(result.is_none());
    }
}
