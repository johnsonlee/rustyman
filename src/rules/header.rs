use super::RuleError;
use crate::config::{HeaderAction, HeaderOperation, HeaderRule};
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

/// Handler for header rewrite rules
pub struct HeaderRewriter {
    rules: Vec<CompiledHeaderRule>,
}

struct CompiledHeaderRule {
    rule: HeaderRule,
    url_pattern: Arc<Regex>,
    operations: Vec<CompiledOperation>,
}

struct CompiledOperation {
    operation: HeaderOperation,
    name_regex: Option<Arc<Regex>>,
    value_regex: Option<Arc<Regex>>,
}

impl HeaderRewriter {
    pub fn new(rules: Vec<HeaderRule>) -> Result<Self, RuleError> {
        let compiled: Result<Vec<CompiledHeaderRule>, RuleError> = rules
            .into_iter()
            .filter(|r| r.enabled)
            .map(|rule| {
                let url_pattern = Regex::new(&rule.url_pattern)?;

                let operations: Result<Vec<CompiledOperation>, RuleError> = rule
                    .operations
                    .iter()
                    .map(|op| {
                        // For remove action with wildcard support, compile name as regex
                        let name_regex = if op.action == HeaderAction::Remove
                            && (op.name.contains('*') || op.name.contains('?'))
                        {
                            let pattern = op.name.replace('*', ".*").replace('?', ".");
                            Some(Arc::new(Regex::new(&format!("^{}$", pattern))?))
                        } else if op.action == HeaderAction::Modify {
                            // For modify, name might be a pattern
                            Regex::new(&op.name).ok().map(Arc::new)
                        } else {
                            None
                        };

                        let value_regex = op
                            .value_pattern
                            .as_ref()
                            .map(|p| Regex::new(p))
                            .transpose()?
                            .map(Arc::new);

                        Ok(CompiledOperation {
                            operation: op.clone(),
                            name_regex,
                            value_regex,
                        })
                    })
                    .collect();

                Ok(CompiledHeaderRule {
                    url_pattern: Arc::new(url_pattern),
                    operations: operations?,
                    rule,
                })
            })
            .collect();

        Ok(Self { rules: compiled? })
    }

    /// Rewrite request headers
    pub fn rewrite_request_headers(
        &self,
        url: &str,
        headers: &mut HashMap<String, String>,
    ) -> Vec<String> {
        let mut applied_rules = Vec::new();

        for compiled in &self.rules {
            if !compiled.rule.apply_to_request {
                continue;
            }

            if compiled.url_pattern.is_match(url) {
                debug!(
                    "Header rule '{}' matched request: {}",
                    compiled.rule.name, url
                );
                self.apply_operations(&compiled.operations, headers);
                applied_rules.push(compiled.rule.name.clone());
            }
        }

        applied_rules
    }

    /// Rewrite response headers
    pub fn rewrite_response_headers(
        &self,
        url: &str,
        headers: &mut HashMap<String, String>,
    ) -> Vec<String> {
        let mut applied_rules = Vec::new();

        for compiled in &self.rules {
            if !compiled.rule.apply_to_response {
                continue;
            }

            if compiled.url_pattern.is_match(url) {
                debug!(
                    "Header rule '{}' matched response: {}",
                    compiled.rule.name, url
                );
                self.apply_operations(&compiled.operations, headers);
                applied_rules.push(compiled.rule.name.clone());
            }
        }

        applied_rules
    }

    /// Apply header operations
    fn apply_operations(
        &self,
        operations: &[CompiledOperation],
        headers: &mut HashMap<String, String>,
    ) {
        for compiled_op in operations {
            let op = &compiled_op.operation;

            match op.action {
                HeaderAction::Add => {
                    if let Some(ref value) = op.value {
                        debug!("Adding header: {} = {}", op.name, value);
                        headers.insert(op.name.clone(), value.clone());
                    }
                }
                HeaderAction::Remove => {
                    if let Some(ref name_regex) = compiled_op.name_regex {
                        // Remove headers matching the pattern
                        let keys_to_remove: Vec<_> = headers
                            .keys()
                            .filter(|k| name_regex.is_match(k))
                            .cloned()
                            .collect();

                        for key in keys_to_remove {
                            debug!("Removing header: {}", key);
                            headers.remove(&key);
                        }
                    } else {
                        debug!("Removing header: {}", op.name);
                        headers.remove(&op.name);
                    }
                }
                HeaderAction::Modify => {
                    if let Some(ref value_regex) = compiled_op.value_regex {
                        if let Some(ref replacement) = op.replacement {
                            // Find matching headers
                            let matching_keys: Vec<_> = if let Some(ref name_regex) =
                                compiled_op.name_regex
                            {
                                headers
                                    .keys()
                                    .filter(|k| name_regex.is_match(k))
                                    .cloned()
                                    .collect()
                            } else {
                                headers
                                    .keys()
                                    .filter(|k| *k == &op.name)
                                    .cloned()
                                    .collect()
                            };

                            for key in matching_keys {
                                if let Some(value) = headers.get_mut(&key) {
                                    let new_value = value_regex.replace_all(value, replacement);
                                    debug!(
                                        "Modifying header: {} = {} -> {}",
                                        key, value, new_value
                                    );
                                    *value = new_value.to_string();
                                }
                            }
                        }
                    } else if let Some(ref new_value) = op.value {
                        // Simple value replacement
                        if headers.contains_key(&op.name) {
                            debug!("Modifying header: {} = {}", op.name, new_value);
                            headers.insert(op.name.clone(), new_value.clone());
                        }
                    }
                }
            }
        }
    }

    /// Get all rules
    pub fn rules(&self) -> Vec<&HeaderRule> {
        self.rules.iter().map(|r| &r.rule).collect()
    }

    /// Check if there are any active rules
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_rule(
        name: &str,
        url_pattern: &str,
        operations: Vec<HeaderOperation>,
    ) -> HeaderRule {
        HeaderRule {
            name: name.to_string(),
            enabled: true,
            url_pattern: url_pattern.to_string(),
            apply_to_request: true,
            apply_to_response: true,
            operations,
        }
    }

    #[test]
    fn test_add_header() {
        let rules = vec![create_test_rule(
            "add-auth",
            r".*",
            vec![HeaderOperation {
                action: HeaderAction::Add,
                name: "Authorization".to_string(),
                value: Some("Bearer token123".to_string()),
                value_pattern: None,
                replacement: None,
            }],
        )];

        let rewriter = HeaderRewriter::new(rules).unwrap();
        let mut headers = HashMap::new();

        rewriter.rewrite_request_headers("https://api.example.com/test", &mut headers);

        assert_eq!(headers.get("Authorization"), Some(&"Bearer token123".to_string()));
    }

    #[test]
    fn test_remove_header() {
        let rules = vec![create_test_rule(
            "remove-cookie",
            r".*",
            vec![HeaderOperation {
                action: HeaderAction::Remove,
                name: "Cookie".to_string(),
                value: None,
                value_pattern: None,
                replacement: None,
            }],
        )];

        let rewriter = HeaderRewriter::new(rules).unwrap();
        let mut headers = HashMap::from([("Cookie".to_string(), "session=abc".to_string())]);

        rewriter.rewrite_request_headers("https://api.example.com/test", &mut headers);

        assert!(!headers.contains_key("Cookie"));
    }

    #[test]
    fn test_remove_header_pattern() {
        let rules = vec![create_test_rule(
            "remove-x-headers",
            r".*",
            vec![HeaderOperation {
                action: HeaderAction::Remove,
                name: "X-*".to_string(),
                value: None,
                value_pattern: None,
                replacement: None,
            }],
        )];

        let rewriter = HeaderRewriter::new(rules).unwrap();
        let mut headers = HashMap::from([
            ("X-Custom-Header".to_string(), "value1".to_string()),
            ("X-Another-Header".to_string(), "value2".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ]);

        rewriter.rewrite_request_headers("https://api.example.com/test", &mut headers);

        assert!(!headers.contains_key("X-Custom-Header"));
        assert!(!headers.contains_key("X-Another-Header"));
        assert!(headers.contains_key("Content-Type"));
    }

    #[test]
    fn test_modify_header_regex() {
        let rules = vec![create_test_rule(
            "modify-ua",
            r".*",
            vec![HeaderOperation {
                action: HeaderAction::Modify,
                name: "User-Agent".to_string(),
                value: None,
                value_pattern: Some(r"Chrome/\d+".to_string()),
                replacement: Some("Chrome/999".to_string()),
            }],
        )];

        let rewriter = HeaderRewriter::new(rules).unwrap();
        let mut headers = HashMap::from([
            ("User-Agent".to_string(), "Mozilla/5.0 Chrome/120 Safari".to_string()),
        ]);

        rewriter.rewrite_request_headers("https://api.example.com/test", &mut headers);

        assert!(headers.get("User-Agent").unwrap().contains("Chrome/999"));
    }

    #[test]
    fn test_url_pattern_match() {
        let rules = vec![create_test_rule(
            "api-only",
            r"https://api\.example\.com/.*",
            vec![HeaderOperation {
                action: HeaderAction::Add,
                name: "X-API-Version".to_string(),
                value: Some("v2".to_string()),
                value_pattern: None,
                replacement: None,
            }],
        )];

        let rewriter = HeaderRewriter::new(rules).unwrap();

        let mut headers1 = HashMap::new();
        rewriter.rewrite_request_headers("https://api.example.com/users", &mut headers1);
        assert!(headers1.contains_key("X-API-Version"));

        let mut headers2 = HashMap::new();
        rewriter.rewrite_request_headers("https://www.example.com/page", &mut headers2);
        assert!(!headers2.contains_key("X-API-Version"));
    }
}
