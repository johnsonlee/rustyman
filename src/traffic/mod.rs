use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::broadcast;
use uuid::Uuid;

/// Traffic storage and event broadcasting
pub struct TrafficStore {
    /// All recorded traffic entries
    entries: DashMap<String, TrafficEntry>,
    /// Entry order for pagination
    entry_order: DashMap<u64, String>,
    /// Counter for ordering
    counter: AtomicU64,
    /// Broadcast channel for real-time updates
    tx: broadcast::Sender<TrafficEvent>,
    /// Maximum entries to store
    max_entries: usize,
}

impl TrafficStore {
    pub fn new(max_entries: usize) -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self {
            entries: DashMap::new(),
            entry_order: DashMap::new(),
            counter: AtomicU64::new(0),
            tx,
            max_entries,
        }
    }

    /// Create a new traffic entry for a request
    pub fn create_entry(&self, request: RequestInfo) -> String {
        let id = Uuid::new_v4().to_string();
        let order = self.counter.fetch_add(1, Ordering::SeqCst);

        let entry = TrafficEntry {
            id: id.clone(),
            order,
            request,
            response: None,
            timing: TimingInfo::new(),
            tags: Vec::new(),
            matched_rules: Vec::new(),
        };

        self.entries.insert(id.clone(), entry.clone());
        self.entry_order.insert(order, id.clone());

        // Clean up old entries if needed
        self.cleanup_old_entries();

        // Broadcast event
        let _ = self.tx.send(TrafficEvent::NewRequest(entry));

        id
    }

    /// Update entry with response
    pub fn set_response(&self, id: &str, response: ResponseInfo) {
        if let Some(mut entry) = self.entries.get_mut(id) {
            entry.response = Some(response);
            entry.timing.response_received = Some(Utc::now());
            let _ = self.tx.send(TrafficEvent::ResponseReceived(entry.clone()));
        }
    }

    /// Update entry timing when complete
    pub fn mark_complete(&self, id: &str) {
        if let Some(mut entry) = self.entries.get_mut(id) {
            entry.timing.completed = Some(Utc::now());
            let _ = self.tx.send(TrafficEvent::Completed(entry.clone()));
        }
    }

    /// Add matched rule info
    pub fn add_matched_rule(&self, id: &str, rule_type: &str, rule_name: &str) {
        if let Some(mut entry) = self.entries.get_mut(id) {
            entry.matched_rules.push(MatchedRule {
                rule_type: rule_type.to_string(),
                rule_name: rule_name.to_string(),
            });
        }
    }

    /// Add tag to entry
    pub fn add_tag(&self, id: &str, tag: &str) {
        if let Some(mut entry) = self.entries.get_mut(id) {
            entry.tags.push(tag.to_string());
        }
    }

    /// Get entry by ID
    pub fn get(&self, id: &str) -> Option<TrafficEntry> {
        self.entries.get(id).map(|e| e.clone())
    }

    /// Get all entries (paginated)
    pub fn list(&self, offset: usize, limit: usize) -> Vec<TrafficEntry> {
        let current = self.counter.load(Ordering::SeqCst);
        let start = if current > offset as u64 {
            current - offset as u64
        } else {
            0
        };

        let mut entries = Vec::new();
        let mut count = 0;
        let mut order = start;

        while count < limit && order > 0 {
            order -= 1;
            if let Some(id) = self.entry_order.get(&order) {
                if let Some(entry) = self.entries.get(id.value()) {
                    entries.push(entry.clone());
                    count += 1;
                }
            }
        }

        entries
    }

    /// Get entries count
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Clear all entries
    pub fn clear(&self) {
        self.entries.clear();
        self.entry_order.clear();
        let _ = self.tx.send(TrafficEvent::Cleared);
    }

    /// Subscribe to traffic events
    pub fn subscribe(&self) -> broadcast::Receiver<TrafficEvent> {
        self.tx.subscribe()
    }

    /// Cleanup old entries
    fn cleanup_old_entries(&self) {
        while self.entries.len() > self.max_entries {
            let current = self.counter.load(Ordering::SeqCst);
            let oldest = current.saturating_sub(self.max_entries as u64);

            if let Some((_, id)) = self.entry_order.remove(&oldest) {
                self.entries.remove(&id);
            }
        }
    }

    /// Search entries by URL pattern
    pub fn search(&self, pattern: &str) -> Vec<TrafficEntry> {
        let regex = regex::Regex::new(pattern).ok();

        self.entries
            .iter()
            .filter(|entry| {
                if let Some(ref re) = regex {
                    re.is_match(&entry.request.url)
                } else {
                    entry.request.url.contains(pattern)
                }
            })
            .map(|entry| entry.clone())
            .collect()
    }
}

impl Default for TrafficStore {
    fn default() -> Self {
        Self::new(10000)
    }
}

/// A single traffic entry (request/response pair)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEntry {
    /// Unique identifier
    pub id: String,
    /// Order for sorting
    pub order: u64,
    /// Request information
    pub request: RequestInfo,
    /// Response information (None if pending)
    pub response: Option<ResponseInfo>,
    /// Timing information
    pub timing: TimingInfo,
    /// Tags for filtering
    pub tags: Vec<String>,
    /// Rules that matched this request
    pub matched_rules: Vec<MatchedRule>,
}

/// HTTP request information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestInfo {
    /// HTTP method
    pub method: String,
    /// Full URL
    pub url: String,
    /// HTTP version
    pub http_version: String,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Request body (if captured)
    pub body: Option<Vec<u8>>,
    /// Body size in bytes
    pub body_size: usize,
    /// Client address
    pub client_addr: String,
    /// Host header
    pub host: String,
    /// Path
    pub path: String,
}

/// HTTP response information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseInfo {
    /// HTTP status code
    pub status: u16,
    /// Status reason phrase
    pub reason: String,
    /// HTTP version
    pub http_version: String,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body (if captured)
    pub body: Option<Vec<u8>>,
    /// Body size in bytes
    pub body_size: usize,
    /// Whether response was served from map local/remote
    pub modified: bool,
    /// Modification source if modified
    pub modification_source: Option<String>,
}

/// Timing information for a request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingInfo {
    /// When the request was received
    pub request_received: DateTime<Utc>,
    /// When the response started
    pub response_received: Option<DateTime<Utc>>,
    /// When the transfer completed
    pub completed: Option<DateTime<Utc>>,
}

impl TimingInfo {
    pub fn new() -> Self {
        Self {
            request_received: Utc::now(),
            response_received: None,
            completed: None,
        }
    }

    /// Get request duration in milliseconds
    pub fn duration_ms(&self) -> Option<i64> {
        self.completed.map(|c| {
            (c - self.request_received).num_milliseconds()
        })
    }
}

impl Default for TimingInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a matched rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRule {
    pub rule_type: String,
    pub rule_name: String,
}

/// Traffic events for real-time updates
#[derive(Debug, Clone)]
pub enum TrafficEvent {
    NewRequest(TrafficEntry),
    ResponseReceived(TrafficEntry),
    Completed(TrafficEntry),
    Cleared,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_store() {
        let store = TrafficStore::new(100);

        let request = RequestInfo {
            method: "GET".to_string(),
            url: "https://example.com/test".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: HashMap::new(),
            body: None,
            body_size: 0,
            client_addr: "127.0.0.1:12345".to_string(),
            host: "example.com".to_string(),
            path: "/test".to_string(),
        };

        let id = store.create_entry(request);
        assert!(store.get(&id).is_some());
        assert_eq!(store.count(), 1);
    }
}
