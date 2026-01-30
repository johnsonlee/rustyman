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
            is_websocket: false,
            websocket_messages: None,
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

    /// Create a new traffic entry for a WebSocket connection
    pub fn create_websocket_entry(&self, request: RequestInfo) -> String {
        let id = Uuid::new_v4().to_string();
        let order = self.counter.fetch_add(1, Ordering::SeqCst);

        let entry = TrafficEntry {
            id: id.clone(),
            order,
            request,
            response: None,
            timing: TimingInfo::new(),
            tags: vec!["websocket".to_string()],
            matched_rules: Vec::new(),
            is_websocket: true,
            websocket_messages: Some(Vec::new()),
        };

        self.entries.insert(id.clone(), entry.clone());
        self.entry_order.insert(order, id.clone());

        self.cleanup_old_entries();

        let _ = self.tx.send(TrafficEvent::NewRequest(entry));

        id
    }

    /// Record a WebSocket message on an existing entry
    pub fn record_websocket_message(
        &self,
        id: &str,
        message: WebSocketMessageInfo,
        max_messages: usize,
    ) {
        let should_broadcast = if let Some(mut entry) = self.entries.get_mut(id) {
            let messages = entry.websocket_messages.get_or_insert_with(Vec::new);
            if messages.len() < max_messages {
                messages.push(message.clone());
                true
            } else {
                false
            }
        } else {
            false
        };

        if should_broadcast {
            let _ = self.tx.send(TrafficEvent::WebSocketMessage {
                entry_id: id.to_string(),
                message,
            });
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
    /// Whether this entry is a WebSocket connection
    #[serde(default)]
    pub is_websocket: bool,
    /// WebSocket messages exchanged on this connection
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub websocket_messages: Option<Vec<WebSocketMessageInfo>>,
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

/// WebSocket message direction
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketDirection {
    ClientToServer,
    ServerToClient,
}

/// WebSocket message type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketMessageType {
    Text,
    Binary,
    Ping,
    Pong,
    Close,
}

/// WebSocket message information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketMessageInfo {
    /// When the message was observed
    pub timestamp: DateTime<Utc>,
    /// Direction of the message
    pub direction: WebSocketDirection,
    /// Type of WebSocket message
    pub message_type: WebSocketMessageType,
    /// Payload content (text as UTF-8, binary as base64)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// Payload size in bytes
    pub payload_size: usize,
}

/// Traffic events for real-time updates
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", content = "data")]
pub enum TrafficEvent {
    #[serde(rename = "request")]
    NewRequest(TrafficEntry),
    #[serde(rename = "response")]
    ResponseReceived(TrafficEntry),
    #[serde(rename = "completed")]
    Completed(TrafficEntry),
    #[serde(rename = "cleared")]
    Cleared,
    #[serde(rename = "websocket_message")]
    WebSocketMessage {
        entry_id: String,
        message: WebSocketMessageInfo,
    },
}

impl TrafficEvent {
    /// Convert the event to a JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Convert the event to a pretty-printed JSON string
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Get the event type as a string
    pub fn event_type(&self) -> &'static str {
        match self {
            TrafficEvent::NewRequest(_) => "request",
            TrafficEvent::ResponseReceived(_) => "response",
            TrafficEvent::Completed(_) => "completed",
            TrafficEvent::Cleared => "cleared",
            TrafficEvent::WebSocketMessage { .. } => "websocket_message",
        }
    }

    /// Get the traffic entry if this event contains one
    pub fn entry(&self) -> Option<&TrafficEntry> {
        match self {
            TrafficEvent::NewRequest(e) => Some(e),
            TrafficEvent::ResponseReceived(e) => Some(e),
            TrafficEvent::Completed(e) => Some(e),
            TrafficEvent::Cleared => None,
            TrafficEvent::WebSocketMessage { .. } => None,
        }
    }
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

    #[test]
    fn test_websocket_entry() {
        let store = TrafficStore::new(100);

        let request = RequestInfo {
            method: "GET".to_string(),
            url: "ws://example.com/ws".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: HashMap::new(),
            body: None,
            body_size: 0,
            client_addr: "127.0.0.1:12345".to_string(),
            host: "example.com".to_string(),
            path: "/ws".to_string(),
        };

        let id = store.create_websocket_entry(request);
        let entry = store.get(&id).unwrap();
        assert!(entry.is_websocket);
        assert_eq!(entry.tags, vec!["websocket"]);
        assert!(entry.websocket_messages.is_some());
        assert_eq!(entry.websocket_messages.unwrap().len(), 0);
    }

    #[test]
    fn test_websocket_message_recording() {
        let store = TrafficStore::new(100);

        let request = RequestInfo {
            method: "GET".to_string(),
            url: "ws://example.com/ws".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: HashMap::new(),
            body: None,
            body_size: 0,
            client_addr: "127.0.0.1:12345".to_string(),
            host: "example.com".to_string(),
            path: "/ws".to_string(),
        };

        let id = store.create_websocket_entry(request);

        let msg = WebSocketMessageInfo {
            timestamp: Utc::now(),
            direction: WebSocketDirection::ClientToServer,
            message_type: WebSocketMessageType::Text,
            payload: Some("hello".to_string()),
            payload_size: 5,
        };

        store.record_websocket_message(&id, msg, 1000);

        let entry = store.get(&id).unwrap();
        let messages = entry.websocket_messages.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].payload.as_deref(), Some("hello"));
        assert_eq!(messages[0].payload_size, 5);
    }

    #[test]
    fn test_websocket_message_max_cap() {
        let store = TrafficStore::new(100);

        let request = RequestInfo {
            method: "GET".to_string(),
            url: "ws://example.com/ws".to_string(),
            http_version: "HTTP/1.1".to_string(),
            headers: HashMap::new(),
            body: None,
            body_size: 0,
            client_addr: "127.0.0.1:12345".to_string(),
            host: "example.com".to_string(),
            path: "/ws".to_string(),
        };

        let id = store.create_websocket_entry(request);

        for i in 0..10 {
            let msg = WebSocketMessageInfo {
                timestamp: Utc::now(),
                direction: WebSocketDirection::ClientToServer,
                message_type: WebSocketMessageType::Text,
                payload: Some(format!("msg{}", i)),
                payload_size: 4,
            };
            store.record_websocket_message(&id, msg, 5);
        }

        let entry = store.get(&id).unwrap();
        assert_eq!(entry.websocket_messages.unwrap().len(), 5);
    }
}
