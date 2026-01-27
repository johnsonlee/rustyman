use crate::config::{HeaderRule, MapLocalRule, MapRemoteRule};
use crate::proxy::ProxyState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{sse::{Event, KeepAlive, Sse}, IntoResponse},
    Json,
};
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use async_stream::stream;

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    50
}

#[derive(Debug, Deserialize)]
pub struct SearchParams {
    q: String,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    fn success(data: T) -> Json<Self> {
        Json(Self {
            success: true,
            data: Some(data),
            error: None,
        })
    }
}

fn api_ok() -> (StatusCode, Json<ApiResponse<()>>) {
    (
        StatusCode::OK,
        Json(ApiResponse {
            success: true,
            data: None,
            error: None,
        }),
    )
}

fn api_error(msg: &str) -> (StatusCode, Json<ApiResponse<()>>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiResponse {
            success: false,
            data: None,
            error: Some(msg.to_string()),
        }),
    )
}

/// List traffic entries
pub async fn list_traffic(
    State(state): State<Arc<ProxyState>>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let entries = state.traffic.list(params.offset, params.limit);
    ApiResponse::success(entries)
}

/// Get single traffic entry
pub async fn get_traffic(
    State(state): State<Arc<ProxyState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.traffic.get(&id) {
        Some(entry) => (StatusCode::OK, Json(ApiResponse {
            success: true,
            data: Some(entry),
            error: None,
        })),
        None => (StatusCode::NOT_FOUND, Json(ApiResponse {
            success: false,
            data: None,
            error: Some("Traffic entry not found".to_string()),
        })),
    }
}

/// Clear all traffic
pub async fn clear_traffic(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    state.traffic.clear();
    api_ok()
}

/// Search traffic
pub async fn search_traffic(
    State(state): State<Arc<ProxyState>>,
    Query(params): Query<SearchParams>,
) -> impl IntoResponse {
    let entries = state.traffic.search(&params.q);
    ApiResponse::success(entries)
}

/// Get current config
pub async fn get_config(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    let config = state.config.read().await;
    ApiResponse::success(config.clone())
}

/// Update config
pub async fn update_config(
    State(state): State<Arc<ProxyState>>,
    Json(new_config): Json<crate::config::Config>,
) -> impl IntoResponse {
    let mut config = state.config.write().await;
    *config = new_config;

    // Reload rules
    drop(config);
    if let Err(e) = state.reload_rules().await {
        return api_error(&e.to_string());
    }

    api_ok()
}

/// Get map remote rules
pub async fn get_map_remote_rules(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    let config = state.config.read().await;
    ApiResponse::success(config.map_remote.clone())
}

/// Add map remote rule
pub async fn add_map_remote_rule(
    State(state): State<Arc<ProxyState>>,
    Json(rule): Json<MapRemoteRule>,
) -> impl IntoResponse {
    let mut config = state.config.write().await;
    config.map_remote.push(rule);

    drop(config);
    if let Err(e) = state.reload_rules().await {
        return api_error(&e.to_string());
    }

    api_ok()
}

/// Get map local rules
pub async fn get_map_local_rules(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    let config = state.config.read().await;
    ApiResponse::success(config.map_local.clone())
}

/// Add map local rule
pub async fn add_map_local_rule(
    State(state): State<Arc<ProxyState>>,
    Json(rule): Json<MapLocalRule>,
) -> impl IntoResponse {
    let mut config = state.config.write().await;
    config.map_local.push(rule);

    drop(config);
    if let Err(e) = state.reload_rules().await {
        return api_error(&e.to_string());
    }

    api_ok()
}

/// Get header rules
pub async fn get_header_rules(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    let config = state.config.read().await;
    ApiResponse::success(config.header_rules.clone())
}

/// Add header rule
pub async fn add_header_rule(
    State(state): State<Arc<ProxyState>>,
    Json(rule): Json<HeaderRule>,
) -> impl IntoResponse {
    let mut config = state.config.write().await;
    config.header_rules.push(rule);

    drop(config);
    if let Err(e) = state.reload_rules().await {
        return api_error(&e.to_string());
    }

    api_ok()
}

/// Reload rules from config
pub async fn reload_rules(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    if let Err(e) = state.reload_rules().await {
        return api_error(&e.to_string());
    }

    api_ok()
}

/// Get CA certificate (for download)
pub async fn get_ca_cert(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    let pem = state.ca.ca_cert_pem();

    (
        StatusCode::OK,
        [
            ("content-type", "application/x-pem-file"),
            ("content-disposition", "attachment; filename=\"rustyman-ca.crt\""),
        ],
        pem,
    )
}

/// Get proxy stats
pub async fn get_stats(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    #[derive(Serialize)]
    struct Stats {
        traffic_count: usize,
        cert_cache_size: usize,
        map_remote_rules: usize,
        map_local_rules: usize,
        header_rules: usize,
    }

    let config = state.config.read().await;
    let cache_size = state.ca.cache_size().await;

    let stats = Stats {
        traffic_count: state.traffic.count(),
        cert_cache_size: cache_size,
        map_remote_rules: config.map_remote.len(),
        map_local_rules: config.map_local.len(),
        header_rules: config.header_rules.len(),
    };

    ApiResponse::success(stats)
}

/// SSE endpoint for real-time traffic events
///
/// This endpoint streams traffic events as Server-Sent Events (SSE).
/// Each event is a JSON object with the following structure:
/// ```json
/// {"event":"request","data":{...}}
/// {"event":"response","data":{...}}
/// {"event":"completed","data":{...}}
/// {"event":"cleared"}
/// ```
///
/// Usage:
/// - Browser: `new EventSource('/api/events')`
/// - curl: `curl -N http://localhost:8081/api/events`
/// - Any HTTP client that supports streaming
pub async fn traffic_events(
    State(state): State<Arc<ProxyState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.traffic.subscribe();

    let stream = stream! {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if let Ok(json) = event.to_json() {
                        let event_type = event.event_type();
                        yield Ok(Event::default()
                            .event(event_type)
                            .data(json));
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    // Skip lagged messages, continue receiving
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    // Channel closed, exit the loop
                    break;
                }
            }
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(30))
            .text("keepalive")
    )
}
