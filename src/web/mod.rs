mod api;
mod websocket;

use crate::proxy::ProxyState;
use axum::{
    http::header,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

#[derive(Error, Debug)]
pub enum WebError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Server error: {0}")]
    ServerError(String),
}

/// Web UI server
pub struct WebServer {
    state: Arc<ProxyState>,
}

impl WebServer {
    pub fn new(state: Arc<ProxyState>) -> Self {
        Self { state }
    }

    /// Start the web server
    pub async fn run(&self, host: &str, port: u16, cancel_token: CancellationToken) -> Result<(), WebError> {
        let addr: SocketAddr = format!("{}:{}", host, port)
            .parse()
            .map_err(|e| WebError::ServerError(format!("Invalid address: {}", e)))?;

        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        let app = Router::new()
            // UI routes
            .route("/", get(serve_index))
            .route("/index.html", get(serve_index))
            .route("/static/app.js", get(serve_js))
            .route("/static/style.css", get(serve_css))
            // API routes
            .route("/api/traffic", get(api::list_traffic))
            .route("/api/traffic/:id", get(api::get_traffic))
            .route("/api/traffic/clear", post(api::clear_traffic))
            .route("/api/traffic/search", get(api::search_traffic))
            .route("/api/config", get(api::get_config))
            .route("/api/config", post(api::update_config))
            .route("/api/rules/map-remote", get(api::get_map_remote_rules))
            .route("/api/rules/map-remote", post(api::add_map_remote_rule))
            .route("/api/rules/map-local", get(api::get_map_local_rules))
            .route("/api/rules/map-local", post(api::add_map_local_rule))
            .route("/api/rules/header", get(api::get_header_rules))
            .route("/api/rules/header", post(api::add_header_rule))
            .route("/api/rules/reload", post(api::reload_rules))
            .route("/api/ca/cert", get(api::get_ca_cert))
            .route("/api/stats", get(api::get_stats))
            // SSE endpoint for real-time traffic events
            .route("/api/events", get(api::traffic_events))
            // WebSocket for real-time traffic (legacy, prefer /api/events)
            .route("/ws/traffic", get(websocket::traffic_ws))
            .layer(cors)
            .with_state(Arc::clone(&self.state));

        let listener = TcpListener::bind(addr).await?;
        info!("Web UI listening on http://{}", addr);

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                cancel_token.cancelled().await;
                info!("Web UI shutting down...");
            })
            .await
            .map_err(|e| WebError::ServerError(e.to_string()))?;

        info!("Web UI stopped");
        Ok(())
    }
}

/// Serve index.html
async fn serve_index() -> impl IntoResponse {
    Html(include_str!("../../static/index.html"))
}

/// Serve app.js
async fn serve_js() -> impl IntoResponse {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/javascript")
        .body(include_str!("../../static/app.js").to_string())
        .unwrap()
}

/// Serve style.css
async fn serve_css() -> impl IntoResponse {
    Response::builder()
        .header(header::CONTENT_TYPE, "text/css")
        .body(include_str!("../../static/style.css").to_string())
        .unwrap()
}
