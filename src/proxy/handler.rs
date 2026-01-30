use super::tls::TlsAcceptor;
use super::{ProxyError, ProxyState};
use crate::traffic::{
    RequestInfo, ResponseInfo, WebSocketDirection, WebSocketMessageInfo, WebSocketMessageType,
};
use base64::Engine;
use bytes::Bytes;
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::Builder as ClientBuilder;
use hyper::client::conn::http2::Builder as Http2ClientBuilder;
use hyper::server::conn::http1::Builder as ServerBuilder;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, error, info, warn};

/// Handles a single proxy connection
pub struct ProxyHandler {
    state: Arc<ProxyState>,
    client_addr: SocketAddr,
}

impl ProxyHandler {
    pub fn new(state: Arc<ProxyState>, client_addr: SocketAddr) -> Self {
        Self { state, client_addr }
    }

    /// Handle incoming TCP connection
    pub async fn handle(self, stream: TcpStream) -> Result<(), ProxyError> {
        let io = TokioIo::new(stream);

        let state = Arc::clone(&self.state);
        let client_addr = self.client_addr;

        ServerBuilder::new()
            .preserve_header_case(true)
            .serve_connection(
                io,
                service_fn(move |req| {
                    let state = Arc::clone(&state);
                    let client_addr = client_addr;
                    async move { Self::handle_request(state, client_addr, req).await }
                }),
            )
            .with_upgrades()
            .await
            .map_err(|e| ProxyError::HttpError(e.to_string()))?;

        Ok(())
    }

    /// Handle HTTP request
    async fn handle_request(
        state: Arc<ProxyState>,
        client_addr: SocketAddr,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let method = req.method().clone();
        let uri = req.uri().clone();

        debug!("{} {} from {}", method, uri, client_addr);

        // Handle CONNECT method for HTTPS
        if method == Method::CONNECT {
            return Self::handle_connect(state, client_addr, req).await;
        }

        // Handle regular HTTP request
        Self::handle_http_request(state, client_addr, req).await
    }

    /// Handle CONNECT method (HTTPS tunnel)
    async fn handle_connect(
        state: Arc<ProxyState>,
        client_addr: SocketAddr,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let host = req.uri().host().unwrap_or("").to_string();
        let port = req.uri().port_u16().unwrap_or(443);

        info!("CONNECT {}:{} from {}", host, port, client_addr);

        // Get MITM enabled setting
        let mitm_enabled = {
            let config = state.config.read().await;
            config.proxy.mitm_enabled
        };

        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let io = TokioIo::new(upgraded);

                    if mitm_enabled {
                        // MITM mode: intercept TLS
                        if let Err(e) =
                            Self::handle_mitm_tunnel(state, client_addr, io, &host, port).await
                        {
                            error!("MITM tunnel error for {}:{}: {}", host, port, e);
                        }
                    } else {
                        // Pass-through mode: just tunnel the connection
                        if let Err(e) = Self::handle_passthrough_tunnel(io, &host, port).await {
                            error!("Tunnel error for {}:{}: {}", host, port, e);
                        }
                    }
                }
                Err(e) => {
                    error!("Upgrade failed: {}", e);
                }
            }
        });

        // Return 200 Connection Established
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::new()))
            .unwrap())
    }

    /// Handle MITM tunnel - decrypt, inspect, and re-encrypt TLS traffic
    async fn handle_mitm_tunnel<I>(
        state: Arc<ProxyState>,
        client_addr: SocketAddr,
        upgraded: I,
        host: &str,
        port: u16,
    ) -> Result<(), ProxyError>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // Get certificate for this host
        let cert = state.ca.get_cert_for_domain(host).await?;

        // Create TLS acceptor with the generated certificate
        let tls_acceptor = TlsAcceptor::from_certified_key(&cert)?;

        // Accept TLS connection from client
        let tls_stream = tls_acceptor.accept(upgraded).await?;
        let io = TokioIo::new(tls_stream);

        let host = host.to_string();
        let state_clone = Arc::clone(&state);

        // Serve HTTP/1.1 and HTTP/2 over the TLS connection (auto-detected)
        let mut auto_builder = AutoServerBuilder::new(TokioExecutor::new());
        auto_builder.http1().preserve_header_case(true);
        auto_builder
            .serve_connection_with_upgrades(
                io,
                service_fn(move |req| {
                    let state = Arc::clone(&state_clone);
                    let host = host.clone();
                    let client_addr = client_addr;
                    async move {
                        Self::handle_https_request(state, client_addr, req, &host, port).await
                    }
                }),
            )
            .await
            .map_err(|e| ProxyError::HttpError(e.to_string()))?;

        Ok(())
    }

    /// Handle pass-through tunnel (no MITM)
    async fn handle_passthrough_tunnel<I>(
        upgraded: I,
        host: &str,
        port: u16,
    ) -> Result<(), ProxyError>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        let target = format!("{}:{}", host, port);
        let server = TcpStream::connect(&target).await?;

        let (mut client_read, mut client_write) = tokio::io::split(upgraded);
        let (mut server_read, mut server_write) = tokio::io::split(server);

        let client_to_server = async {
            tokio::io::copy(&mut client_read, &mut server_write).await?;
            server_write.shutdown().await
        };

        let server_to_client = async {
            tokio::io::copy(&mut server_read, &mut client_write).await?;
            client_write.shutdown().await
        };

        tokio::try_join!(client_to_server, server_to_client)?;

        Ok(())
    }

    /// Handle HTTPS request after MITM decryption
    async fn handle_https_request(
        state: Arc<ProxyState>,
        client_addr: SocketAddr,
        req: Request<Incoming>,
        host: &str,
        port: u16,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        // Build the full URL
        let uri = req.uri();
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let full_url = if port == 443 {
            format!("https://{}{}", host, path)
        } else {
            format!("https://{}:{}{}", host, port, path)
        };

        debug!("HTTPS {} {} from {}", req.method(), full_url, client_addr);

        // Process the request with rules
        Self::process_request(state, client_addr, req, &full_url, host, port, true).await
    }

    /// Handle regular HTTP request
    async fn handle_http_request(
        state: Arc<ProxyState>,
        client_addr: SocketAddr,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let uri = req.uri().clone();
        let full_url = uri.to_string();

        let host = uri.host().unwrap_or("").to_string();
        let port = uri.port_u16().unwrap_or(80);

        Self::process_request(state, client_addr, req, &full_url, &host, port, false).await
    }

    /// Process request through rules and forward
    async fn process_request(
        state: Arc<ProxyState>,
        client_addr: SocketAddr,
        req: Request<Incoming>,
        full_url: &str,
        host: &str,
        port: u16,
        is_https: bool,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        // Check for WebSocket upgrade before body collection
        if Self::is_websocket_upgrade(&req) {
            return Self::handle_websocket_proxy(
                state,
                client_addr,
                req,
                full_url,
                host,
                port,
                is_https,
            )
            .await;
        }

        let method = req.method().clone();
        let http_version = format!("{:?}", req.version());

        // Collect request headers
        let mut headers: HashMap<String, String> = req
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        // Collect request body
        let (parts, body) = req.into_parts();
        let body_bytes = body.collect().await.map(|b| b.to_bytes()).ok();
        let body_size = body_bytes.as_ref().map(|b| b.len()).unwrap_or(0);

        // Create traffic entry
        let request_info = RequestInfo {
            method: method.to_string(),
            url: full_url.to_string(),
            http_version: http_version.clone(),
            headers: headers.clone(),
            body: body_bytes.as_ref().map(|b| b.to_vec()),
            body_size,
            client_addr: client_addr.to_string(),
            host: host.to_string(),
            path: parts.uri.path().to_string(),
        };

        let entry_id = state.traffic.create_entry(request_info);

        // Check Map Local rules first
        let rules = state.rules.read().await;
        if let Some(map_local_match) = rules.map_local.match_url(full_url) {
            state
                .traffic
                .add_matched_rule(&entry_id, "map_local", &map_local_match.rule_name);

            // Read local file
            match rules.map_local.read_file(&map_local_match.local_path).await {
                Ok(content) if content.exists => {
                    let mime_type = map_local_match
                        .mime_type
                        .or(content.mime_type)
                        .unwrap_or_else(|| "application/octet-stream".to_string());

                    info!(
                        "Map Local: {} -> {} ({})",
                        full_url, map_local_match.local_path, mime_type
                    );

                    let response_info = ResponseInfo {
                        status: 200,
                        reason: "OK".to_string(),
                        http_version: "HTTP/1.1".to_string(),
                        headers: HashMap::from([("content-type".to_string(), mime_type.clone())]),
                        body: Some(content.content.clone()),
                        body_size: content.content.len(),
                        modified: true,
                        modification_source: Some(format!("map_local:{}", map_local_match.rule_name)),
                    };

                    state.traffic.set_response(&entry_id, response_info);
                    state.traffic.mark_complete(&entry_id);

                    return Ok(Response::builder()
                        .status(200)
                        .header("content-type", mime_type)
                        .header("x-rustyman-map-local", &map_local_match.local_path)
                        .body(Full::new(Bytes::from(content.content)))
                        .unwrap());
                }
                Ok(_) => {
                    warn!("Map Local file not found: {}", map_local_match.local_path);
                }
                Err(e) => {
                    error!("Map Local read error: {}", e);
                }
            }
        }

        // Check Map Remote rules
        let target_url;
        let target_host;
        let target_port;
        let target_is_https;

        if let Some(map_remote_match) = rules.map_remote.match_url(full_url) {
            state
                .traffic
                .add_matched_rule(&entry_id, "map_remote", &map_remote_match.rule_name);

            info!(
                "Map Remote: {} -> {}",
                full_url, map_remote_match.target_url
            );

            target_url = map_remote_match.target_url.clone();
            if let Ok(parsed) = target_url.parse::<Uri>() {
                target_host = parsed.host().unwrap_or(host).to_string();
                target_port = parsed.port_u16().unwrap_or(if parsed.scheme_str() == Some("https") {
                    443
                } else {
                    80
                });
                target_is_https = parsed.scheme_str() == Some("https");
            } else {
                target_host = host.to_string();
                target_port = port;
                target_is_https = is_https;
            }
        } else {
            target_url = full_url.to_string();
            target_host = host.to_string();
            target_port = port;
            target_is_https = is_https;
        }

        // Apply header rules to request
        let applied_rules = rules.header_rewriter.rewrite_request_headers(full_url, &mut headers);
        for rule_name in &applied_rules {
            state.traffic.add_matched_rule(&entry_id, "header_request", rule_name);
        }

        drop(rules);

        // Forward request to target server
        let response = Self::forward_request(
            &method,
            &target_url,
            &target_host,
            target_port,
            target_is_https,
            headers,
            body_bytes,
        )
        .await;

        match response {
            Ok(mut resp) => {
                // Collect response headers
                let mut resp_headers: HashMap<String, String> = resp
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();

                // Apply header rules to response
                let rules = state.rules.read().await;
                let applied_rules = rules
                    .header_rewriter
                    .rewrite_response_headers(full_url, &mut resp_headers);
                for rule_name in &applied_rules {
                    state.traffic.add_matched_rule(&entry_id, "header_response", rule_name);
                }
                drop(rules);

                // Collect response body
                let status = resp.status();
                let body = resp.body_mut().collect().await.map(|b| b.to_bytes()).ok();
                let body_size = body.as_ref().map(|b| b.len()).unwrap_or(0);

                // Try to decompress body for traffic inspection
                let content_encoding = resp_headers
                    .get("content-encoding")
                    .map(|s| s.as_str())
                    .unwrap_or("");

                let decoded_body = if !content_encoding.is_empty() {
                    body.as_ref()
                        .and_then(|b| decompress_body(b, content_encoding))
                } else {
                    body.as_ref().map(|b| b.to_vec())
                };

                let response_info = ResponseInfo {
                    status: status.as_u16(),
                    reason: status.canonical_reason().unwrap_or("").to_string(),
                    http_version: format!("{:?}", resp.version()),
                    headers: resp_headers.clone(),
                    body: decoded_body,
                    body_size,
                    modified: target_url != full_url,
                    modification_source: if target_url != full_url {
                        Some(format!("map_remote:{}", target_url))
                    } else {
                        None
                    },
                };

                state.traffic.set_response(&entry_id, response_info);
                state.traffic.mark_complete(&entry_id);

                // Build response with modified headers
                let mut builder = Response::builder().status(status);
                for (key, value) in &resp_headers {
                    // Skip hop-by-hop headers
                    if !is_hop_by_hop_header(key) {
                        builder = builder.header(key, value);
                    }
                }

                Ok(builder
                    .body(Full::new(body.unwrap_or_default()))
                    .unwrap())
            }
            Err(e) => {
                error!("Forward request failed: {}", e);

                let response_info = ResponseInfo {
                    status: 502,
                    reason: "Bad Gateway".to_string(),
                    http_version: "HTTP/1.1".to_string(),
                    headers: HashMap::new(),
                    body: Some(format!("Proxy Error: {}", e).into_bytes()),
                    body_size: 0,
                    modified: false,
                    modification_source: None,
                };

                state.traffic.set_response(&entry_id, response_info);
                state.traffic.mark_complete(&entry_id);

                Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Full::new(Bytes::from(format!("Proxy Error: {}", e))))
                    .unwrap())
            }
        }
    }

    /// Forward request to target server
    async fn forward_request(
        method: &Method,
        url: &str,
        host: &str,
        port: u16,
        is_https: bool,
        headers: HashMap<String, String>,
        body: Option<Bytes>,
    ) -> Result<Response<Incoming>, ProxyError> {
        let uri: Uri = url.parse().map_err(|e| ProxyError::HttpError(format!("Invalid URL: {}", e)))?;
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        // Connect to target server
        let target = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&target)
            .await
            .map_err(|e| ProxyError::IoError(e))?;

        if is_https {
            // TLS connection with ALPN for HTTP/2 negotiation
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

            let connector = TlsConnector::from(Arc::new(config));

            let server_name = ServerName::try_from(host.to_string())
                .map_err(|e| ProxyError::TlsError(format!("Invalid server name: {}", e)))?;

            let tls_stream = connector
                .connect(server_name, stream)
                .await
                .map_err(|e| ProxyError::TlsError(e.to_string()))?;

            // Check negotiated ALPN protocol
            let alpn = tls_stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());

            if alpn.as_deref() == Some(b"h2") {
                debug!("Using HTTP/2 for upstream connection to {}", host);
                Self::send_request_h2(TokioIo::new(tls_stream), method, host, path, headers, body)
                    .await
            } else {
                Self::send_request(TokioIo::new(tls_stream), method, host, path, headers, body)
                    .await
            }
        } else {
            Self::send_request(TokioIo::new(stream), method, host, path, headers, body).await
        }
    }

    /// Send HTTP request over a connection
    async fn send_request<I>(
        io: TokioIo<I>,
        method: &Method,
        host: &str,
        path: &str,
        headers: HashMap<String, String>,
        body: Option<Bytes>,
    ) -> Result<Response<Incoming>, ProxyError>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, conn) = ClientBuilder::new()
            .preserve_header_case(true)
            .handshake(io)
            .await
            .map_err(|e| ProxyError::HttpError(e.to_string()))?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                error!("Connection error: {}", e);
            }
        });

        let mut req_builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", host);

        for (key, value) in &headers {
            // Skip hop-by-hop headers and host (we set it above)
            if !is_hop_by_hop_header(key) && key.to_lowercase() != "host" {
                req_builder = req_builder.header(key, value);
            }
        }

        let req = if let Some(body) = body {
            req_builder
                .body(Full::new(body))
                .map_err(|e| ProxyError::HttpError(e.to_string()))?
        } else {
            req_builder
                .body(Full::new(Bytes::new()))
                .map_err(|e| ProxyError::HttpError(e.to_string()))?
        };

        sender
            .send_request(req)
            .await
            .map_err(|e| ProxyError::HttpError(e.to_string()))
    }

    /// Send HTTP/2 request over a connection
    async fn send_request_h2<I>(
        io: TokioIo<I>,
        method: &Method,
        host: &str,
        path: &str,
        headers: HashMap<String, String>,
        body: Option<Bytes>,
    ) -> Result<Response<Incoming>, ProxyError>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, conn) = Http2ClientBuilder::new(TokioExecutor::new())
            .handshake(io)
            .await
            .map_err(|e| ProxyError::HttpError(e.to_string()))?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                error!("HTTP/2 connection error: {}", e);
            }
        });

        let mut req_builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", host);

        for (key, value) in &headers {
            if !is_hop_by_hop_header(key) && key.to_lowercase() != "host" {
                req_builder = req_builder.header(key, value);
            }
        }

        let req = if let Some(body) = body {
            req_builder
                .body(Full::new(body))
                .map_err(|e| ProxyError::HttpError(e.to_string()))?
        } else {
            req_builder
                .body(Full::new(Bytes::new()))
                .map_err(|e| ProxyError::HttpError(e.to_string()))?
        };

        sender
            .send_request(req)
            .await
            .map_err(|e| ProxyError::HttpError(e.to_string()))
    }

    /// Check if a request is a WebSocket upgrade
    fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
        let upgrade = req
            .headers()
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase());
        let connection = req
            .headers()
            .get("connection")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_lowercase());

        upgrade.as_deref() == Some("websocket")
            && connection
                .as_ref()
                .map(|c| c.contains("upgrade"))
                .unwrap_or(false)
    }

    /// Handle WebSocket proxy upgrade
    async fn handle_websocket_proxy(
        state: Arc<ProxyState>,
        client_addr: SocketAddr,
        req: Request<Incoming>,
        full_url: &str,
        host: &str,
        port: u16,
        is_https: bool,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        // Extract WebSocket headers before consuming the request
        let method = req.method().to_string();
        let http_version = format!("{:?}", req.version());
        let path = req.uri().path().to_string();
        let headers: HashMap<String, String> = req
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let ws_key = headers
            .get("sec-websocket-key")
            .cloned()
            .unwrap_or_default();
        let ws_protocol = headers.get("sec-websocket-protocol").cloned();

        info!("WebSocket upgrade: {} from {}", full_url, client_addr);

        // Compute accept key
        let accept_key =
            tungstenite::handshake::derive_accept_key(ws_key.as_bytes());

        // Create traffic entry
        let request_info = RequestInfo {
            method,
            url: full_url.to_string(),
            http_version,
            headers: headers.clone(),
            body: None,
            body_size: 0,
            client_addr: client_addr.to_string(),
            host: host.to_string(),
            path,
        };

        let max_ws_messages = {
            let config = state.config.read().await;
            config.proxy.max_websocket_messages
        };

        let entry_id = state.traffic.create_websocket_entry(request_info);

        // Prepare values for the spawned task
        let host = host.to_string();
        let full_url = full_url.to_string();
        let ws_protocol_clone = ws_protocol.clone();
        let state_clone = Arc::clone(&state);

        // Get upgrade future (consumes the request)
        let on_upgrade = hyper::upgrade::on(req);

        // Spawn WebSocket relay task
        tokio::spawn(async move {
            match on_upgrade.await {
                Ok(upgraded) => {
                    if let Err(e) = Self::relay_websocket(
                        state_clone,
                        upgraded,
                        &full_url,
                        &host,
                        port,
                        is_https,
                        &entry_id,
                        max_ws_messages,
                        ws_protocol_clone.as_deref(),
                    )
                    .await
                    {
                        error!("WebSocket relay error for {}: {}", full_url, e);
                    }
                }
                Err(e) => {
                    error!("WebSocket upgrade failed: {}", e);
                }
            }
        });

        // Return 101 Switching Protocols
        let mut response = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .header("sec-websocket-accept", &accept_key);

        if let Some(protocol) = ws_protocol {
            response = response.header("sec-websocket-protocol", protocol);
        }

        Ok(response.body(Full::new(Bytes::new())).unwrap())
    }

    /// Establish WebSocket relay between client and upstream
    #[allow(clippy::too_many_arguments)]
    async fn relay_websocket(
        state: Arc<ProxyState>,
        upgraded: hyper::upgrade::Upgraded,
        full_url: &str,
        host: &str,
        port: u16,
        is_https: bool,
        entry_id: &str,
        max_messages: usize,
        protocol: Option<&str>,
    ) -> Result<(), ProxyError> {
        // Connect to upstream
        let upstream_io = Self::connect_upstream_raw(host, port, is_https).await?;

        // Build WebSocket URL for upstream
        let ws_url = if is_https {
            full_url.replacen("https://", "wss://", 1)
        } else {
            full_url.replacen("http://", "ws://", 1)
        };

        // Build upstream WebSocket request
        let mut request = tungstenite::http::Request::builder()
            .uri(&ws_url)
            .header("Host", host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tungstenite::handshake::client::generate_key(),
            );

        if let Some(proto) = protocol {
            request = request.header("Sec-WebSocket-Protocol", proto);
        }

        let request = request
            .body(())
            .map_err(|e| ProxyError::HttpError(format!("Failed to build WS request: {}", e)))?;

        // WebSocket handshake with upstream
        let (upstream_ws, _) = tokio_tungstenite::client_async(request, upstream_io)
            .await
            .map_err(|e| {
                ProxyError::HttpError(format!("WebSocket upstream handshake failed: {}", e))
            })?;

        // Wrap client IO as WebSocket (handshake already completed by hyper)
        let client_io = TokioIo::new(upgraded);
        let client_ws = WebSocketStream::from_raw_socket(
            client_io,
            tungstenite::protocol::Role::Server,
            None,
        )
        .await;

        // Relay frames bidirectionally
        Self::relay_websocket_frames(state, client_ws, upstream_ws, entry_id, max_messages).await;

        Ok(())
    }

    /// Bidirectionally relay WebSocket frames between client and upstream
    async fn relay_websocket_frames<C, U>(
        state: Arc<ProxyState>,
        client_ws: WebSocketStream<C>,
        upstream_ws: WebSocketStream<U>,
        entry_id: &str,
        max_messages: usize,
    ) where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let (mut client_sink, mut client_stream) = client_ws.split();
        let (mut upstream_sink, mut upstream_stream) = upstream_ws.split();

        let entry_id_1 = entry_id.to_string();
        let entry_id_2 = entry_id.to_string();
        let state_1 = Arc::clone(&state);
        let state_2 = Arc::clone(&state);

        let client_to_upstream = async move {
            while let Some(msg) = client_stream.next().await {
                match msg {
                    Ok(msg) => {
                        let ws_info =
                            ws_message_to_info(&msg, WebSocketDirection::ClientToServer);
                        state_1.traffic.record_websocket_message(
                            &entry_id_1,
                            ws_info,
                            max_messages,
                        );

                        if msg.is_close() {
                            let _ = upstream_sink.send(msg).await;
                            break;
                        }
                        if upstream_sink.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("WebSocket client stream error: {}", e);
                        break;
                    }
                }
            }
        };

        let upstream_to_client = async move {
            while let Some(msg) = upstream_stream.next().await {
                match msg {
                    Ok(msg) => {
                        let ws_info =
                            ws_message_to_info(&msg, WebSocketDirection::ServerToClient);
                        state_2.traffic.record_websocket_message(
                            &entry_id_2,
                            ws_info,
                            max_messages,
                        );

                        if msg.is_close() {
                            let _ = client_sink.send(msg).await;
                            break;
                        }
                        if client_sink.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("WebSocket upstream stream error: {}", e);
                        break;
                    }
                }
            }
        };

        tokio::select! {
            _ = client_to_upstream => {},
            _ = upstream_to_client => {},
        }

        state.traffic.mark_complete(entry_id);
    }

    /// Connect to upstream server, returning a raw TCP or TLS stream
    async fn connect_upstream_raw(
        host: &str,
        port: u16,
        is_https: bool,
    ) -> Result<UpstreamStream, ProxyError> {
        let target = format!("{}:{}", host, port);
        let stream = TcpStream::connect(&target).await?;

        if is_https {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            let connector = TlsConnector::from(Arc::new(config));
            let server_name = ServerName::try_from(host.to_string())
                .map_err(|e| ProxyError::TlsError(format!("Invalid server name: {}", e)))?;

            let tls_stream = connector
                .connect(server_name, stream)
                .await
                .map_err(|e| ProxyError::TlsError(e.to_string()))?;

            Ok(UpstreamStream::Tls(Box::new(tls_stream)))
        } else {
            Ok(UpstreamStream::Plain(stream))
        }
    }
}

/// Raw upstream stream — either plain TCP or TLS
enum UpstreamStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for UpstreamStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            UpstreamStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            UpstreamStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_flush(cx),
            UpstreamStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            UpstreamStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Unpin for UpstreamStream {}

/// Convert a tungstenite Message to a WebSocketMessageInfo for traffic recording
fn ws_message_to_info(
    msg: &tungstenite::Message,
    direction: WebSocketDirection,
) -> WebSocketMessageInfo {
    let (message_type, payload, payload_size) = match msg {
        tungstenite::Message::Text(text) => {
            (WebSocketMessageType::Text, Some(text.clone()), text.len())
        }
        tungstenite::Message::Binary(data) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(data);
            (WebSocketMessageType::Binary, Some(encoded), data.len())
        }
        tungstenite::Message::Ping(data) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(data);
            (WebSocketMessageType::Ping, Some(encoded), data.len())
        }
        tungstenite::Message::Pong(data) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(data);
            (WebSocketMessageType::Pong, Some(encoded), data.len())
        }
        tungstenite::Message::Close(frame) => {
            let payload = frame.as_ref().map(|f| f.reason.to_string());
            let size = frame.as_ref().map(|f| f.reason.len()).unwrap_or(0);
            (WebSocketMessageType::Close, payload, size)
        }
        tungstenite::Message::Frame(_) => (WebSocketMessageType::Binary, None, 0),
    };

    WebSocketMessageInfo {
        timestamp: Utc::now(),
        direction,
        message_type,
        payload,
        payload_size,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traffic::{WebSocketDirection, WebSocketMessageType};

    #[test]
    fn test_ws_message_to_info_text() {
        let msg = tungstenite::Message::Text("hello world".into());
        let info = ws_message_to_info(&msg, WebSocketDirection::ClientToServer);
        assert!(matches!(info.message_type, WebSocketMessageType::Text));
        assert_eq!(info.payload_size, 11);
        assert!(info.payload.is_some());
    }

    #[test]
    fn test_ws_message_to_info_binary() {
        let data = vec![1u8, 2, 3, 4];
        let msg = tungstenite::Message::Binary(data.clone().into());
        let info = ws_message_to_info(&msg, WebSocketDirection::ServerToClient);
        assert!(matches!(info.message_type, WebSocketMessageType::Binary));
        assert_eq!(info.payload_size, 4);
        // Verify base64 round-trip
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(info.payload.unwrap())
            .unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_ws_message_to_info_close() {
        let msg = tungstenite::Message::Close(Some(tungstenite::protocol::CloseFrame {
            code: tungstenite::protocol::frame::coding::CloseCode::Normal,
            reason: "goodbye".into(),
        }));
        let info = ws_message_to_info(&msg, WebSocketDirection::ClientToServer);
        assert!(matches!(info.message_type, WebSocketMessageType::Close));
        assert_eq!(info.payload.as_deref(), Some("goodbye"));
    }
}

/// Check if a header is a hop-by-hop header
fn is_hop_by_hop_header(name: &str) -> bool {
    let name = name.to_lowercase();
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Decompress body based on content-encoding
fn decompress_body(body: &[u8], encoding: &str) -> Option<Vec<u8>> {
    match encoding.to_lowercase().as_str() {
        "gzip" => {
            use std::io::Read;
            let mut decoder = flate2::read::GzDecoder::new(body);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed).ok()?;
            Some(decompressed)
        }
        "deflate" => {
            use std::io::Read;
            let mut decoder = flate2::read::DeflateDecoder::new(body);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed).ok()?;
            Some(decompressed)
        }
        "br" => {
            let mut decompressed = Vec::new();
            brotli::BrotliDecompress(&mut std::io::Cursor::new(body), &mut decompressed).ok()?;
            Some(decompressed)
        }
        _ => None,
    }
}
