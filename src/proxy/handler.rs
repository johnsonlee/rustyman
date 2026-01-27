use super::tls::TlsAcceptor;
use super::{ProxyError, ProxyState};
use crate::traffic::{RequestInfo, ResponseInfo};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::Builder as ClientBuilder;
use hyper::server::conn::http1::Builder as ServerBuilder;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
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

        // Serve HTTP over the TLS connection
        ServerBuilder::new()
            .preserve_header_case(true)
            .serve_connection(
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

                let response_info = ResponseInfo {
                    status: status.as_u16(),
                    reason: status.canonical_reason().unwrap_or("").to_string(),
                    http_version: format!("{:?}", resp.version()),
                    headers: resp_headers.clone(),
                    body: body.as_ref().map(|b| b.to_vec()),
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
            // TLS connection
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

            Self::send_request(TokioIo::new(tls_stream), method, host, path, headers, body).await
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
