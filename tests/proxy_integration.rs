use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::Builder as ClientBuilder;
use hyper::server::conn::http1::Builder as ServerBuilder;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustyman::cert::CertificateAuthority;
use rustyman::config::Config;
use rustyman::proxy::ProxyServer;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::WebSocketStream;
use tokio_util::sync::CancellationToken;

fn get_free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

async fn wait_for_port(addr: SocketAddr) {
    for _ in 0..200 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("Server didn't start in time at {}", addr);
}

struct ProxyFixture {
    pub state: std::sync::Arc<rustyman::proxy::ProxyState>,
    pub addr: SocketAddr,
    cancel: CancellationToken,
    _temp_dir: tempfile::TempDir,
}

impl Drop for ProxyFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

async fn start_proxy() -> ProxyFixture {
    let proxy_port = get_free_port();
    let temp_dir = tempfile::TempDir::new().unwrap();

    let ca = CertificateAuthority::new(
        temp_dir.path().join("ca.crt").to_str().unwrap(),
        temp_dir.path().join("ca.key").to_str().unwrap(),
        true,
        3650,
        365,
    )
    .unwrap();

    let mut config = Config::default();
    config.proxy.port = proxy_port;
    config.proxy.mitm_enabled = true;

    let cancel = CancellationToken::new();
    let server = ProxyServer::new(config, ca, cancel.clone()).unwrap();
    let state = server.state();
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", proxy_port).parse().unwrap();

    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        server.run(cancel_clone).await.ok();
    });

    wait_for_port(proxy_addr).await;

    ProxyFixture {
        state,
        addr: proxy_addr,
        cancel,
        _temp_dir: temp_dir,
    }
}

/// Test that HTTP/1.1 requests are correctly forwarded through the proxy.
#[tokio::test]
async fn test_http_forward_through_proxy() {
    // Start upstream HTTP server
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((stream, _)) = upstream_listener.accept().await {
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                ServerBuilder::new()
                    .serve_connection(
                        io,
                        service_fn(|_| async {
                            Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(
                                "hello from upstream",
                            ))))
                        }),
                    )
                    .await
                    .ok();
            });
        }
    });

    let fixture = start_proxy().await;

    // Send HTTP request through proxy
    let stream = TcpStream::connect(fixture.addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = ClientBuilder::new().handshake(io).await.unwrap();
    tokio::spawn(conn);

    let req = Request::get(format!(
        "http://127.0.0.1:{}/test",
        upstream_addr.port()
    ))
    .header("host", format!("127.0.0.1:{}", upstream_addr.port()))
    .body(Full::new(Bytes::new()))
    .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "hello from upstream");

    // Verify traffic was recorded
    assert!(fixture.state.traffic.count() > 0);
}

/// Test that WebSocket connections are transparently proxied and
/// messages are recorded in the traffic store.
#[tokio::test]
async fn test_websocket_proxy() {
    // Start WebSocket echo server
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((stream, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                match tokio_tungstenite::accept_async(stream).await {
                    Ok(ws) => {
                        let (write, read) = ws.split();
                        read.forward(write).await.ok();
                    }
                    Err(e) => eprintln!("WS echo accept error: {}", e),
                }
            });
        }
    });

    let fixture = start_proxy().await;

    // Connect TCP to proxy and send WebSocket upgrade request
    let mut stream = TcpStream::connect(fixture.addr).await.unwrap();

    let key = tungstenite::handshake::client::generate_key();
    let request = format!(
        "GET http://127.0.0.1:{}/ HTTP/1.1\r\n\
         Host: 127.0.0.1:{}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         \r\n",
        echo_addr.port(),
        echo_addr.port(),
        key,
    );

    stream.write_all(request.as_bytes()).await.unwrap();

    // Read HTTP 101 response
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await.unwrap();
        assert!(n > 0, "Connection closed before 101 response");
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let response = String::from_utf8_lossy(&buf);
    assert!(
        response.starts_with("HTTP/1.1 101"),
        "Expected 101, got: {}",
        response.lines().next().unwrap_or("")
    );

    // Wrap raw TCP as WebSocket client (handshake is done)
    let ws = WebSocketStream::from_raw_socket(
        stream,
        tungstenite::protocol::Role::Client,
        None,
    )
    .await;

    let (mut write, mut read) = ws.split();

    // Send and receive a text message
    write
        .send(tungstenite::Message::Text("hello proxy".into()))
        .await
        .unwrap();

    let msg = read.next().await.unwrap().unwrap();
    match &msg {
        tungstenite::Message::Text(text) => {
            assert_eq!(text.to_string(), "hello proxy");
        }
        other => panic!("Expected Text, got {:?}", other),
    }

    // Send and receive a second message
    write
        .send(tungstenite::Message::Text("second".into()))
        .await
        .unwrap();

    let msg = read.next().await.unwrap().unwrap();
    match &msg {
        tungstenite::Message::Text(text) => {
            assert_eq!(text.to_string(), "second");
        }
        other => panic!("Expected Text, got {:?}", other),
    }

    // Close
    write
        .send(tungstenite::Message::Close(None))
        .await
        .unwrap();

    // Give the relay task time to flush traffic recording
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify traffic store has a WebSocket entry with recorded messages
    let entries = fixture.state.traffic.list(0, 100);
    let ws_entry = entries.iter().find(|e| e.is_websocket);
    assert!(ws_entry.is_some(), "No WebSocket traffic entry found");

    let ws_entry = ws_entry.unwrap();
    let messages = ws_entry.websocket_messages.as_ref().unwrap();
    // At least the 2 sent + 2 echoed messages
    assert!(
        messages.len() >= 4,
        "Expected >= 4 recorded WS messages, got {}",
        messages.len()
    );
}
