use crate::proxy::ProxyState;
use crate::traffic::TrafficEvent;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::sync::Arc;
use tracing::{debug, error};

/// WebSocket handler for real-time traffic updates
pub async fn traffic_ws(
    ws: WebSocketUpgrade,
    State(state): State<Arc<ProxyState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

/// Handle WebSocket connection
async fn handle_socket(socket: WebSocket, state: Arc<ProxyState>) {
    let (mut sender, mut receiver) = socket.split();

    // Subscribe to traffic events
    let mut rx = state.traffic.subscribe();

    // Spawn task to send traffic events to client
    let send_task = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let ws_event = match event {
                        TrafficEvent::NewRequest(entry) => WsEvent {
                            event_type: "new_request".to_string(),
                            data: serde_json::to_value(&entry).unwrap_or_default(),
                        },
                        TrafficEvent::ResponseReceived(entry) => WsEvent {
                            event_type: "response_received".to_string(),
                            data: serde_json::to_value(&entry).unwrap_or_default(),
                        },
                        TrafficEvent::Completed(entry) => WsEvent {
                            event_type: "completed".to_string(),
                            data: serde_json::to_value(&entry).unwrap_or_default(),
                        },
                        TrafficEvent::Cleared => WsEvent {
                            event_type: "cleared".to_string(),
                            data: serde_json::Value::Null,
                        },
                    };

                    if let Ok(json) = serde_json::to_string(&ws_event) {
                        if sender.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    // Channel lagged, skip some messages
                    debug!("WebSocket receiver lagged: {}", e);
                }
            }
        }
    });

    // Spawn task to receive messages from client (for ping/pong)
    let recv_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Ping(_)) => {
                    debug!("Received ping");
                    // Pong is handled automatically by axum
                }
                Ok(Message::Close(_)) => {
                    debug!("WebSocket closed by client");
                    break;
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }

    debug!("WebSocket connection closed");
}

#[derive(Serialize)]
struct WsEvent {
    event_type: String,
    data: serde_json::Value,
}
