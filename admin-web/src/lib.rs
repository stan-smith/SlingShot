use anyhow::Result;
use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use fingerprint_store::FingerprintStore;
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Mutex};

/// Pending node awaiting admin approval
pub struct PendingNode {
    pub name: String,
    pub fingerprint: String,
    pub rtsp_url: String,
    pub address: String,
    pub approve_tx: oneshot::Sender<bool>,
}

/// Shared admin state
pub struct AdminState {
    /// Active WebSocket sessions: session_id -> sender
    pub sessions: Mutex<HashMap<u64, mpsc::Sender<String>>>,
    /// Nodes waiting for approval
    pub pending_nodes: Mutex<Vec<PendingNode>>,
    /// Counter for session IDs
    next_session_id: Mutex<u64>,
    /// Channel to send commands to central daemon
    pub command_tx: mpsc::Sender<AdminCommand>,
    /// Fingerprint store for authentication
    pub store: Arc<Mutex<FingerprintStore>>,
}

/// Command from admin to daemon
pub struct AdminCommand {
    pub raw_line: String,
}

impl AdminState {
    pub fn new(command_tx: mpsc::Sender<AdminCommand>, store: Arc<Mutex<FingerprintStore>>) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            pending_nodes: Mutex::new(Vec::new()),
            next_session_id: Mutex::new(1),
            command_tx,
            store,
        }
    }

    async fn next_id(&self) -> u64 {
        let mut id = self.next_session_id.lock().await;
        let current = *id;
        *id += 1;
        current
    }
}

/// Broadcast a message to all connected admin sessions
pub async fn broadcast(state: &AdminState, message: &str) {
    let sessions = state.sessions.lock().await;
    for tx in sessions.values() {
        let _ = tx.send(message.to_string()).await;
    }
}

/// Request approval for a node from connected admins
/// Returns true if approved, false if rejected
pub async fn request_approval(
    state: &Arc<AdminState>,
    name: String,
    fingerprint: String,
    rtsp_url: String,
    address: String,
) -> bool {
    let (tx, rx) = oneshot::channel();

    // Add to pending list
    {
        let mut pending = state.pending_nodes.lock().await;
        pending.push(PendingNode {
            name: name.clone(),
            fingerprint: fingerprint.clone(),
            rtsp_url: rtsp_url.clone(),
            address: address.clone(),
            approve_tx: tx,
        });
    }

    // Notify admins
    let msg = format!(
        "PENDING|{}|{}|{}",
        name,
        &fingerprint[..16.min(fingerprint.len())],
        address
    );
    broadcast(state, &msg).await;

    // Wait for approval/rejection
    rx.await.unwrap_or(false)
}

/// Start the admin web server on the specified address
pub async fn run_admin_server(addr: &str, state: Arc<AdminState>) -> Result<()> {
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/ws", get(ws_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("Admin web server listening on http://{}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn index_handler() -> impl IntoResponse {
    Html(INDEX_HTML)
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AdminState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<AdminState>) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    // ========== Authentication Phase ==========
    // Wait for AUTH or TOKEN message (timeout 30s)
    let auth_result = tokio::time::timeout(Duration::from_secs(30), ws_rx.next()).await;

    let (authenticated, session_token) = match auth_result {
        Ok(Some(Ok(Message::Text(msg)))) => {
            let store = state.store.lock().await;
            if msg.starts_with("AUTH|") {
                // Password auth: AUTH|username|password
                let parts: Vec<&str> = msg.split('|').collect();
                if parts.len() == 3 {
                    if store.verify_admin(parts[1], parts[2]).unwrap_or(false) {
                        // Create session token
                        let token = store.create_session(parts[1]).ok();
                        (true, token)
                    } else {
                        (false, None)
                    }
                } else {
                    (false, None)
                }
            } else if msg.starts_with("TOKEN|") {
                // Token auth: TOKEN|session_token
                let token = msg.strip_prefix("TOKEN|").unwrap_or("");
                if store.verify_session(token).unwrap_or(None).is_some() {
                    (true, Some(token.to_string()))
                } else {
                    (false, None)
                }
            } else {
                (false, None)
            }
        }
        _ => (false, None),
    };

    if !authenticated {
        // Rate limit: 1 second delay on failed auth to prevent brute force
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = ws_tx.send(Message::Text("AUTH_FAILED".into())).await;
        return;
    }

    // Send auth success with token
    let token_msg = format!("AUTH_OK|{}", session_token.unwrap_or_default());
    let _ = ws_tx.send(Message::Text(token_msg.into())).await;

    // ========== Authenticated Session ==========
    let (tx, mut rx) = mpsc::channel::<String>(100);
    let session_id = state.next_id().await;

    // Register session
    {
        let mut sessions = state.sessions.lock().await;
        sessions.insert(session_id, tx);
    }

    // Send current pending nodes
    {
        let pending = state.pending_nodes.lock().await;
        for node in pending.iter() {
            let msg = format!(
                "PENDING|{}|{}|{}",
                node.name,
                &node.fingerprint[..16.min(node.fingerprint.len())],
                node.address
            );
            let _ = ws_tx.send(Message::Text(msg.into())).await;
        }
    }

    let state_clone = Arc::clone(&state);

    // Spawn task to forward messages to WebSocket
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_tx.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    // Handle incoming messages
    while let Some(Ok(msg)) = ws_rx.next().await {
        if let Message::Text(text) = msg {
            let line = text.trim();
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            match parts[0].to_lowercase().as_str() {
                "approve" if parts.len() >= 2 => {
                    let name = parts[1];
                    let mut pending = state_clone.pending_nodes.lock().await;
                    if let Some(idx) = pending.iter().position(|n| n.name == name) {
                        let node = pending.remove(idx);
                        let _ = node.approve_tx.send(true);
                        broadcast(&state_clone, &format!("APPROVED|{}", name)).await;
                    }
                }
                "reject" if parts.len() >= 2 => {
                    let name = parts[1];
                    let mut pending = state_clone.pending_nodes.lock().await;
                    if let Some(idx) = pending.iter().position(|n| n.name == name) {
                        let node = pending.remove(idx);
                        let _ = node.approve_tx.send(false);
                        broadcast(&state_clone, &format!("REJECTED|{}", name)).await;
                    }
                }
                "pending" => {
                    let pending = state_clone.pending_nodes.lock().await;
                    if pending.is_empty() {
                        if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                            let _ = tx.send("No pending nodes".to_string()).await;
                        }
                    } else {
                        for node in pending.iter() {
                            let msg = format!(
                                "PENDING|{}|{}|{}",
                                node.name,
                                &node.fingerprint[..16.min(node.fingerprint.len())],
                                node.address
                            );
                            if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                let _ = tx.send(msg).await;
                            }
                        }
                    }
                }
                "help" => {
                    let help_lines = [
                        "=== Admin Commands ===",
                        "  nodes / list          - List connected nodes",
                        "  pending               - List nodes awaiting approval",
                        "  approve <name>        - Approve pending node",
                        "  reject <name>         - Reject pending node",
                        "",
                        "=== Node Commands ===",
                        "  <node> params         - Show current stream parameters",
                        "  <node> res <w> <h>    - Set resolution",
                        "  <node> bitrate <kbps> - Set bitrate",
                        "  <node> fps <rate>     - Set framerate",
                        "",
                        "=== PTZ Commands ===",
                        "  <node> left [spd] [ms]   - Pan left",
                        "  <node> right [spd] [ms]  - Pan right",
                        "  <node> up [spd] [ms]     - Tilt up",
                        "  <node> down [spd] [ms]   - Tilt down",
                        "  <node> zoomin [spd] [ms] - Zoom in",
                        "  <node> zoomout [spd] [ms]- Zoom out",
                        "  <node> home              - Go to home position",
                        "  <node> stop              - Stop movement",
                        "  <node> status            - Get PTZ position",
                        "  <node> info              - Get camera info",
                    ];
                    if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                        for line in help_lines {
                            let _ = tx.send(line.to_string()).await;
                        }
                    }
                }
                _ => {
                    // Forward to daemon
                    let cmd = AdminCommand {
                        raw_line: line.to_string(),
                    };
                    let _ = state_clone.command_tx.send(cmd).await;
                }
            }
        }
    }

    // Cleanup
    send_task.abort();
    {
        let mut sessions = state.sessions.lock().await;
        sessions.remove(&session_id);
    }
}

const INDEX_HTML: &str = include_str!("../static/index.html");
