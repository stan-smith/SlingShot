use anyhow::Result;
use chrono::SecondsFormat;
use axum::{
    extract::{
        connect_info::ConnectInfo,
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use fingerprint_store::FingerprintStore;
use futures::{SinkExt, StreamExt};
use hls_server::HlsState;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, Mutex};

/// Pending node awaiting admin approval
pub struct PendingNode {
    pub name: String,
    pub fingerprint: String,
    pub rtsp_url: String,
    pub address: String,
    pub approve_tx: oneshot::Sender<bool>,
}

/// Rate limit tracking entry for IP-based authentication throttling
pub struct RateLimitEntry {
    pub failed_attempts: u32,
    pub last_attempt: Instant,
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
    /// HLS server state for video streaming
    pub hls_state: Arc<HlsState>,
    /// IP-based rate limiting for authentication
    pub rate_limits: Mutex<HashMap<IpAddr, RateLimitEntry>>,
}

/// Command from admin to daemon
pub struct AdminCommand {
    pub raw_line: String,
}

impl AdminState {
    /// Create a new AdminState with default HLS configuration
    pub fn new(command_tx: mpsc::Sender<AdminCommand>, store: Arc<Mutex<FingerprintStore>>) -> Self {
        Self::with_hls_config(command_tx, store, PathBuf::from("/tmp/hls"), 8554)
    }

    /// Create a new AdminState with custom HLS configuration
    pub fn with_hls_config(
        command_tx: mpsc::Sender<AdminCommand>,
        store: Arc<Mutex<FingerprintStore>>,
        hls_dir: PathBuf,
        rtsp_port: u16,
    ) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            pending_nodes: Mutex::new(Vec::new()),
            next_session_id: Mutex::new(1),
            command_tx,
            store,
            hls_state: Arc::new(HlsState::new(hls_dir, rtsp_port)),
            rate_limits: Mutex::new(HashMap::new()),
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
    // Create HLS router with shared HLS state (stateless merge)
    let hls_router = hls_server::routes::hls_router(state.hls_state.clone());

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/admin", get(admin_page_handler))
        .route("/ws", get(ws_handler))
        .with_state(state)
        // HLS streaming routes - merged without state (already has its own)
        .nest("/hls", hls_router);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("Admin web server listening on http://{}", addr);
    println!("HLS streaming available at /hls/<node>/stream.m3u8");

    // Use into_make_service_with_connect_info to extract client IP for rate limiting
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

async fn index_handler() -> impl IntoResponse {
    Html(INDEX_HTML)
}

async fn admin_page_handler() -> impl IntoResponse {
    Html(ADMIN_HTML)
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AdminState>>,
) -> impl IntoResponse {
    let client_ip = addr.ip();
    ws.on_upgrade(move |socket| handle_socket(socket, state, client_ip))
}

async fn handle_socket(socket: WebSocket, state: Arc<AdminState>, client_ip: IpAddr) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    // ~ Rate Limit Check ~
    // Check if this IP is rate limited before allowing auth attempt
    {
        let mut rate_limits = state.rate_limits.lock().await;

        // Clean up stale entries (older than 15 minutes)
        let cutoff = Instant::now() - Duration::from_secs(15 * 60);
        rate_limits.retain(|_, entry| entry.last_attempt > cutoff);

        // Check if IP is locked out
        if let Some(entry) = rate_limits.get(&client_ip) {
            // Lockout after 4+ failures for 5 minutes
            if entry.failed_attempts >= 4 {
                let lockout_end = entry.last_attempt + Duration::from_secs(5 * 60);
                if Instant::now() < lockout_end {
                    let remaining = lockout_end.duration_since(Instant::now()).as_secs();
                    println!(
                        "Rate limit: {} is locked out ({} failures), {} seconds remaining",
                        client_ip, entry.failed_attempts, remaining
                    );
                    let _ = ws_tx
                        .send(Message::Text(format!("RATE_LIMITED|{}", remaining).into()))
                        .await;
                    return;
                }
            }
        }
    }

    // ~ Authentication Phase ~
    // Wait for TOTP or TOKEN message (timeout 30s)
    let auth_result = tokio::time::timeout(Duration::from_secs(30), ws_rx.next()).await;

    let (authenticated, session_token, user_role) = match auth_result {
        Ok(Some(Ok(Message::Text(msg)))) => {
            let store = state.store.lock().await;
            if msg.starts_with("TOTP|") {
                // TOTP auth: TOTP|username|code
                let parts: Vec<&str> = msg.split('|').collect();
                if parts.len() == 3 {
                    let username = parts[1];
                    let code = parts[2];
                    if store.verify_totp(username, code).unwrap_or(false) {
                        // Get user role
                        let role = store.get_user(username)
                            .ok()
                            .flatten()
                            .map(|u| u.role)
                            .unwrap_or_else(|| "user".to_string());
                        // Create session token
                        let token = store.create_session(username).ok();
                        (true, token, role)
                    } else {
                        (false, None, String::new())
                    }
                } else {
                    (false, None, String::new())
                }
            } else if msg.starts_with("TOKEN|") {
                // Token auth: TOKEN|session_token
                let token = msg.strip_prefix("TOKEN|").unwrap_or("");
                if let Some((_username, role)) = store.verify_session(token).unwrap_or(None) {
                    (true, Some(token.to_string()), role)
                } else {
                    (false, None, String::new())
                }
            } else {
                (false, None, String::new())
            }
        }
        _ => (false, None, String::new()),
    };

    if !authenticated {
        // Update rate limit tracking with exponential backoff
        let delay_secs = {
            let mut rate_limits = state.rate_limits.lock().await;
            let entry = rate_limits.entry(client_ip).or_insert(RateLimitEntry {
                failed_attempts: 0,
                last_attempt: Instant::now(),
            });
            entry.failed_attempts += 1;
            entry.last_attempt = Instant::now();

            // Exponential backoff: 1s, 2s, 4s, 8s (capped)
            let delay = match entry.failed_attempts {
                1 => 1,
                2 => 2,
                3 => 4,
                _ => 8,
            };

            println!(
                "Rate limit: {} failed {} time(s), delay {}s",
                client_ip, entry.failed_attempts, delay
            );

            delay
        };

        tokio::time::sleep(Duration::from_secs(delay_secs)).await;
        let _ = ws_tx.send(Message::Text("AUTH_FAILED".into())).await;
        return;
    }

    // Clear rate limit on successful auth
    {
        let mut rate_limits = state.rate_limits.lock().await;
        rate_limits.remove(&client_ip);
    }

    // Send auth success with token and role
    let token_msg = format!("AUTH_OK|{}|{}", session_token.unwrap_or_default(), user_role);
    let _ = ws_tx.send(Message::Text(token_msg.into())).await;

    // Track role for permission checks
    let is_admin = user_role == "admin";

    // ~ Authenticated Session ~
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

            // Get command name (first segment before | or space)
            let cmd_end = line.find(|c| c == '|' || c == ' ').unwrap_or(line.len());
            let cmd = &line[..cmd_end].to_lowercase();

            // For whitespace-separated commands
            let parts: Vec<&str> = line.split_whitespace().collect();

            match cmd.as_str() {
                "approve" if parts.len() >= 2 => {
                    if !is_admin {
                        if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                            let _ = tx.send("ERROR|Permission denied (admin only)".to_string()).await;
                        }
                        continue;
                    }
                    let name = parts[1];
                    let mut pending = state_clone.pending_nodes.lock().await;
                    if let Some(idx) = pending.iter().position(|n| n.name == name) {
                        let node = pending.remove(idx);
                        let _ = node.approve_tx.send(true);
                        broadcast(&state_clone, &format!("APPROVED|{}", name)).await;
                    }
                }
                "reject" if parts.len() >= 2 => {
                    if !is_admin {
                        if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                            let _ = tx.send("ERROR|Permission denied (admin only)".to_string()).await;
                        }
                        continue;
                    }
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
                "approved" => {
                    let store = state_clone.store.lock().await;
                    match store.list_approved() {
                        Ok(nodes) => {
                            let json: Vec<_> = nodes.iter().map(|n| {
                                format!(
                                    r#"{{"fingerprint":"{}","node_name":"{}","first_seen":"{}","last_seen":"{}","approved_by":"{}"}}"#,
                                    n.fingerprint,
                                    n.node_name,
                                    n.first_seen.to_rfc3339_opts(SecondsFormat::Secs, true),
                                    n.last_seen.to_rfc3339_opts(SecondsFormat::Secs, true),
                                    n.approved_by.as_deref().unwrap_or("")
                                )
                            }).collect();
                            let msg = format!("APPROVED_NODES|[{}]", json.join(","));
                            if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                let _ = tx.send(msg).await;
                            }
                        }
                        Err(e) => {
                            if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                let _ = tx.send(format!("ERROR|{}", e)).await;
                            }
                        }
                    }
                }
                "revoke" if parts.len() >= 2 => {
                    if !is_admin {
                        if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                            let _ = tx.send("ERROR|Permission denied (admin only)".to_string()).await;
                        }
                        continue;
                    }
                    let fingerprint = parts[1];
                    let store = state_clone.store.lock().await;
                    match store.revoke(fingerprint) {
                        Ok(true) => {
                            broadcast(&state_clone, &format!("REVOKED|{}", fingerprint)).await;
                            // Also disconnect the node if it's currently connected
                            drop(store); // Release lock before sending command
                            let cmd = AdminCommand { raw_line: format!("disconnect_by_fp {}", fingerprint) };
                            let _ = state_clone.command_tx.send(cmd).await;
                        }
                        Ok(false) => {
                            if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                let _ = tx.send("ERROR|Node not found".to_string()).await;
                            }
                        }
                        Err(e) => {
                            if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                let _ = tx.send(format!("ERROR|{}", e)).await;
                            }
                        }
                    }
                }
                "help" => {
                    let help_lines = [
                        "~ Admin Commands ~",
                        "  nodes / list          - List connected nodes",
                        "  pending               - List nodes awaiting approval",
                        "  approve <name>        - Approve pending node",
                        "  reject <name>         - Reject pending node",
                        "  approved              - List all approved nodes",
                        "  revoke <fingerprint>  - Revoke node approval (admin)",
                        "",
                        "~ Node Commands ~",
                        "  <node> params         - Show current stream parameters",
                        "  <node> res <w> <h>    - Set resolution",
                        "  <node> bitrate <kbps> - Set bitrate",
                        "  <node> fps <rate>     - Set framerate",
                        "",
                        "~ PTZ Commands ~",
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
                // ~ User Management Commands (Admin Only) ~
                "users" => {
                    if !is_admin {
                        if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                            let _ = tx.send("ERROR|Permission denied (admin only)".to_string()).await;
                        }
                        continue;
                    }
                    let store = state_clone.store.lock().await;
                    match store.list_users() {
                        Ok(users) => {
                            let json: Vec<_> = users.iter().map(|u| {
                                format!(r#"{{"username":"{}","role":"{}","description":"{}","created_at":"{}"}}"#,
                                    u.username,
                                    u.role,
                                    u.description.as_deref().unwrap_or(""),
                                    u.created_at
                                )
                            }).collect();
                            let msg = format!("USERS|[{}]", json.join(","));
                            if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                let _ = tx.send(msg).await;
                            }
                        }
                        Err(e) => {
                            if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                let _ = tx.send(format!("ERROR|{}", e)).await;
                            }
                        }
                    }
                }
                "user_create" => {
                    // user_create|username|role|description
                    if !is_admin {
                        if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                            let _ = tx.send("ERROR|Permission denied (admin only)".to_string()).await;
                        }
                        continue;
                    }
                    // Parse pipe-separated parts from original line
                    let pipe_parts: Vec<&str> = line.split('|').collect();
                    if pipe_parts.len() < 3 {
                        if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                            let _ = tx.send("ERROR|Usage: user_create|username|role|description".to_string()).await;
                        }
                        continue;
                    }
                    let username = pipe_parts[1];
                    let role = pipe_parts[2];
                    let description = if pipe_parts.len() > 3 { pipe_parts[3] } else { "" };

                    // Generate TOTP secret
                    match FingerprintStore::generate_totp_secret(username) {
                        Ok((secret, qr_png)) => {
                            // Store pending user creation (will be confirmed with user_verify)
                            // For now, send QR code as base64
                            use base64::{Engine, engine::general_purpose::STANDARD};
                            let qr_base64 = STANDARD.encode(&qr_png);
                            let msg = format!("USER_QR|{}|{}|{}|{}|{}", username, role, description, secret, qr_base64);
                            if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                let _ = tx.send(msg).await;
                            }
                        }
                        Err(e) => {
                            if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                let _ = tx.send(format!("ERROR|{}", e)).await;
                            }
                        }
                    }
                }
                "user_verify" => {
                    // user_verify|username|totp_secret|role|description|code
                    if !is_admin {
                        if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                            let _ = tx.send("ERROR|Permission denied (admin only)".to_string()).await;
                        }
                        continue;
                    }
                    let pipe_parts: Vec<&str> = line.split('|').collect();
                    if pipe_parts.len() < 6 {
                        if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                            let _ = tx.send("ERROR|Usage: user_verify|username|secret|role|description|code".to_string()).await;
                        }
                        continue;
                    }
                    let username = pipe_parts[1];
                    let secret = pipe_parts[2];
                    let role = pipe_parts[3];
                    let description = pipe_parts[4];
                    let code = pipe_parts[5];

                    // Verify the TOTP code
                    match FingerprintStore::verify_totp_code(secret, code) {
                        Ok(true) => {
                            // Code valid - create the user
                            let store = state_clone.store.lock().await;
                            match store.create_user(username, secret, role, description) {
                                Ok(()) => {
                                    if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                        let _ = tx.send(format!("USER_CREATED|{}", username)).await;
                                    }
                                }
                                Err(e) => {
                                    if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                        let _ = tx.send(format!("ERROR|{}", e)).await;
                                    }
                                }
                            }
                        }
                        Ok(false) => {
                            if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                let _ = tx.send("ERROR|Invalid TOTP code".to_string()).await;
                            }
                        }
                        Err(e) => {
                            if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                let _ = tx.send(format!("ERROR|{}", e)).await;
                            }
                        }
                    }
                }
                "user_role" => {
                    // user_role|username|role
                    if !is_admin {
                        if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                            let _ = tx.send("ERROR|Permission denied (admin only)".to_string()).await;
                        }
                        continue;
                    }
                    let pipe_parts: Vec<&str> = line.split('|').collect();
                    if pipe_parts.len() < 3 {
                        if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                            let _ = tx.send("ERROR|Usage: user_role|username|role".to_string()).await;
                        }
                        continue;
                    }
                    let username = pipe_parts[1];
                    let role = pipe_parts[2];

                    let store = state_clone.store.lock().await;
                    match store.update_user_role(username, role) {
                        Ok(()) => {
                            if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                let _ = tx.send(format!("USER_UPDATED|{}", username)).await;
                            }
                        }
                        Err(e) => {
                            if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                let _ = tx.send(format!("ERROR|{}", e)).await;
                            }
                        }
                    }
                }
                "user_desc" => {
                    // user_desc|username|description
                    if !is_admin {
                        if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                            let _ = tx.send("ERROR|Permission denied (admin only)".to_string()).await;
                        }
                        continue;
                    }
                    let pipe_parts: Vec<&str> = line.split('|').collect();
                    if pipe_parts.len() < 3 {
                        if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                            let _ = tx.send("ERROR|Usage: user_desc|username|description".to_string()).await;
                        }
                        continue;
                    }
                    let username = pipe_parts[1];
                    let description = pipe_parts[2];

                    let store = state_clone.store.lock().await;
                    match store.update_user_description(username, description) {
                        Ok(()) => {
                            if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                let _ = tx.send(format!("USER_UPDATED|{}", username)).await;
                            }
                        }
                        Err(e) => {
                            if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                let _ = tx.send(format!("ERROR|{}", e)).await;
                            }
                        }
                    }
                }
                "user_delete" => {
                    // user_delete|username
                    if !is_admin {
                        if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                            let _ = tx.send("ERROR|Permission denied (admin only)".to_string()).await;
                        }
                        continue;
                    }
                    let pipe_parts: Vec<&str> = line.split('|').collect();
                    if pipe_parts.len() < 2 {
                        if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                            let _ = tx.send("ERROR|Usage: user_delete|username".to_string()).await;
                        }
                        continue;
                    }
                    let username = pipe_parts[1];

                    let store = state_clone.store.lock().await;
                    match store.delete_user(username) {
                        Ok(()) => {
                            if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                let _ = tx.send(format!("USER_DELETED|{}", username)).await;
                            }
                        }
                        Err(e) => {
                            if let Some(tx) = state_clone.sessions.lock().await.get(&session_id) {
                                let _ = tx.send(format!("ERROR|{}", e)).await;
                            }
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
const ADMIN_HTML: &str = include_str!("../static/admin.html");
