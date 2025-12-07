//! ONVIF Server Library
//!
//! Presents connected remote nodes as virtual ONVIF cameras to VMS systems.
//! Translates ONVIF PTZ commands to an internal command protocol.
//!
//! All endpoints require WS-Security UsernameToken authentication.

mod templates;

use axum::{
    extract::{connect_info::ConnectInfo, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Router,
};
use quick_xml::events::Event;
use quick_xml::Reader;
use rate_limiter::{RateLimitConfig, SharedIpRateLimiter};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// Maximum age of WS-Security timestamps (5 minutes)
const MAX_REQUEST_AGE_SECS: u64 = 300;

/// Handle to a connected remote node for sending commands
#[derive(Clone)]
pub struct NodeHandle {
    pub name: String,
    pub cmd_tx: mpsc::Sender<String>,
}

/// ONVIF server state
pub struct OnvifServerState {
    pub nodes: Arc<Mutex<HashMap<String, NodeHandle>>>,
    pub local_ip: String,
    pub credentials: ws_security::Credentials,
    /// Rate limiter for ONVIF requests (per-IP)
    pub rate_limiter: SharedIpRateLimiter,
}

/// Start the ONVIF HTTP server
pub async fn run_onvif_server(
    addr: SocketAddr,
    nodes: Arc<Mutex<HashMap<String, NodeHandle>>>,
    local_ip: String,
    credentials: ws_security::Credentials,
) -> anyhow::Result<()> {
    let state = Arc::new(OnvifServerState {
        nodes,
        local_ip,
        credentials,
        rate_limiter: SharedIpRateLimiter::new(RateLimitConfig::onvif()),
    });

    let app = Router::new()
        // Per-node endpoints
        .route("/onvif/{node}/device_service", post(handle_device_service))
        .route("/onvif/{node}/media_service", post(handle_media_service))
        .route("/onvif/{node}/ptz_service", post(handle_ptz_service))
        // Generic discovery endpoint
        .route("/onvif/device_service", post(handle_discovery))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("ONVIF server listening on port {}", addr.port());

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}

/// Check WS-Security authentication
fn check_auth(body: &str, state: &OnvifServerState) -> Result<(), String> {
    ws_security::authenticate(body, &state.credentials, MAX_REQUEST_AGE_SECS)
        .map_err(|e| e.to_string())
}

/// Check rate limit and return appropriate SOAP fault if exceeded
fn check_rate_limit(
    state: &OnvifServerState,
    client_ip: IpAddr,
) -> Option<(StatusCode, [(&'static str, &'static str); 1], String)> {
    if !state.rate_limiter.check(&client_ip) {
        Some((
            StatusCode::TOO_MANY_REQUESTS,
            [("Content-Type", "application/soap+xml")],
            templates::fault("ter:RateLimit", "Too many requests - please slow down"),
        ))
    } else {
        None
    }
}

/// Handle discovery requests (list all nodes)
async fn handle_discovery(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<OnvifServerState>>,
    body: String,
) -> impl IntoResponse {
    // Rate limit check
    if let Some(rate_limit_response) = check_rate_limit(&state, addr.ip()) {
        return rate_limit_response;
    }

    if let Err(reason) = check_auth(&body, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            [("Content-Type", "application/soap+xml")],
            templates::auth_fault(&reason),
        );
    }

    let action = extract_soap_action(&body);
    println!("[ONVIF] Discovery: {}", action);

    let response = match action.as_str() {
        "GetServices" => {
            let nodes = state.nodes.lock().await;
            let mut services = String::new();
            for name in nodes.keys() {
                services.push_str(&templates::service_entry(&state.local_ip, name));
            }
            templates::get_services_response(&services)
        }
        _ => templates::fault("ActionNotSupported", &format!("Unknown action: {}", action)),
    };

    (
        StatusCode::OK,
        [("Content-Type", "application/soap+xml")],
        response,
    )
}

/// Handle ONVIF Device Service requests for a specific node
async fn handle_device_service(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(node): Path<String>,
    State(state): State<Arc<OnvifServerState>>,
    body: String,
) -> impl IntoResponse {
    // Rate limit check
    if let Some(rate_limit_response) = check_rate_limit(&state, addr.ip()) {
        return rate_limit_response;
    }

    if let Err(reason) = check_auth(&body, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            [("Content-Type", "application/soap+xml")],
            templates::auth_fault(&reason),
        );
    }

    let action = extract_soap_action(&body);
    println!("[ONVIF] Device service for '{}': {}", node, action);

    let nodes = state.nodes.lock().await;
    if !nodes.contains_key(&node) {
        return (
            StatusCode::NOT_FOUND,
            [("Content-Type", "application/soap+xml")],
            templates::fault("ter:InvalidArgVal", &format!("Node '{}' not found", node)),
        );
    }
    drop(nodes);

    let response = match action.as_str() {
        "GetDeviceInformation" => templates::get_device_information(&node),
        "GetCapabilities" => templates::get_capabilities(&state.local_ip, &node),
        _ => templates::fault("ActionNotSupported", &format!("Unknown action: {}", action)),
    };

    (
        StatusCode::OK,
        [("Content-Type", "application/soap+xml")],
        response,
    )
}

/// Handle ONVIF Media Service requests for a specific node
async fn handle_media_service(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(node): Path<String>,
    State(state): State<Arc<OnvifServerState>>,
    body: String,
) -> impl IntoResponse {
    // Rate limit check
    if let Some(rate_limit_response) = check_rate_limit(&state, addr.ip()) {
        return rate_limit_response;
    }

    if let Err(reason) = check_auth(&body, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            [("Content-Type", "application/soap+xml")],
            templates::auth_fault(&reason),
        );
    }

    let action = extract_soap_action(&body);
    println!("[ONVIF] Media service for '{}': {}", node, action);

    let nodes = state.nodes.lock().await;
    if !nodes.contains_key(&node) {
        return (
            StatusCode::NOT_FOUND,
            [("Content-Type", "application/soap+xml")],
            templates::fault("ter:InvalidArgVal", &format!("Node '{}' not found", node)),
        );
    }
    drop(nodes);

    let response = match action.as_str() {
        "GetProfiles" => templates::get_profiles(&node),
        "GetStreamUri" => templates::get_stream_uri(&state.local_ip, &node),
        _ => templates::fault("ActionNotSupported", &format!("Unknown action: {}", action)),
    };

    (
        StatusCode::OK,
        [("Content-Type", "application/soap+xml")],
        response,
    )
}

/// Handle ONVIF PTZ Service requests - translates to internal protocol
async fn handle_ptz_service(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(node): Path<String>,
    State(state): State<Arc<OnvifServerState>>,
    body: String,
) -> impl IntoResponse {
    // Rate limit check
    if let Some(rate_limit_response) = check_rate_limit(&state, addr.ip()) {
        return rate_limit_response;
    }

    if let Err(reason) = check_auth(&body, &state) {
        return (
            StatusCode::UNAUTHORIZED,
            [("Content-Type", "application/soap+xml")],
            templates::auth_fault(&reason),
        );
    }

    let action = extract_soap_action(&body);
    println!("[ONVIF] PTZ service for '{}': {}", node, action);

    let nodes = state.nodes.lock().await;
    let node_handle = match nodes.get(&node) {
        Some(h) => h.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                [("Content-Type", "application/soap+xml")],
                templates::fault("ter:InvalidArgVal", &format!("Node '{}' not found", node)),
            );
        }
    };
    drop(nodes);

    let response = match action.as_str() {
        "ContinuousMove" => {
            let (pan, tilt, zoom) = extract_velocity(&body);
            println!(
                "[ONVIF->{}] ContinuousMove: pan={}, tilt={}, zoom={}",
                node, pan, tilt, zoom
            );

            let cmd = format!("CMD|ptz {} {} {}", pan, tilt, zoom);
            if let Err(e) = node_handle.cmd_tx.send(cmd).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Content-Type", "application/soap+xml")],
                    templates::fault("ter:Action", &format!("Failed to send command: {}", e)),
                );
            }
            templates::continuous_move_response().to_string()
        }

        "Stop" => {
            println!("[ONVIF->{}] Stop", node);

            let cmd = "CMD|stop".to_string();
            if let Err(e) = node_handle.cmd_tx.send(cmd).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Content-Type", "application/soap+xml")],
                    templates::fault("ter:Action", &format!("Failed to send command: {}", e)),
                );
            }
            templates::stop_response().to_string()
        }

        "AbsoluteMove" => {
            let (pan, tilt, zoom) = extract_position(&body);
            println!(
                "[ONVIF->{}] AbsoluteMove: pan={}, tilt={}, zoom={}",
                node, pan, tilt, zoom
            );

            let cmd = format!("CMD|goto {} {} {}", pan, tilt, zoom);
            if let Err(e) = node_handle.cmd_tx.send(cmd).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Content-Type", "application/soap+xml")],
                    templates::fault("ter:Action", &format!("Failed to send command: {}", e)),
                );
            }
            templates::absolute_move_response().to_string()
        }

        "GotoHomePosition" => {
            println!("[ONVIF->{}] GotoHomePosition", node);

            let cmd = "CMD|home".to_string();
            if let Err(e) = node_handle.cmd_tx.send(cmd).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("Content-Type", "application/soap+xml")],
                    templates::fault("ter:Action", &format!("Failed to send command: {}", e)),
                );
            }
            templates::goto_home_response().to_string()
        }

        "GetStatus" => {
            // TODO: Implement request-response pattern for status queries
            templates::get_status_response().to_string()
        }

        "GetConfigurations" => templates::get_configurations(&node),

        "GetNodes" => templates::get_nodes(&node),

        _ => templates::fault("ActionNotSupported", &format!("Unknown action: {}", action)),
    };

    (
        StatusCode::OK,
        [("Content-Type", "application/soap+xml")],
        response,
    )
}

/// Extract SOAP action from ONVIF request body
pub fn extract_soap_action(xml: &str) -> String {
    let mut reader = Reader::from_str(xml);
    let mut in_body = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let local_name = e.local_name();
                let name = String::from_utf8_lossy(local_name.as_ref()).to_string();

                if name == "Body" {
                    in_body = true;
                    continue;
                }

                if in_body && name != "Envelope" {
                    return name;
                }
            }
            Ok(Event::End(e)) => {
                let local_name = e.local_name();
                let name = String::from_utf8_lossy(local_name.as_ref()).to_string();
                if name == "Body" {
                    in_body = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }

    "Unknown".to_string()
}

/// Extract velocity (pan, tilt, zoom) from ONVIF ContinuousMove request
pub fn extract_velocity(xml: &str) -> (f32, f32, f32) {
    let mut pan = 0.0f32;
    let mut tilt = 0.0f32;
    let mut zoom = 0.0f32;

    let mut reader = Reader::from_str(xml);

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let local_name = e.local_name();
                let name = String::from_utf8_lossy(local_name.as_ref());

                if name == "PanTilt" {
                    for attr in e.attributes().flatten() {
                        let key_local = attr.key.local_name();
                        let key = String::from_utf8_lossy(key_local.as_ref());
                        if key == "x" {
                            if let Ok(v) = attr.unescape_value() {
                                pan = v.parse().unwrap_or(0.0);
                            }
                        } else if key == "y" {
                            if let Ok(v) = attr.unescape_value() {
                                tilt = v.parse().unwrap_or(0.0);
                            }
                        }
                    }
                } else if name == "Zoom" {
                    for attr in e.attributes().flatten() {
                        let key_local = attr.key.local_name();
                        let key = String::from_utf8_lossy(key_local.as_ref());
                        if key == "x" {
                            if let Ok(v) = attr.unescape_value() {
                                zoom = v.parse().unwrap_or(0.0);
                            }
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }

    (pan, tilt, zoom)
}

/// Extract position from ONVIF AbsoluteMove request (same format as velocity)
pub fn extract_position(xml: &str) -> (f32, f32, f32) {
    extract_velocity(xml)
}

/// Get the local IP address by connecting to an external address
pub fn get_local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}
