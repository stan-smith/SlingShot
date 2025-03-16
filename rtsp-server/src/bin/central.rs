use admin_web::{broadcast, request_approval, run_admin_server, AdminCommand, AdminState};
use anyhow::Result;
use gstreamer_rtsp_server::prelude::*;
use onvif_server::{get_local_ip, run_onvif_server, NodeHandle};
use quinn::{Endpoint, ServerConfig};
use std::collections::HashMap;
use std::env;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Central Node - RTSP Stream Controller & Relay
///
/// - Accepts QUIC connections from remote RTSP server nodes
/// - Relays their RTSP streams locally on node-specific paths
/// - Sends commands to control stream parameters (resolution, bitrate, framerate)
struct RemoteNode {
    address: SocketAddr,
    fingerprint: String,
    rtsp_url: String,
    cmd_tx: mpsc::Sender<String>,
}

fn main() -> Result<()> {
    // Initialize GStreamer
    gstreamer::init()?;

    // Run async runtime
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Parse CLI arguments
    let args: Vec<String> = env::args().collect();
    let headless = args.iter().any(|a| a == "--headless");
    let admin_port: u16 = args
        .iter()
        .position(|a| a == "--admin-port")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(8081);

    println!("==========================================");
    println!("RTSP STREAM CONTROLLER - Central Node");
    println!("==========================================");
    println!();

    // Create RTSP server for relaying streams
    let rtsp_server = gstreamer_rtsp_server::RTSPServer::new();
    rtsp_server.set_service("8554");
    let mounts = rtsp_server.mount_points().expect("Failed to get mount points");
    let mounts = Arc::new(mounts);

    // Run GLib main loop and RTSP server in a separate thread
    let main_loop = glib::MainLoop::new(None, false);
    let main_loop_clone = main_loop.clone();
    std::thread::spawn(move || {
        let _rtsp_id = rtsp_server.attach(None).expect("Failed to attach RTSP server");
        main_loop_clone.run();
    });

    // Give the GLib loop a moment to start
    std::thread::sleep(std::time::Duration::from_millis(100));

    println!("RTSP relay server listening on port 8554");

    // Generate self-signed Ed25519 certificate for QUIC
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let cert_params = rcgen::CertificateParams::new(vec![
        "localhost".to_string(),
        "0.0.0.0".to_string(),
    ])?;
    let cert = cert_params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let cert_chain = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {}", e))?;

    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse key: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("No private key found"))?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    server_crypto.alpn_protocols = vec![];

    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_uni_streams(100_u8.into());
    transport_config.max_concurrent_bidi_streams(100_u8.into());
    // Keep connection alive indefinitely
    transport_config.max_idle_timeout(None);
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    server_config.transport_config(Arc::new(transport_config));

    let bind_addr: SocketAddr = "0.0.0.0:5001".parse()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;

    println!("QUIC control server listening on port 5001");
    println!("Admin web interface at http://127.0.0.1:{}", admin_port);
    if headless {
        println!("Running in headless mode (no stdin)");
    }
    println!();
    print_help();
    println!();

    // Shared state for connected nodes
    let nodes: Arc<tokio::sync::Mutex<HashMap<String, RemoteNode>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    // ONVIF node handles (shared with ONVIF server)
    let onvif_nodes: Arc<tokio::sync::Mutex<HashMap<String, NodeHandle>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    // Share mounts for adding relay factories
    // Get local IP for ONVIF server
    let local_ip = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());

    // Start ONVIF server
    let onvif_addr: SocketAddr = "0.0.0.0:8080".parse()?;
    let onvif_nodes_clone = Arc::clone(&onvif_nodes);
    tokio::spawn(async move {
        if let Err(e) = run_onvif_server(onvif_addr, onvif_nodes_clone, local_ip).await {
            eprintln!("ONVIF server error: {}", e);
        }
    });

    // Create admin state and channel
    let (admin_cmd_tx, mut admin_cmd_rx) = mpsc::channel::<AdminCommand>(100);
    let admin_state = Arc::new(AdminState::new(admin_cmd_tx));

    // Start admin web server
    let admin_state_clone = Arc::clone(&admin_state);
    tokio::spawn(async move {
        if let Err(e) = run_admin_server(admin_port, admin_state_clone).await {
            eprintln!("Admin server error: {}", e);
        }
    });

    // Channel for user input commands
    let (input_tx, mut input_rx) = mpsc::channel::<String>(100);

    // Spawn input reader thread (only if not headless)
    if !headless {
        std::thread::spawn(move || {
            let stdin = io::stdin();
            let mut stdout = io::stdout();

            loop {
                print!("> ");
                stdout.flush().unwrap();

                let mut line = String::new();
                if stdin.lock().read_line(&mut line).unwrap() == 0 {
                    break;
                }
                let _ = input_tx.blocking_send(line.trim().to_string());
            }
        });
    }

    // Spawn connection acceptor
    let nodes_clone = Arc::clone(&nodes);
    let onvif_nodes_clone = Arc::clone(&onvif_nodes);
    let mounts_clone = Arc::clone(&mounts);
    let admin_state_conn = Arc::clone(&admin_state);
    let endpoint_clone = endpoint.clone();
    tokio::spawn(async move {
        loop {
            if let Some(incoming) = endpoint_clone.accept().await {
                let nodes = Arc::clone(&nodes_clone);
                let onvif_nodes = Arc::clone(&onvif_nodes_clone);
                let mounts = Arc::clone(&mounts_clone);
                let admin_state = Arc::clone(&admin_state_conn);
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_connection(incoming, nodes, onvif_nodes, mounts, admin_state).await
                    {
                        eprintln!("Connection error: {}", e);
                    }
                });
            }
        }
    });

    // Main command loop - handle both stdin and admin web commands
    loop {
        tokio::select! {
            // Handle admin web commands
            Some(admin_cmd) = admin_cmd_rx.recv() => {
                let line = admin_cmd.raw_line;
                let response = process_command(&line, &nodes, &admin_state).await;
                if let Some(resp) = response {
                    broadcast(&admin_state, &resp).await;
                }
            }

            // Handle stdin commands (only active if not headless)
            Some(line) = input_rx.recv() => {
                if line.is_empty() {
                    continue;
                }

                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }

                match parts[0].to_lowercase().as_str() {
                    "nodes" | "list" => {
                        let nodes = nodes.lock().await;
                        if nodes.is_empty() {
                            println!("No remote nodes connected");
                        } else {
                            println!("Connected nodes:");
                            for (name, node) in nodes.iter() {
                                println!("  {} - {} ({})", name, node.address, &node.fingerprint[..16]);
                                println!("    Remote RTSP: {}", node.rtsp_url);
                                println!("    Local relay: rtsp://127.0.0.1:8554/{}/stream", name);
                            }
                        }
                    }
                    "help" | "h" | "?" => {
                        print_help();
                    }
                    "quit" | "exit" | "q" => {
                        println!("Shutting down...");
                        main_loop.quit();
                        break;
                    }
                    node_name => {
                        // Commands directed at a specific node
                        if parts.len() < 2 {
                            println!("Usage: <node> <command> [args...]");
                            continue;
                        }

                        let nodes = nodes.lock().await;
                        if let Some(node) = nodes.get(node_name) {
                            let cmd = parts[1..].join(" ");
                            let msg = format!("CMD|{}", cmd);
                            if let Err(e) = node.cmd_tx.send(msg).await {
                                eprintln!("Failed to send command: {}", e);
                            }
                        } else {
                            println!("Unknown node: {}", node_name);
                            println!("Use 'nodes' to list connected nodes");
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Process a command from admin web interface
async fn process_command(
    line: &str,
    nodes: &Arc<tokio::sync::Mutex<HashMap<String, RemoteNode>>>,
    _admin_state: &Arc<AdminState>,
) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    match parts[0].to_lowercase().as_str() {
        "nodes" | "list" => {
            let nodes = nodes.lock().await;
            if nodes.is_empty() {
                Some("No remote nodes connected".to_string())
            } else {
                let mut response = String::from("Connected nodes:\n");
                for (name, node) in nodes.iter() {
                    response.push_str(&format!(
                        "  {} - {} ({})\n",
                        name,
                        node.address,
                        &node.fingerprint[..16]
                    ));
                }
                Some(response)
            }
        }
        node_name => {
            if parts.len() < 2 {
                return Some("Usage: <node> <command> [args...]".to_string());
            }

            let nodes = nodes.lock().await;
            if let Some(node) = nodes.get(node_name) {
                let cmd = parts[1..].join(" ");
                let msg = format!("CMD|{}", cmd);
                if let Err(e) = node.cmd_tx.send(msg).await {
                    Some(format!("Failed to send command: {}", e))
                } else {
                    None // Response will come via node's response handler
                }
            } else {
                Some(format!("Unknown node: {}", node_name))
            }
        }
    }
}

async fn handle_connection(
    incoming: quinn::Incoming,
    nodes: Arc<tokio::sync::Mutex<HashMap<String, RemoteNode>>>,
    onvif_nodes: Arc<tokio::sync::Mutex<HashMap<String, NodeHandle>>>,
    mounts: Arc<gstreamer_rtsp_server::RTSPMountPoints>,
    admin_state: Arc<AdminState>,
) -> Result<()> {
    let connection = incoming.await?;
    let remote = connection.remote_address();

    println!("\n[New connection from {}]", remote);

    // Receive authentication request: AUTH|name|fingerprint|rtsp_url
    let mut recv_stream = connection.accept_uni().await?;
    let buffer = recv_stream.read_to_end(1024 * 1024).await?;
    let message = String::from_utf8_lossy(&buffer);

    if !message.starts_with("AUTH|") {
        println!("Invalid auth format from {}", remote);
        return Ok(());
    }

    let parts: Vec<&str> = message.split('|').collect();
    if parts.len() != 4 {
        println!("Malformed auth from {} (expected AUTH|name|fingerprint|rtsp_url)", remote);
        return Ok(());
    }

    let node_name = parts[1].to_string();
    let fingerprint = parts[2].to_string();
    let rtsp_url = parts[3].to_string();

    println!("==========================================");
    println!("AUTHENTICATION REQUEST");
    println!("  Node: {}", node_name);
    println!("  Address: {}", remote);
    println!("  Fingerprint: {}", &fingerprint[..32.min(fingerprint.len())]);
    println!("  RTSP URL: {}", rtsp_url);
    println!("==========================================");

    // Request approval via admin web interface
    let approved = request_approval(
        &admin_state,
        node_name.clone(),
        fingerprint.clone(),
        rtsp_url.clone(),
        remote.to_string(),
    )
    .await;

    let mut send_stream = connection.open_uni().await?;

    if approved {
        let response = format!("APPROVED|Welcome, {}!", node_name);
        send_stream.write_all(response.as_bytes()).await?;
        send_stream.finish()?;

        println!("Approved {}", node_name);

        // Wait for confirmation
        let mut confirm_stream = connection.accept_uni().await?;
        let confirm_buffer = confirm_stream.read_to_end(1024 * 1024).await?;
        let confirmation = String::from_utf8_lossy(&confirm_buffer);

        if confirmation.starts_with("CONFIRM|") {
            println!("Node {} confirmed and ready", node_name);
        }

        // Create RTSP relay factory for this node
        let mount_path = format!("/{}/stream", node_name);
        create_relay_factory(&mounts, &mount_path, &rtsp_url)?;
        println!("RTSP relay created at rtsp://127.0.0.1:8554{}", mount_path);

        // Create command channel for this node
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<String>(100);

        // Store node in main registry
        {
            let mut nodes = nodes.lock().await;
            nodes.insert(
                node_name.clone(),
                RemoteNode {
                    address: remote,
                    fingerprint: fingerprint.clone(),
                    rtsp_url: rtsp_url.clone(),
                    cmd_tx: cmd_tx.clone(),
                },
            );
        }

        // Also register with ONVIF server
        {
            let mut onvif = onvif_nodes.lock().await;
            onvif.insert(
                node_name.clone(),
                NodeHandle {
                    name: node_name.clone(),
                    cmd_tx: cmd_tx.clone(),
                },
            );
        }

        println!("Node '{}' connected. Commands: '<node> <cmd>'", node_name);
        println!("ONVIF PTZ available at: http://localhost:8080/onvif/{}/ptz_service", node_name);
        println!();

        // Notify admin clients
        broadcast(&admin_state, &format!("CONNECTED|{}", node_name)).await;

        // Command/response loop
        loop {
            tokio::select! {
                // Send commands to remote
                Some(cmd) = cmd_rx.recv() => {
                    let mut send_stream = connection.open_uni().await?;
                    send_stream.write_all(cmd.as_bytes()).await?;
                    send_stream.finish()?;
                }

                // Receive responses from remote
                result = connection.accept_uni() => {
                    match result {
                        Ok(mut recv_stream) => {
                            let buffer = recv_stream.read_to_end(1024 * 1024).await?;
                            let msg = String::from_utf8_lossy(&buffer);

                            let broadcast_msg = if msg.starts_with("RESULT|") {
                                let parts: Vec<&str> = msg.splitn(3, '|').collect();
                                if parts.len() >= 3 {
                                    let status = parts[1];
                                    let data = parts[2];
                                    if status == "ok" {
                                        println!("[{}] {}", node_name, data);
                                        Some(format!("[{}] {}", node_name, data))
                                    } else {
                                        println!("[{}] Error: {}", node_name, data);
                                        Some(format!("[{}] Error: {}", node_name, data))
                                    }
                                } else {
                                    None
                                }
                            } else if msg.starts_with("STATUS|") {
                                let parts: Vec<&str> = msg.splitn(2, '|').collect();
                                if parts.len() >= 2 {
                                    println!("[{}] Status: {}", node_name, parts[1]);
                                    Some(format!("[{}] Status: {}", node_name, parts[1]))
                                } else {
                                    None
                                }
                            } else {
                                None
                            };

                            // Broadcast to admin clients
                            if let Some(msg) = broadcast_msg {
                                broadcast(&admin_state, &msg).await;
                            }

                            print!("> ");
                            io::stdout().flush().unwrap();
                        }
                        Err(e) => {
                            println!("\n[{}] Disconnected: {}", node_name, e);
                            break;
                        }
                    }
                }
            }
        }

        // Remove relay and node on disconnect
        mounts.remove_factory(&mount_path);
        {
            let mut nodes = nodes.lock().await;
            nodes.remove(&node_name);
        }
        {
            let mut onvif = onvif_nodes.lock().await;
            onvif.remove(&node_name);
        }
        println!("Node '{}' removed, relay stopped", node_name);

        // Notify admin clients
        broadcast(&admin_state, &format!("DISCONNECTED|{}", node_name)).await;
    } else {
        let response = "DENIED|Access denied".to_string();
        send_stream.write_all(response.as_bytes()).await?;
        send_stream.finish()?;
        println!("Denied {}", node_name);
    }

    Ok(())
}

fn create_relay_factory(
    mounts: &gstreamer_rtsp_server::RTSPMountPoints,
    mount_path: &str,
    source_rtsp_url: &str,
) -> Result<()> {
    let factory = gstreamer_rtsp_server::RTSPMediaFactory::new();

    // Pipeline: pull from remote RTSP, re-encode, and serve
    // Using rtspsrc to pull, then depay/decode, re-encode and pay
    let pipeline = format!(
        "( rtspsrc location={} latency=100 \
           ! rtph264depay \
           ! h264parse \
           ! rtph264pay name=pay0 pt=96 )",
        source_rtsp_url
    );

    factory.set_launch(&pipeline);
    factory.set_shared(true);

    mounts.add_factory(mount_path, factory);

    Ok(())
}

fn print_help() {
    println!("Commands:");
    println!("  nodes                        - List connected nodes with RTSP URLs");
    println!();
    println!("Stream Control:");
    println!("  <node> res <w> <h>           - Set resolution (e.g., khadas res 1280 720)");
    println!("  <node> bitrate <kbps>        - Set bitrate (e.g., khadas bitrate 2000)");
    println!("  <node> fps <rate>            - Set framerate (e.g., khadas fps 15)");
    println!("  <node> params                - Show current stream parameters");
    println!();
    println!("PTZ Control:");
    println!("  <node> left [speed] [ms]     - Pan left (e.g., khadas left 0.5 500)");
    println!("  <node> right [speed] [ms]    - Pan right");
    println!("  <node> up [speed] [ms]       - Tilt up");
    println!("  <node> down [speed] [ms]     - Tilt down");
    println!("  <node> zoomin [speed] [ms]   - Zoom in (alias: zi)");
    println!("  <node> zoomout [speed] [ms]  - Zoom out (alias: zo)");
    println!("  <node> ptz <p> <t> [z] [ms]  - Custom PTZ move");
    println!("  <node> goto <p> <t> <z>      - Go to absolute position");
    println!("  <node> home                  - Return to home position");
    println!("  <node> stop                  - Stop PTZ movement");
    println!("  <node> status                - Get PTZ position");
    println!("  <node> info                  - Get camera info");
    println!();
    println!("  help                         - Show this help");
    println!("  quit                         - Exit");
    println!();
    println!("Relayed streams: rtsp://127.0.0.1:8554/<node>/stream");
    println!("ONVIF PTZ:       http://127.0.0.1:8080/onvif/<node>/ptz_service");
    println!();
    println!("Options:");
    println!("  --headless                   - Run without stdin (admin via web only)");
    println!("  --admin-port <port>          - Admin web port (default: 8081)");
}
