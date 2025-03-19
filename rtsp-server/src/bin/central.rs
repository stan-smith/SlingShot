use admin_web::{broadcast, request_approval, run_admin_server, AdminCommand, AdminState};
use anyhow::Result;
use gstreamer::prelude::*;
use gstreamer_app::AppSrc;
use gstreamer_rtsp_server::prelude::*;
use onvif_server::{get_local_ip, run_onvif_server, NodeHandle};
use quinn::{Endpoint, ServerConfig};
use std::collections::HashMap;
use std::env;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Central Node - RTSP Stream Controller
///
/// - Accepts QUIC connections from remote video nodes
/// - Receives video over QUIC and serves via local RTSP
/// - Sends commands to control stream parameters (resolution, bitrate, framerate)
struct RemoteNode {
    address: SocketAddr,
    fingerprint: String,
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
                                println!("    Video: QUIC stream");
                                println!("    Local RTSP: rtsp://127.0.0.1:8554/{}/stream", name);
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

    // Receive authentication request: AUTH|name|fingerprint|VIDEO
    let mut recv_stream = connection.accept_uni().await?;
    let buffer = recv_stream.read_to_end(1024 * 1024).await?;
    let message = String::from_utf8_lossy(&buffer);

    if !message.starts_with("AUTH|") {
        println!("Invalid auth format from {}", remote);
        return Ok(());
    }

    let parts: Vec<&str> = message.split('|').collect();
    if parts.len() != 4 {
        println!("Malformed auth from {} (expected AUTH|name|fingerprint|VIDEO)", remote);
        return Ok(());
    }

    let node_name = parts[1].to_string();
    let fingerprint = parts[2].to_string();
    let video_mode = parts[3] == "VIDEO";

    println!("==========================================");
    println!("AUTHENTICATION REQUEST");
    println!("  Node: {}", node_name);
    println!("  Address: {}", remote);
    println!("  Fingerprint: {}", &fingerprint[..32.min(fingerprint.len())]);
    println!("  Video Mode: {}", if video_mode { "QUIC" } else { "Legacy RTSP" });
    println!("==========================================");

    // Request approval via admin web interface
    let approved = request_approval(
        &admin_state,
        node_name.clone(),
        fingerprint.clone(),
        format!("Video over QUIC from {}", remote),
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

        // Wait for VIDEO_START stream
        let mut video_stream = connection.accept_uni().await?;

        // Read the first bytes to check for VIDEO_START marker
        let mut marker_buf = [0u8; 11]; // "VIDEO_START".len()
        video_stream.read_exact(&mut marker_buf).await?;
        if &marker_buf != b"VIDEO_START" {
            println!("Expected VIDEO_START marker from {}", node_name);
            return Ok(());
        }

        println!("Video stream established from {}", node_name);

        // Create RTSP factory with appsrc for this node
        let mount_path = format!("/{}/stream", node_name);

        // Channel for video frames (shared with RTSP factory)
        let frame_tx: Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<quic_video::VideoFrame>>>> =
            Arc::new(std::sync::Mutex::new(None));
        let frame_tx_clone = Arc::clone(&frame_tx);

        // Create factory with appsrc pipeline
        // Using do-timestamp=true lets GStreamer handle timestamps based on buffer arrival,
        // which is more robust for live streaming than manual PTS setting
        let factory = gstreamer_rtsp_server::RTSPMediaFactory::new();
        factory.set_launch(
            "( appsrc name=videosrc is-live=true format=time do-timestamp=true \
               caps=video/x-h264,stream-format=byte-stream,alignment=au \
               ! h264parse \
               ! rtph264pay name=pay0 pt=96 )",
        );
        factory.set_shared(true);

        // Get appsrc when media is configured
        factory.connect_media_configure(move |_factory, media| {
            let element = media.element();
            if let Some(bin) = element.downcast_ref::<gstreamer::Bin>() {
                if let Some(appsrc_elem) = bin.by_name("videosrc") {
                    let appsrc = appsrc_elem.dynamic_cast::<AppSrc>().unwrap();

                    // Create a sync channel for this media instance
                    let (tx, rx) = std::sync::mpsc::channel::<quic_video::VideoFrame>();

                    // Store sender so we can forward frames to it
                    *frame_tx_clone.lock().unwrap() = Some(tx);

                    // Spawn thread to push frames to appsrc
                    // With do-timestamp=true, GStreamer handles timestamps based on arrival time
                    std::thread::spawn(move || {
                        let mut waiting_for_keyframe = true;
                        let mut pushed = 0u64;

                        println!("  [appsrc] Thread started, waiting for keyframe");

                        while let Ok(frame) = rx.recv() {
                            // Wait for keyframe before starting playback for smoother start
                            if waiting_for_keyframe {
                                if !frame.is_keyframe {
                                    continue;
                                }
                                waiting_for_keyframe = false;
                                println!("  [appsrc] Got keyframe, starting playback");
                            }

                            // Create buffer - do_timestamp=true handles PTS
                            let mut buffer = gstreamer::Buffer::from_slice(frame.data.clone());
                            {
                                let buffer_ref = buffer.get_mut().unwrap();
                                if !frame.is_keyframe {
                                    buffer_ref.set_flags(gstreamer::BufferFlags::DELTA_UNIT);
                                }
                            }

                            match appsrc.push_buffer(buffer) {
                                Ok(_) => {
                                    pushed += 1;
                                    if pushed % 30 == 0 {
                                        println!("  [appsrc] Pushed {} buffers", pushed);
                                    }
                                }
                                Err(e) => {
                                    println!("  [appsrc] Push error: {:?}, exiting after {} buffers", e, pushed);
                                    break;
                                }
                            }
                        }
                        println!("  [appsrc] Thread exiting after {} buffers", pushed);
                    });

                    println!("RTSP media configured with appsrc for {}", media.element().name());
                }
            }
        });

        mounts.add_factory(&mount_path, factory);
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

        // Spawn video receiver task
        let node_name_video = node_name.clone();
        let video_handle = tokio::spawn(async move {
            let mut buffer = Vec::new();
            let mut frame_count = 0u64;
            let mut bytes_received = 0u64;
            let mut crc_errors = 0u64;
            let start = std::time::Instant::now();
            let mut seq_tracker = quic_video::SequenceTracker::new();

            // Helper to read more data into buffer
            async fn read_more(buffer: &mut Vec<u8>, video_stream: &mut quinn::RecvStream, node_name: &str) -> bool {
                match video_stream.read_chunk(4096, false).await {
                    Ok(Some(chunk)) => {
                        buffer.extend_from_slice(&chunk.bytes);
                        true
                    }
                    Ok(None) => {
                        println!("[{}] Video stream ended", node_name);
                        false
                    }
                    Err(e) => {
                        println!("[{}] Video stream error: {}", node_name, e);
                        false
                    }
                }
            }

            loop {
                // Read until we have at least 4 bytes (length prefix)
                while buffer.len() < 4 {
                    if !read_more(&mut buffer, &mut video_stream, &node_name_video).await {
                        return;
                    }
                }

                let frame_len = u32::from_be_bytes(buffer[..4].try_into().unwrap()) as usize;

                // Sanity check frame length - if impossible, stream is corrupted beyond recovery
                if frame_len > 10_000_000 || frame_len < 29 {
                    eprintln!("[{}] FRAME DESYNC at frame {}: frame_len={} invalid (expected 29-10M)",
                        node_name_video, frame_count, frame_len);
                    eprintln!("[{}] Length bytes: {:02X?}", node_name_video, &buffer[..4]);
                    eprintln!("[{}] Buffer[0..32]: {:02X?}", node_name_video, &buffer[..buffer.len().min(32)]);
                    eprintln!("[{}] Total bytes received so far: {}", node_name_video, bytes_received);
                    return; // Close stream - remote will reconnect
                }
                buffer.drain(..4);

                // Read frame data
                while buffer.len() < frame_len {
                    if !read_more(&mut buffer, &mut video_stream, &node_name_video).await {
                        return;
                    }
                }
                let frame_data: Vec<u8> = buffer.drain(..frame_len).collect();

                // Decode frame (includes CRC32 validation)
                let frame = match quic_video::VideoFrame::decode(&frame_data) {
                    Ok(f) => {
                        // Log for debugging - match sender's logging pattern
                        if frame_count < 5 || frame_count % 500 == 0 || f.sequence > 2630 {
                            eprintln!("[RECV:{}] seq={} len={} first8={:02X?}",
                                node_name_video, f.sequence, frame_len, &frame_data[..8.min(frame_data.len())]);
                        }
                        f
                    }
                    Err(quic_video::DecodeError::ChecksumMismatch { expected, actual, sequence }) => {
                        crc_errors += 1;
                        eprintln!("[{}] CRC MISMATCH at frame {}: seq={}, expected 0x{:08X}, got 0x{:08X}",
                            node_name_video, frame_count, sequence, expected, actual);
                        eprintln!("[{}] Frame len was {}, data starts: {:02X?}",
                            node_name_video, frame_len, &frame_data[..frame_data.len().min(32)]);
                        continue; // Skip this frame, try next
                    }
                    Err(e) => {
                        eprintln!("[{}] Failed to decode frame: {} (frame_len={})", node_name_video, e, frame_len);
                        continue;
                    }
                };

                // Check sequence for gaps
                if let Some(gap) = seq_tracker.check(frame.sequence) {
                    eprintln!("[{}] SEQUENCE GAP: expected seq {}, got {} (gap of {} frames)",
                        node_name_video,
                        frame.sequence.wrapping_sub(gap),
                        frame.sequence,
                        gap);
                }

                frame_count += 1;
                bytes_received += (4 + frame_len) as u64; // 4 len + data

                // Send to RTSP pipeline
                if let Some(tx) = frame_tx.lock().unwrap().as_ref() {
                    let _ = tx.send(frame.clone());
                }

                // Print stats every 30 frames
                if frame_count % 30 == 0 {
                    let elapsed = start.elapsed().as_secs_f64();
                    let mbps = (bytes_received as f64 * 8.0) / (elapsed * 1_000_000.0);
                    let integrity_status = if crc_errors > 0 || seq_tracker.gaps_detected() > 0 {
                        format!(" [CRC:{} GAPS:{}]", crc_errors, seq_tracker.gaps_detected())
                    } else {
                        String::new()
                    };
                    println!(
                        "[{}] Received {} frames, {:.1} MB, {:.2} Mbps{}{}",
                        node_name_video,
                        frame_count,
                        bytes_received as f64 / 1_000_000.0,
                        mbps,
                        if frame.is_keyframe { " [KEY]" } else { "" },
                        integrity_status
                    );
                }
            }
        });

        // Command/response loop
        let mut stats_interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                // Log QUIC connection stats
                _ = stats_interval.tick() => {
                    quic_metrics::log_stats(&connection, &node_name);
                }

                // Send commands to remote
                Some(cmd) = cmd_rx.recv() => {
                    let mut send_stream = connection.open_uni().await?;
                    send_stream.write_all(cmd.as_bytes()).await?;
                    send_stream.finish()?;
                }

                // Receive responses from remote (commands only, video is handled separately)
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

        // Cancel video receiver when disconnected
        video_handle.abort();

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
