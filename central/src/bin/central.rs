use admin_web::{broadcast, request_approval, run_admin_server, AdminCommand, AdminState};
use anyhow::Result;
use config_manager::CentralConfig;
use fingerprint_store::FingerprintStore;
use gstreamer::prelude::*;
use gstreamer_app::AppSrc;
use gstreamer_rtsp_server::prelude::*;
use onvif_server::{get_local_ip, run_onvif_server, NodeHandle};
use quinn::{Endpoint, ServerConfig};
use recording_retrieval::{
    decode_message_type, format_size, FileChunk, FileComplete, FileHeader, FileMessageType,
    FileTransferReceiver, TransferComplete, TransferError, FILE_TRANSFER_MAGIC,
};
use std::collections::HashMap;
use std::env;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
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

    // Load configuration (require config file to exist)
    let config = match CentralConfig::load() {
        Ok(c) => c,
        Err(_) => {
            eprintln!("No configuration found.");
            eprintln!();
            eprintln!("Run 'kaiju-central-setup' to configure network bindings before starting.");
            std::process::exit(1);
        }
    };

    // Initialize fingerprint store for auto-approval
    let fingerprint_store = match FingerprintStore::open() {
        Ok(store) => {
            if let Ok(path) = FingerprintStore::default_path() {
                println!("Fingerprint store: {}", path.display());
            }
            Arc::new(tokio::sync::Mutex::new(store))
        }
        Err(e) => {
            eprintln!("Warning: Could not open fingerprint store: {}", e);
            eprintln!("Auto-approval for known nodes will be disabled.");
            // Use in-memory store as fallback
            Arc::new(tokio::sync::Mutex::new(
                FingerprintStore::open_at(std::path::Path::new(":memory:"))
                    .expect("Failed to create in-memory store"),
            ))
        }
    };

    println!("==========================================");
    println!("RTSP STREAM CONTROLLER - Central Node");
    println!("==========================================");
    println!();

    // Create RTSP server for relaying streams
    let rtsp_server = gstreamer_rtsp_server::RTSPServer::new();
    rtsp_server.set_service(&config.rtsp_port.to_string());
    // Note: gstreamer-rtsp-server binds to 0.0.0.0 by default and doesn't support
    // binding to specific interfaces easily. We set the port from config.
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

    println!("RTSP relay server listening on port {}", config.rtsp_port);

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
    server_config.transport_config(Arc::new(quic_common::video_transport_config()));

    // Bind QUIC server to first configured interface (QUIC/quinn only supports one endpoint)
    let quic_bind = config.quic_addrs().into_iter().next()
        .unwrap_or_else(|| format!("0.0.0.0:{}", config.quic_port));
    let bind_addr: SocketAddr = quic_bind.parse()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;

    println!("QUIC control server listening on {}", bind_addr);

    // Print admin web endpoint
    if let Some(addr) = config.admin_addrs().into_iter().next() {
        println!("Admin web interface at http://{}", addr);
    }
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

    // Get local IP for ONVIF server
    let local_ip = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());

    // Start ONVIF server
    let onvif_addr: SocketAddr = config.onvif_addrs().into_iter().next()
        .unwrap_or_else(|| format!("0.0.0.0:{}", config.onvif_port))
        .parse()?;
    let onvif_nodes_clone = Arc::clone(&onvif_nodes);
    tokio::spawn(async move {
        if let Err(e) = run_onvif_server(onvif_addr, onvif_nodes_clone, local_ip).await {
            eprintln!("ONVIF server error: {}", e);
        }
    });
    println!("ONVIF server listening on http://{}", onvif_addr);

    // Create admin state and channel
    let (admin_cmd_tx, mut admin_cmd_rx) = mpsc::channel::<AdminCommand>(100);
    let admin_state = Arc::new(AdminState::new(admin_cmd_tx));

    // Start admin web server
    let admin_addr = config.admin_addrs().into_iter().next()
        .unwrap_or_else(|| format!("0.0.0.0:{}", config.admin_port));
    let admin_state_clone = Arc::clone(&admin_state);
    tokio::spawn(async move {
        if let Err(e) = run_admin_server(&admin_addr, admin_state_clone).await {
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
    let fingerprint_store_conn = Arc::clone(&fingerprint_store);
    let endpoint_clone = endpoint.clone();
    tokio::spawn(async move {
        loop {
            if let Some(incoming) = endpoint_clone.accept().await {
                let nodes = Arc::clone(&nodes_clone);
                let onvif_nodes = Arc::clone(&onvif_nodes_clone);
                let mounts = Arc::clone(&mounts_clone);
                let admin_state = Arc::clone(&admin_state_conn);
                let fp_store = Arc::clone(&fingerprint_store_conn);
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_connection(incoming, nodes, onvif_nodes, mounts, admin_state, fp_store).await
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
    fingerprint_store: Arc<tokio::sync::Mutex<FingerprintStore>>,
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
    if parts.len() < 4 || parts.len() > 5 {
        println!("Malformed auth from {} (expected AUTH|name|fingerprint|VIDEO[|ENCRYPT/NOENC])", remote);
        return Ok(());
    }

    let node_name = parts[1].to_string();
    let fingerprint = parts[2].to_string();
    let video_mode = parts[3] == "VIDEO";
    let encryption_requested = parts.get(4).map(|&s| s == "ENCRYPT").unwrap_or(false);

    println!("==========================================");
    println!("AUTHENTICATION REQUEST");
    println!("  Node: {}", node_name);
    println!("  Address: {}", remote);
    println!("  Fingerprint: {}", &fingerprint[..32.min(fingerprint.len())]);
    println!("  Video Mode: {}", if video_mode { "QUIC" } else { "Legacy RTSP" });
    println!("  Encryption: {}", if encryption_requested { "requested" } else { "not requested" });
    println!("==========================================");

    // Check if fingerprint is already approved
    let approved = {
        let store = fingerprint_store.lock().await;
        match store.is_approved(&fingerprint) {
            Ok(Some(existing)) => {
                // Previously approved node reconnecting
                println!(
                    "Auto-approving known node '{}' (fingerprint: {}...)",
                    existing.node_name,
                    &fingerprint[..16.min(fingerprint.len())]
                );
                // Update last_seen timestamp
                if let Err(e) = store.update_last_seen(&fingerprint) {
                    eprintln!("Warning: Could not update last_seen: {}", e);
                }
                true
            }
            Ok(None) => {
                // New node - needs manual approval
                drop(store); // Release lock before blocking on approval
                let manual_approved = request_approval(
                    &admin_state,
                    node_name.clone(),
                    fingerprint.clone(),
                    format!("Video over QUIC from {}", remote),
                    remote.to_string(),
                )
                .await;

                if manual_approved {
                    // Store the newly approved fingerprint
                    let store = fingerprint_store.lock().await;
                    if let Err(e) = store.approve(&fingerprint, &node_name, Some("admin")) {
                        eprintln!("Warning: Could not store approved fingerprint: {}", e);
                    } else {
                        println!(
                            "Stored fingerprint for '{}' in approved nodes database",
                            node_name
                        );
                    }
                }
                manual_approved
            }
            Err(e) => {
                eprintln!("Warning: Could not check fingerprint store: {}", e);
                // Fall back to manual approval on error
                drop(store);
                request_approval(
                    &admin_state,
                    node_name.clone(),
                    fingerprint.clone(),
                    format!("Video over QUIC from {}", remote),
                    remote.to_string(),
                )
                .await
            }
        }
    };

    let mut send_stream = connection.open_uni().await?;

    if approved {
        // Generate encryption key if requested
        let encryption_pubkey = if encryption_requested {
            let store = fingerprint_store.lock().await;
            match store.generate_encryption_key(&fingerprint) {
                Ok(pubkey) => {
                    println!("Generated/retrieved encryption key for {}", node_name);
                    Some(pubkey)
                }
                Err(e) => {
                    eprintln!("Warning: Failed to generate encryption key: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Build response: APPROVED|message or APPROVED|message|pubkey_hex
        let response = if let Some(ref pubkey) = encryption_pubkey {
            format!("APPROVED|Welcome, {}!|{}", node_name, pubkey)
        } else {
            format!("APPROVED|Welcome, {}!", node_name)
        };
        send_stream.write_all(response.as_bytes()).await?;
        send_stream.finish()?;

        println!("Approved {} (encryption: {})", node_name, if encryption_pubkey.is_some() { "enabled" } else { "disabled" });

        // Wait for confirmation
        let mut confirm_stream = connection.accept_uni().await?;
        let confirm_buffer = confirm_stream.read_to_end(1024 * 1024).await?;
        let confirmation = String::from_utf8_lossy(&confirm_buffer);

        if confirmation.starts_with("CONFIRM|") {
            println!("Node {} confirmed and ready", node_name);
        }

        // Wait for VIDEO_STREAM marker
        let mut marker_stream = connection.accept_uni().await?;
        let marker = marker_stream.read_to_end(64).await?;
        if marker != b"VIDEO_STREAM" {
            println!("Expected VIDEO_STREAM marker from {}, got {:?}", node_name, String::from_utf8_lossy(&marker));
            return Ok(());
        }

        println!("Video stream-per-frame mode established from {}", node_name);

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

        // QoS metrics for this node
        let mut qos = quic_video::QosMetrics::new();

        // Cache keyframe for late RTSP clients
        let cached_keyframe: Arc<std::sync::Mutex<Option<quic_video::VideoFrame>>> =
            Arc::new(std::sync::Mutex::new(None));

        // File transfer receiver for this node
        let output_dir = dirs::video_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("kaiju")
            .join(&node_name);

        // Look up decryption key for this node
        let decryption_key = {
            let store = fingerprint_store.lock().await;
            match store.get_encryption_keypair(&fingerprint) {
                Ok(Some((secret, _public))) => {
                    println!("[{}] Decryption key loaded", node_name);
                    Some(secret)
                }
                Ok(None) => {
                    println!("[{}] No encryption key found (unencrypted transfers only)", node_name);
                    None
                }
                Err(e) => {
                    eprintln!("[{}] Error loading encryption key: {}", node_name, e);
                    None
                }
            }
        };

        let mut file_receiver = if let Some(key) = decryption_key {
            FileTransferReceiver::with_decryption_key(output_dir.clone(), key)
        } else {
            FileTransferReceiver::new(output_dir.clone())
        };

        // Main loop: handle video frames, commands, and stats
        let mut stats_interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                // Log QUIC connection stats and QoS metrics
                _ = stats_interval.tick() => {
                    quic_metrics::log_stats(&connection, &node_name);

                    // Print QoS metrics every 5 seconds
                    if let Some(report) = qos.report_if_due() {
                        println!("[{}:QoS] {}", node_name, report);
                    }
                }

                // Send commands to remote
                Some(cmd) = cmd_rx.recv() => {
                    let mut send_stream = connection.open_uni().await?;
                    send_stream.write_all(cmd.as_bytes()).await?;
                    send_stream.finish()?;
                }

                // Receive streams (video frames or command responses)
                result = connection.accept_uni() => {
                    match result {
                        Ok(mut recv_stream) => {
                            let data = match recv_stream.read_to_end(10_000_000).await {
                                Ok(d) => d,
                                Err(e) => {
                                    eprintln!("[{}] Stream read error: {}", node_name, e);
                                    qos.drop_frame();
                                    continue;
                                }
                            };

                            if data.is_empty() {
                                continue;
                            }

                            // Peek first byte to determine stream type
                            // 0x01 = file transfer, ASCII printable (32-126) = command response, otherwise = video frame
                            let first_byte = data[0];
                            if first_byte == FILE_TRANSFER_MAGIC {
                                // File transfer message
                                match decode_message_type(&data) {
                                    Ok(FileMessageType::FileHeader) => {
                                        match FileHeader::decode(&data) {
                                            Ok(header) => {
                                                println!(
                                                    "[{}] Receiving file {}/{}: {} ({})",
                                                    node_name,
                                                    header.file_index + 1,
                                                    header.total_files,
                                                    header.filename,
                                                    format_size(header.file_size)
                                                );
                                                if let Err(e) = file_receiver.start_file(header).await {
                                                    eprintln!("[{}] Failed to start file: {}", node_name, e);
                                                }
                                            }
                                            Err(e) => eprintln!("[{}] FileHeader decode error: {}", node_name, e),
                                        }
                                    }
                                    Ok(FileMessageType::FileChunk) => {
                                        match FileChunk::decode(&data) {
                                            Ok(chunk) => {
                                                if let Err(e) = file_receiver.receive_chunk(chunk).await {
                                                    eprintln!("[{}] Chunk receive error: {}", node_name, e);
                                                }
                                            }
                                            Err(e) => eprintln!("[{}] FileChunk decode error: {}", node_name, e),
                                        }
                                    }
                                    Ok(FileMessageType::FileComplete) => {
                                        match FileComplete::decode(&data) {
                                            Ok(complete) => {
                                                match file_receiver.complete_file(complete.request_id, complete.file_index).await {
                                                    Ok(path) => {
                                                        println!("[{}] Saved: {}", node_name, path.display());
                                                        broadcast(&admin_state, &format!("[{}] Saved: {}", node_name, path.display())).await;
                                                    }
                                                    Err(e) => eprintln!("[{}] File complete error: {}", node_name, e),
                                                }
                                            }
                                            Err(e) => eprintln!("[{}] FileComplete decode error: {}", node_name, e),
                                        }
                                    }
                                    Ok(FileMessageType::TransferComplete) => {
                                        match TransferComplete::decode(&data) {
                                            Ok(complete) => {
                                                println!(
                                                    "[{}] Transfer complete: {} files ({})",
                                                    node_name,
                                                    complete.total_files,
                                                    format_size(complete.total_bytes)
                                                );
                                                broadcast(&admin_state, &format!(
                                                    "[{}] Transfer complete: {} files saved to {}",
                                                    node_name, complete.total_files, output_dir.display()
                                                )).await;
                                            }
                                            Err(e) => eprintln!("[{}] TransferComplete decode error: {}", node_name, e),
                                        }
                                    }
                                    Ok(FileMessageType::TransferError) => {
                                        match TransferError::decode(&data) {
                                            Ok(error) => {
                                                eprintln!("[{}] Transfer error: {}", node_name, error.message);
                                                broadcast(&admin_state, &format!("[{}] Transfer error: {}", node_name, error.message)).await;
                                            }
                                            Err(e) => eprintln!("[{}] TransferError decode error: {}", node_name, e),
                                        }
                                    }
                                    Err(e) => eprintln!("[{}] Unknown file transfer message: {}", node_name, e),
                                }
                            } else if first_byte >= 32 && first_byte <= 126 {
                                // Command response (text)
                                let msg = String::from_utf8_lossy(&data);

                                // Handle heartbeat from remote
                                if msg.starts_with("HEARTBEAT|") {
                                    let ack = msg.replace("HEARTBEAT|", "HEARTBEAT_ACK|");
                                    let mut send_stream = connection.open_uni().await?;
                                    send_stream.write_all(ack.as_bytes()).await?;
                                    send_stream.finish()?;
                                    continue;
                                }

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

                                if let Some(msg) = broadcast_msg {
                                    broadcast(&admin_state, &msg).await;
                                }

                                print!("> ");
                                io::stdout().flush().unwrap();
                            } else {
                                // Video frame (binary)
                                let frame = match quic_video::VideoFrame::decode(&data) {
                                    Ok(f) => f,
                                    Err(e) => {
                                        eprintln!("[{}] Frame decode error: {}", node_name, e);
                                        qos.drop_frame();
                                        continue;
                                    }
                                };

                                // Track QoS metrics - returns true if frame is fresh (newest seen)
                                let is_fresh = qos.record(frame.sequence, data.len());

                                // Skip stale frames (arrived after a newer frame)
                                if !is_fresh {
                                    continue;
                                }

                                // Cache keyframes for late RTSP clients
                                if frame.is_keyframe {
                                    *cached_keyframe.lock().unwrap() = Some(frame.clone());
                                }

                                // Send to RTSP pipeline
                                if let Some(tx) = frame_tx.lock().unwrap().as_ref() {
                                    let _ = tx.send(frame);
                                }
                            }
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
    println!("Recording Retrieval:");
    println!("  <node> recordings 5 mins ago           - Retrieve last 5 minutes");
    println!("  <node> recordings 2 hours ago          - Retrieve last 2 hours");
    println!("  <node> recordings since yesterday      - Since midnight yesterday");
    println!("  <node> recordings since midnight       - Since midnight today");
    println!("  <node> recordings last hour            - Last 60 minutes");
    println!("  <node> recordings <ISO8601> <ISO8601>  - Specific time range");
    println!("  Files saved to: ~/Videos/kaiju/<node>/");
    println!();
    println!("  help                         - Show this help");
    println!("  quit                         - Exit");
    println!();
    println!("Relayed streams: rtsp://<host>:<port>/<node>/stream");
    println!("ONVIF PTZ:       http://<host>:<port>/onvif/<node>/ptz_service");
    println!();
    println!("Options:");
    println!("  --headless                   - Run without stdin (admin via web only)");
    println!();
    println!("Configuration: Run 'kaiju-central-setup' to configure network bindings and ports.");
}
