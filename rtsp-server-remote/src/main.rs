mod storage;

use anyhow::Result;
use ffmpeg_recorder::{has_disk_space, Recorder, RecorderConfig};
use ed25519_dalek::{SigningKey, VerifyingKey};
use gstreamer::prelude::*;
use gstreamer_rtsp_server::prelude::*;
use onvif_client::OnvifClient;
use quinn::{ClientConfig, Endpoint};
use std::env;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

/// Remote Node - RTSP Relay with ONVIF Camera Control
///
/// - Connects to an ONVIF camera and relays its stream
/// - Connects to central node via QUIC for authentication and commands
/// - Accepts PTZ commands to control the camera
struct CameraConfig {
    host: String,
    user: String,
    pass: String,
}

/// Dynamic stream parameters
#[derive(Clone)]
struct StreamParams {
    width: i32,
    height: i32,
    framerate: i32,
    bitrate: u32,
}

impl Default for StreamParams {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
            framerate: 30,
            bitrate: 4000,
        }
    }
}

/// Shared state for dynamic pipeline control
struct PipelineState {
    capsfilter: Option<gstreamer::Element>,
    encoder: Option<gstreamer::Element>,
    params: StreamParams,
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 6 {
        eprintln!("Usage: {} <node-name> <central-ip:port> <camera-ip> <camera-user> <camera-pass>", args[0]);
        eprintln!("Example: {} khadas 192.168.1.100:5001 192.168.2.90 admin password", args[0]);
        std::process::exit(1);
    }

    let node_name = args[1].clone();
    let central_addr = args[2].clone();
    let camera = CameraConfig {
        host: args[3].clone(),
        user: args[4].clone(),
        pass: args[5].clone(),
    };

    // Initialize GStreamer
    gstreamer::init()?;

    // Run async runtime
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main(node_name, central_addr, camera))
}

async fn async_main(node_name: String, central_addr: String, camera: CameraConfig) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    println!("==========================================");
    println!("RTSP REMOTE NODE: {}", node_name);
    println!("==========================================");
    println!();

    // Setup storage for recordings
    let storage = storage::Storage::new();
    if !storage.is_available() {
        println!("Storage not configured or not available.");
        match storage.setup_interactive() {
            Ok(true) => println!("Storage ready.\n"),
            Ok(false) => println!("Storage setup skipped.\n"),
            Err(e) => println!("Storage setup failed: {}\nContinuing without storage.\n", e),
        }
    } else {
        if let Some(path) = storage.recordings_path() {
            println!("Storage available at: {}\n", path.display());
        }
    }

    // Generate Ed25519 keypair for fingerprinting
    let secret_bytes: [u8; 32] = rand::random();
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key: VerifyingKey = (&signing_key).into();
    let fingerprint = hex::encode(verifying_key.as_bytes());

    println!("Fingerprint: {}", &fingerprint[..32]);
    println!();

    // Create ONVIF client and test connection
    let onvif = Arc::new(Mutex::new(OnvifClient::new(&camera.host, &camera.user, &camera.pass)));

    println!("Connecting to ONVIF camera at {}...", camera.host);
    let (device_info, camera_rtsp_url) = {
        let mut client = onvif.lock().unwrap();
        let info = client.get_device_info()?;

        // Fetch available profiles
        let profiles = client.get_profiles()?;

        let selected_profile = if profiles.is_empty() {
            // No profiles found, use default
            println!("No profiles found, using default");
            None
        } else if profiles.len() == 1 {
            // Only one profile, use it automatically
            println!("Using profile: {}", profiles[0]);
            client.set_profile(&profiles[0].token);
            Some(profiles[0].token.clone())
        } else {
            // Multiple profiles, let user choose
            println!("\nAvailable profiles:");
            for (i, profile) in profiles.iter().enumerate() {
                println!("  [{}] {}", i + 1, profile);
            }
            println!();

            let selected = prompt_profile_selection(profiles.len())?;
            let profile = &profiles[selected];
            println!("Selected: {}", profile);
            client.set_profile(&profile.token);
            Some(profile.token.clone())
        };

        let url = if let Some(ref token) = selected_profile {
            client.get_stream_uri_for_profile(token)?
        } else {
            client.get_stream_uri()?
        };

        (info, url)
    };
    println!("Camera: {}", device_info);
    println!("Camera RTSP: {}", camera_rtsp_url);
    println!();

    // Ask about recording now, but start ffmpeg AFTER RTSP server is attached
    // (spawning ffmpeg before GLib attach seems to cause issues)
    let recording_config: Option<RecorderConfig> = if prompt_yes_no("Enable local recording?")? {
        let storage = storage::Storage::new();
        if !storage.is_available() {
            println!("Storage not available. Setting up...");
            match storage.setup_interactive() {
                Ok(true) => println!("Storage ready."),
                Ok(false) => {
                    println!("Storage setup skipped. Recording disabled.");
                }
                Err(e) => {
                    println!("Storage setup failed: {}. Recording disabled.", e);
                }
            }
        }

        if let Some(output_dir) = storage.recordings_path() {
            let reserve_pct = prompt_number("Disk reserve % (stop when disk is X% full)", 90)?;
            Some(RecorderConfig {
                rtsp_url: camera_rtsp_url.clone(),
                output_dir,
                segment_duration: 30,
                disk_reserve_percent: reserve_pct,
                file_format: "mp4".to_string(),
            })
        } else {
            None
        }
    } else {
        None
    };
    println!();

    // Create shared pipeline state for dynamic control
    let pipeline_state = Arc::new(Mutex::new(PipelineState {
        capsfilter: None,
        encoder: None,
        params: StreamParams::default(),
    }));

    // Create RTSP server to relay the camera stream
    let rtsp_server = gstreamer_rtsp_server::RTSPServer::new();
    rtsp_server.set_service("8554");
    let mounts = rtsp_server.mount_points().expect("Failed to get mount points");

    // Create factory that pulls from the ONVIF camera with dynamic pipeline
    let factory = gstreamer_rtsp_server::RTSPMediaFactory::new();
    let params = pipeline_state.lock().unwrap().params.clone();
    let pipeline = format!(
        "( rtspsrc location=\"{}\" latency=100 \
           ! rtph264depay \
           ! avdec_h264 \
           ! videoconvert \
           ! videoscale \
           ! videorate \
           ! capsfilter name=caps caps=video/x-raw,width={},height={},framerate={}/1 \
           ! x264enc name=encoder bitrate={} tune=zerolatency speed-preset=ultrafast \
           ! rtph264pay name=pay0 pt=96 )",
        camera_rtsp_url, params.width, params.height, params.framerate, params.bitrate
    );
    factory.set_launch(&pipeline);
    factory.set_shared(true);

    // Capture element references when media is configured
    let state_clone = Arc::clone(&pipeline_state);
    factory.connect_media_configure(move |_factory, media| {
        let element = media.element();
        if let Some(bin) = element.downcast_ref::<gstreamer::Bin>() {
            let mut state = state_clone.lock().unwrap();
            state.capsfilter = bin.by_name("caps");
            state.encoder = bin.by_name("encoder");
            if state.capsfilter.is_some() && state.encoder.is_some() {
                println!("Pipeline elements captured for dynamic control");
            }
        }
    });

    mounts.add_factory("/stream", factory);

    // Create GLib main context and attach RTSP server BEFORE running main loop
    // The main loop will run in a separate thread, but we attach first
    let main_ctx = glib::MainContext::default();

    // Attach RTSP server to the context (this adds sources, doesn't need loop running)
    let _rtsp_id = rtsp_server.attach(Some(&main_ctx)).expect("Failed to attach RTSP server");

    // Now start the main loop in a background thread
    let main_loop = glib::MainLoop::new(Some(&main_ctx), false);
    let main_loop_clone = main_loop.clone();
    std::thread::spawn(move || {
        main_loop_clone.run();
    });

    // Get local IP for RTSP URL
    let local_ip = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    let relay_rtsp_url = format!("rtsp://{}:8554/stream", local_ip);

    println!("RTSP relay started");
    println!("Relay URL: {}", relay_rtsp_url);
    println!();

    // Start recorder now (after GLib is set up, before central connection)
    // This ensures recording works even if central connection fails
    let mut recorder: Option<Recorder> = if let Some(config) = recording_config {
        println!("Starting recorder...");
        let mut rec = Recorder::new(config);
        match rec.start() {
            Ok(()) => {
                println!("Recording to: {}", rec.config().output_dir.display());
                Some(rec)
            }
            Err(e) => {
                eprintln!("Failed to start recorder: {}. Continuing without recording.", e);
                None
            }
        }
    } else {
        None
    };
    println!();

    // Connect to central node
    println!("Connecting to central node at {}...", central_addr);

    let mut crypto = quic_common::insecure_client_config();
    crypto.alpn_protocols = vec![];

    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
    let mut client_config = ClientConfig::new(Arc::new(quic_config));

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_uni_streams(100_u8.into());
    transport_config.max_concurrent_bidi_streams(100_u8.into());
    transport_config.max_idle_timeout(None);
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    client_config.transport_config(Arc::new(transport_config));

    let bind_addr: SocketAddr = "0.0.0.0:0".parse()?;
    let endpoint = Endpoint::client(bind_addr)?;

    let remote_addr: SocketAddr = central_addr.parse()?;
    let connection = endpoint
        .connect_with(client_config, remote_addr, "localhost")?
        .await?;

    // Determine which local IP is used to reach central
    // This ensures we advertise the correct IP (e.g., Tailscale IP when connecting over Tailscale)
    let connection_local_ip = get_local_ip_for_dest(&remote_addr.ip())
        .unwrap_or_else(|| local_ip.clone());
    let advertised_rtsp_url = format!("rtsp://{}:8554/stream", connection_local_ip);

    println!("Connected to central node");
    println!("Advertising RTSP URL: {}", advertised_rtsp_url);

    // Send authentication request: AUTH|name|fingerprint|rtsp_url
    let mut send_stream = connection.open_uni().await?;
    let auth_request = format!("AUTH|{}|{}|{}", node_name, fingerprint, advertised_rtsp_url);
    send_stream.write_all(auth_request.as_bytes()).await?;
    send_stream.finish()?;

    println!("Authentication request sent, waiting for approval...");

    // Wait for approval/denial
    let mut recv_stream = connection.accept_uni().await?;
    let buffer = recv_stream.read_to_end(1024 * 1024).await?;
    let response = String::from_utf8_lossy(&buffer);

    if response.starts_with("APPROVED") {
        println!("Approved by central node!");

        // Send confirmation
        let mut confirm_stream = connection.open_uni().await?;
        let confirmation = format!("CONFIRM|{}|Ready - Camera: {}", node_name, device_info);
        confirm_stream.write_all(confirmation.as_bytes()).await?;
        confirm_stream.finish()?;

        println!();
        println!("==========================================");
        println!("READY - Listening for commands");
        println!("==========================================");
        println!();

        // Command loop with periodic recorder health check
        let mut health_check_interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                result = connection.accept_uni() => {
                    match result {
                        Ok(mut recv_stream) => {
                            let buffer = recv_stream.read_to_end(1024 * 1024).await?;
                            let msg = String::from_utf8_lossy(&buffer);

                            if msg.starts_with("CMD|") {
                                let cmd = msg.strip_prefix("CMD|").unwrap_or("");
                                println!("Received command: {}", cmd);

                                let result = handle_command(cmd, &onvif, &pipeline_state);

                                // Send result back
                                let mut send_stream = connection.open_uni().await?;
                                let response = match result {
                                    Ok(msg) => format!("RESULT|ok|{}", msg),
                                    Err(e) => format!("RESULT|error|{}", e),
                                };
                                send_stream.write_all(response.as_bytes()).await?;
                                send_stream.finish()?;
                            }
                        }
                        Err(e) => {
                            println!("Disconnected from central: {}", e);
                            break;
                        }
                    }
                }
                _ = health_check_interval.tick() => {
                    // Check recorder health
                    if let Some(ref mut rec) = recorder {
                        if let Err(e) = rec.check_and_restart() {
                            eprintln!("Recorder error: {}", e);
                        }
                        if !has_disk_space(&rec.config().output_dir, rec.config().disk_reserve_percent) {
                            eprintln!("WARNING: Disk space low, stopping recording");
                            if let Err(e) = rec.stop() {
                                eprintln!("Failed to stop recorder: {}", e);
                            }
                        }
                    }
                }
            }
        }
    } else if response.starts_with("DENIED") {
        println!("Denied by central node: {}", response);
    } else {
        println!("Unexpected response: {}", response);
    }

    // Stop recorder if running
    if let Some(ref mut rec) = recorder {
        println!("Stopping recorder...");
        if let Err(e) = rec.stop() {
            eprintln!("Failed to stop recorder: {}", e);
        }
    }

    main_loop.quit();
    Ok(())
}

fn handle_command(
    cmd: &str,
    onvif: &Arc<Mutex<OnvifClient>>,
    pipeline_state: &Arc<Mutex<PipelineState>>,
) -> Result<String, String> {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.is_empty() {
        return Err("Empty command".to_string());
    }

    match parts[0].to_lowercase().as_str() {
        // Stream parameter controls
        "resolution" | "res" => {
            if parts.len() < 3 {
                return Err("Usage: resolution <width> <height>".to_string());
            }
            let width: i32 = parts[1].parse().map_err(|_| "Invalid width")?;
            let height: i32 = parts[2].parse().map_err(|_| "Invalid height")?;

            let mut state = pipeline_state.lock().unwrap();
            state.params.width = width;
            state.params.height = height;

            if let Some(ref caps) = state.capsfilter {
                let new_caps = gstreamer::Caps::builder("video/x-raw")
                    .field("width", width)
                    .field("height", height)
                    .field("framerate", gstreamer::Fraction::new(state.params.framerate, 1))
                    .build();
                caps.set_property("caps", &new_caps);
                Ok(format!("Resolution changed to {}x{}", width, height))
            } else {
                Err("Pipeline not ready (no clients connected?)".to_string())
            }
        }

        "bitrate" | "br" => {
            if parts.len() < 2 {
                return Err("Usage: bitrate <kbps>".to_string());
            }
            let bitrate: u32 = parts[1].parse().map_err(|_| "Invalid bitrate")?;

            // Limit to 20 Mbps max
            if bitrate > 20000 {
                return Err("Maximum bitrate is 20000 kbps (20 Mbps)".to_string());
            }

            let mut state = pipeline_state.lock().unwrap();
            state.params.bitrate = bitrate;

            if let Some(ref encoder) = state.encoder {
                encoder.set_property("bitrate", bitrate);
                Ok(format!("Bitrate changed to {} kbps", bitrate))
            } else {
                Err("Pipeline not ready (no clients connected?)".to_string())
            }
        }

        "framerate" | "fps" => {
            if parts.len() < 2 {
                return Err("Usage: framerate <fps>".to_string());
            }
            let fps: i32 = parts[1].parse().map_err(|_| "Invalid framerate")?;

            // Limit to 60 fps max
            if fps > 60 {
                return Err("Maximum framerate is 60 fps".to_string());
            }
            if fps < 1 {
                return Err("Minimum framerate is 1 fps".to_string());
            }

            let mut state = pipeline_state.lock().unwrap();
            state.params.framerate = fps;

            if let Some(ref caps) = state.capsfilter {
                let new_caps = gstreamer::Caps::builder("video/x-raw")
                    .field("width", state.params.width)
                    .field("height", state.params.height)
                    .field("framerate", gstreamer::Fraction::new(fps, 1))
                    .build();
                caps.set_property("caps", &new_caps);
                Ok(format!("Framerate changed to {} fps", fps))
            } else {
                Err("Pipeline not ready (no clients connected?)".to_string())
            }
        }

        "params" | "stream" => {
            let state = pipeline_state.lock().unwrap();
            Ok(format!(
                "Stream: {}x{} @ {} fps, {} kbps",
                state.params.width, state.params.height, state.params.framerate, state.params.bitrate
            ))
        }

        // PTZ and camera commands need the ONVIF client
        _ => handle_ptz_command(parts, onvif),
    }
}

fn handle_ptz_command(parts: Vec<&str>, onvif: &Arc<Mutex<OnvifClient>>) -> Result<String, String> {
    let client = onvif.lock().unwrap();

    match parts[0].to_lowercase().as_str() {
        // PTZ continuous move
        "ptz" | "move" => {
            if parts.len() < 2 {
                return Err("Usage: ptz <pan> <tilt> [zoom] [duration_ms]".to_string());
            }
            let pan: f32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.0);
            let tilt: f32 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0);
            let zoom: f32 = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0.0);
            let duration: u64 = parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(500);

            client.ptz_move(pan, tilt, zoom).map_err(|e| e.to_string())?;

            if duration > 0 {
                std::thread::sleep(std::time::Duration::from_millis(duration));
                client.ptz_stop().map_err(|e| e.to_string())?;
                Ok(format!("PTZ move pan={} tilt={} zoom={} for {}ms", pan, tilt, zoom, duration))
            } else {
                Ok(format!("PTZ move pan={} tilt={} zoom={} (continuous)", pan, tilt, zoom))
            }
        }

        // PTZ stop
        "stop" => {
            client.ptz_stop().map_err(|e| e.to_string())?;
            Ok("PTZ stopped".to_string())
        }

        // PTZ goto absolute position
        "goto" => {
            if parts.len() < 4 {
                return Err("Usage: goto <pan> <tilt> <zoom>".to_string());
            }
            let pan: f32 = parts[1].parse().map_err(|_| "Invalid pan")?;
            let tilt: f32 = parts[2].parse().map_err(|_| "Invalid tilt")?;
            let zoom: f32 = parts[3].parse().map_err(|_| "Invalid zoom")?;

            client.ptz_goto(pan, tilt, zoom).map_err(|e| e.to_string())?;
            Ok(format!("PTZ goto pan={} tilt={} zoom={}", pan, tilt, zoom))
        }

        // PTZ status
        "status" | "pos" => {
            let pos = client.ptz_status().map_err(|e| e.to_string())?;
            Ok(format!("PTZ position: {}", pos))
        }

        // Device info
        "info" => {
            let info = client.get_device_info().map_err(|e| e.to_string())?;
            Ok(format!("Camera: {}", info))
        }

        // Home position (pan=0, tilt=0, zoom=0)
        "home" => {
            client.ptz_goto(0.0, 0.0, 0.0).map_err(|e| e.to_string())?;
            Ok("PTZ returning to home position".to_string())
        }

        // Quick pan shortcuts
        "left" => {
            let speed: f32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.5);
            let duration: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(500);
            client.ptz_move(-speed, 0.0, 0.0).map_err(|e| e.to_string())?;
            std::thread::sleep(std::time::Duration::from_millis(duration));
            client.ptz_stop().map_err(|e| e.to_string())?;
            Ok(format!("Panned left at {} for {}ms", speed, duration))
        }
        "right" => {
            let speed: f32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.5);
            let duration: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(500);
            client.ptz_move(speed, 0.0, 0.0).map_err(|e| e.to_string())?;
            std::thread::sleep(std::time::Duration::from_millis(duration));
            client.ptz_stop().map_err(|e| e.to_string())?;
            Ok(format!("Panned right at {} for {}ms", speed, duration))
        }
        "up" => {
            let speed: f32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.5);
            let duration: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(500);
            client.ptz_move(0.0, speed, 0.0).map_err(|e| e.to_string())?;
            std::thread::sleep(std::time::Duration::from_millis(duration));
            client.ptz_stop().map_err(|e| e.to_string())?;
            Ok(format!("Tilted up at {} for {}ms", speed, duration))
        }
        "down" => {
            let speed: f32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.5);
            let duration: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(500);
            client.ptz_move(0.0, -speed, 0.0).map_err(|e| e.to_string())?;
            std::thread::sleep(std::time::Duration::from_millis(duration));
            client.ptz_stop().map_err(|e| e.to_string())?;
            Ok(format!("Tilted down at {} for {}ms", speed, duration))
        }
        "zoomin" | "zi" => {
            let speed: f32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.5);
            let duration: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(500);
            client.ptz_move(0.0, 0.0, speed).map_err(|e| e.to_string())?;
            std::thread::sleep(std::time::Duration::from_millis(duration));
            client.ptz_stop().map_err(|e| e.to_string())?;
            Ok(format!("Zoomed in at {} for {}ms", speed, duration))
        }
        "zoomout" | "zo" => {
            let speed: f32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.5);
            let duration: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(500);
            client.ptz_move(0.0, 0.0, -speed).map_err(|e| e.to_string())?;
            std::thread::sleep(std::time::Duration::from_millis(duration));
            client.ptz_stop().map_err(|e| e.to_string())?;
            Ok(format!("Zoomed out at {} for {}ms", speed, duration))
        }

        _ => Err(format!("Unknown command: {}. Try: ptz, stop, goto, status, info, home, left, right, up, down, zoomin, zoomout", parts[0])),
    }
}

fn get_local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}

/// Get local IP used to reach a specific destination
/// This ensures we advertise the correct interface (e.g., Tailscale IP when connecting over Tailscale)
fn get_local_ip_for_dest(dest: &std::net::IpAddr) -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    let dest_addr = std::net::SocketAddr::new(*dest, 80);
    socket.connect(dest_addr).ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}

fn prompt_profile_selection(count: usize) -> Result<usize> {
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    loop {
        print!("Select profile [1-{}]: ", count);
        io::stdout().flush()?;

        let mut input = String::new();
        handle.read_line(&mut input)?;
        let choice = input.trim();

        if let Ok(num) = choice.parse::<usize>() {
            if num >= 1 && num <= count {
                return Ok(num - 1); // Return 0-indexed
            }
        }
        println!("Please enter a number between 1 and {}", count);
    }
}

fn prompt_yes_no(prompt: &str) -> Result<bool> {
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    loop {
        print!("{} [y/n]: ", prompt);
        io::stdout().flush()?;

        let mut input = String::new();
        handle.read_line(&mut input)?;
        let choice = input.trim().to_lowercase();

        match choice.as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please enter 'y' or 'n'"),
        }
    }
}

fn prompt_number(prompt: &str, default: u8) -> Result<u8> {
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    loop {
        print!("{} [default: {}]: ", prompt, default);
        io::stdout().flush()?;

        let mut input = String::new();
        handle.read_line(&mut input)?;
        let choice = input.trim();

        if choice.is_empty() {
            return Ok(default);
        }

        if let Ok(num) = choice.parse::<u8>() {
            if num <= 100 {
                return Ok(num);
            }
        }
        println!("Please enter a number between 0 and 100");
    }
}

