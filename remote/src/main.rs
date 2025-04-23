mod storage;

use anyhow::Result;
use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use ffmpeg_recorder::{ensure_disk_space, Recorder, RecorderConfig};
use gstreamer::prelude::*;
use gstreamer_app::AppSink;
use onvif_client::OnvifClient;
use quinn::Endpoint;
use recording_retrieval::{
    find_recordings_in_range, format_size, parse_time_range, FileTransferSender, TransferError,
};
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Remote Node - Video Streamer with ONVIF Camera Control
///
/// - Connects to an ONVIF camera or direct RTSP stream
/// - Connects to central node via QUIC for authentication, commands, and video
/// - Sends video frames over QUIC (no local RTSP server needed)
/// - Accepts PTZ commands to control the camera (ONVIF only)

#[derive(Parser)]
#[command(name = "remote")]
#[command(about = "Kaiju remote edge node - streams video to central node")]
struct Cli {
    /// Node name for identification
    #[arg(short, long)]
    name: String,

    /// Central node address (ip:port)
    #[arg(short, long)]
    central: String,

    #[command(subcommand)]
    source: Source,
}

#[derive(Subcommand)]
enum Source {
    /// Connect to RTSP stream directly
    Rtsp {
        /// Full RTSP URL (credentials embedded, e.g. rtsp://user:pass@host/path)
        #[arg(short, long)]
        url: String,
    },
    /// Connect via ONVIF camera discovery
    Onvif {
        /// Camera IP address
        #[arg(long)]
        ip: String,
        /// Camera username
        #[arg(long)]
        user: String,
        /// Camera password
        #[arg(long)]
        pass: String,
    },
}

/// Dynamic stream parameters
#[derive(Clone)]
struct StreamParams {
    width: i32,
    height: i32,
    /// Target framerate (None = passthrough from source)
    framerate: Option<i32>,
    bitrate: u32,
}

impl Default for StreamParams {
    fn default() -> Self {
        Self {
            width: 1024,
            height: 576,
            framerate: None,  // Passthrough from source by default
            bitrate: 400,  // Start low, can increase via command
        }
    }
}

/// Shared state for dynamic pipeline control
struct PipelineState {
    capsfilter: Option<gstreamer::Element>,
    encoder: Option<gstreamer::Element>,
    videorate: Option<gstreamer::Element>,
    params: StreamParams,
    /// Detected source framerate (set when pipeline negotiates)
    source_framerate: Option<i32>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize GStreamer
    gstreamer::init()?;

    // Run async runtime
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main(cli.name, cli.central, cli.source))
}

async fn async_main(node_name: String, central_addr: String, source: Source) -> Result<()> {
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

    // Get RTSP URL and optional ONVIF client based on source type
    let (camera_rtsp_url, onvif, device_info) = match source {
        Source::Rtsp { url } => {
            println!("Using direct RTSP source");
            println!("RTSP URL: {}", url);
            println!();
            (url, None, "Direct RTSP".to_string())
        }
        Source::Onvif { ip, user, pass } => {
            let mut client = OnvifClient::new(&ip, &user, &pass);
            println!("Connecting to ONVIF camera at {}...", ip);

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

            let info_str = format!("{}", info);
            println!("Camera: {}", info);
            println!("Camera RTSP: {}", url);
            println!();

            (url, Some(Arc::new(Mutex::new(client))), info_str)
        }
    };

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
        videorate: None,
        params: StreamParams::default(),
        source_framerate: None,
    }));

    // Create channel for video frames (will be sent over QUIC)
    let (frame_tx, frame_rx) = mpsc::channel::<quic_video::VideoFrame>(30);

    // Create GStreamer pipeline with appsink (video goes over QUIC, not local RTSP)
    let gst_pipeline = gstreamer::Pipeline::new();
    let params = pipeline_state.lock().unwrap().params.clone();

    let src = gstreamer::ElementFactory::make("rtspsrc")
        .property("location", &camera_rtsp_url)
        .property("latency", 100u32)
        .build()?;

    let depay = gstreamer::ElementFactory::make("rtph264depay").build()?;
    let decode = gstreamer::ElementFactory::make("avdec_h264").build()?;
    let convert = gstreamer::ElementFactory::make("videoconvert").build()?;
    let scale = gstreamer::ElementFactory::make("videoscale").build()?;
    // Configure videorate to only drop frames, never duplicate (prevents buffering)
    let rate = gstreamer::ElementFactory::make("videorate")
        .property("drop-only", true)
        .property("skip-to-first", true)
        .build()?;

    // Capsfilter: set resolution only, let framerate pass through from source
    // User can reduce framerate later but not increase above source
    let capsfilter = gstreamer::ElementFactory::make("capsfilter")
        .name("caps")
        .property(
            "caps",
            gstreamer::Caps::builder("video/x-raw")
                .field("width", params.width)
                .field("height", params.height)
                // No framerate field = passthrough from source
                .build(),
        )
        .build()?;

    let encoder = gstreamer::ElementFactory::make("x264enc")
        .name("encoder")
        .property("bitrate", params.bitrate)
        .property_from_str("tune", "zerolatency")
        .property_from_str("speed-preset", "ultrafast")
        .property("key-int-max", 30u32)
        .build()?;

    let parser = gstreamer::ElementFactory::make("h264parse").build()?;

    let appsink = gstreamer::ElementFactory::make("appsink")
        .name("videosink")
        .build()?
        .dynamic_cast::<AppSink>()
        .unwrap();

    // Configure appsink - never drop frames, let backpressure flow
    // H.264 decoder can't handle gaps, so dropping frames causes decode errors
    appsink.set_sync(false);
    appsink.set_max_buffers(30);  // ~1 second buffer at 30fps
    appsink.set_drop(false);      // NEVER drop - backpressure will naturally slow encoder
    appsink.set_caps(Some(
        &gstreamer::Caps::builder("video/x-h264")
            .field("stream-format", "byte-stream")
            .field("alignment", "au")
            .build(),
    ));

    // Add elements to pipeline
    gst_pipeline.add_many([
        &src,
        &depay,
        &decode,
        &convert,
        &scale,
        &rate,
        &capsfilter,
        &encoder,
        &parser,
        appsink.upcast_ref(),
    ])?;

    // Link static elements (depay onwards)
    gstreamer::Element::link_many([
        &depay,
        &decode,
        &convert,
        &scale,
        &rate,
        &capsfilter,
        &encoder,
        &parser,
        appsink.upcast_ref(),
    ])?;

    // Handle dynamic pad from rtspsrc
    let depay_weak = depay.downgrade();
    src.connect_pad_added(move |_src, src_pad| {
        let Some(depay) = depay_weak.upgrade() else {
            return;
        };
        let sink_pad = depay.static_pad("sink").unwrap();
        if sink_pad.is_linked() {
            return;
        }
        if let Err(e) = src_pad.link(&sink_pad) {
            eprintln!("Failed to link rtspsrc pad: {:?}", e);
        }
    });

    // Detect source framerate using ffprobe (more reliable than GStreamer caps)
    {
        let mut state = pipeline_state.lock().unwrap();
        match detect_source_framerate(&camera_rtsp_url) {
            Ok(fps) => {
                println!("Detected source framerate: {} fps", fps);
                state.source_framerate = Some(fps);
            }
            Err(e) => {
                eprintln!("Warning: Could not detect source framerate: {}", e);
            }
        }
    }

    // Store element references for dynamic control
    {
        let mut state = pipeline_state.lock().unwrap();
        state.capsfilter = Some(capsfilter.clone());
        state.encoder = Some(encoder.clone());
        state.videorate = Some(rate.clone());
    }

    // Set up appsink callback to send frames to channel
    let frame_tx_clone = frame_tx.clone();
    let frame_sequence = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let frame_sequence_clone = frame_sequence.clone();
    appsink.set_callbacks(
        gstreamer_app::AppSinkCallbacks::builder()
            .new_sample(move |sink| {
                let sample = sink.pull_sample().map_err(|_| gstreamer::FlowError::Error)?;
                let buffer = sample.buffer().ok_or(gstreamer::FlowError::Error)?;
                let map = buffer.map_readable().map_err(|_| gstreamer::FlowError::Error)?;

                // Convert nanoseconds to 90kHz RTP clock
                let pts = buffer.pts().map(|t| t.nseconds() / 11111).unwrap_or(0);
                let is_keyframe = !buffer.flags().contains(gstreamer::BufferFlags::DELTA_UNIT);

                // Get next sequence number
                let seq = frame_sequence_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let frame = quic_video::VideoFrame::new(seq, pts, is_keyframe, map.as_slice().to_vec());

                // IMPORTANT: Never drop frames - decoder can't handle gaps in frame sequence
                // If QUIC can't keep up, backpressure will naturally slow down the pipeline
                let _ = frame_tx_clone.blocking_send(frame);

                Ok(gstreamer::FlowSuccess::Ok)
            })
            .build(),
    );

    // Start the pipeline
    gst_pipeline.set_state(gstreamer::State::Playing)?;
    println!("Video pipeline started (camera → QUIC)");
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

    let client_config = quic_common::create_client_config()?;

    let bind_addr: SocketAddr = "0.0.0.0:0".parse()?;
    let endpoint = Endpoint::client(bind_addr)?;

    let remote_addr: SocketAddr = central_addr.parse()?;
    let connection = endpoint
        .connect_with(client_config, remote_addr, "localhost")?
        .await?;

    println!("Connected to central node");

    // Send authentication request: AUTH|name|fingerprint|VIDEO
    // The "VIDEO" marker indicates this node will stream video over QUIC (not RTSP)
    let mut send_stream = connection.open_uni().await?;
    let auth_request = format!("AUTH|{}|{}|VIDEO", node_name, fingerprint);
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

        // Send VIDEO_STREAM marker so central knows to expect stream-per-frame video
        let mut marker_stream = connection.open_uni().await?;
        marker_stream.write_all(b"VIDEO_STREAM").await?;
        marker_stream.finish()?;

        println!();
        println!("==========================================");
        println!("READY - Streaming video (stream-per-frame)");
        println!("==========================================");
        println!();

        // Spawn video sender task - one QUIC stream per frame
        let node_name_clone = node_name.clone();
        let conn_clone = connection.clone();
        let video_handle = tokio::spawn(async move {
            let mut frame_rx = frame_rx;
            let mut frame_count = 0u64;
            let mut bytes_sent = 0u64;
            let mut last_report_time = std::time::Instant::now();
            let mut last_report_bytes = 0u64;

            while let Some(frame) = frame_rx.recv().await {
                let encoded = frame.encode();
                let frame_size = encoded.len();

                // Open new stream for this frame, write, finish
                let stream_result = conn_clone.open_uni().await;
                let mut stream = match stream_result {
                    Ok(s) => s,
                    Err(_) => break,
                };
                if stream.write_all(&encoded).await.is_err() {
                    break;
                }
                if stream.finish().is_err() {
                    break;
                }

                frame_count += 1;
                bytes_sent += frame_size as u64;

                // Print stats every 30 frames (about once per second)
                if frame_count % 30 == 0 {
                    let now = std::time::Instant::now();
                    let interval_secs = now.duration_since(last_report_time).as_secs_f64();
                    let interval_bytes = bytes_sent - last_report_bytes;
                    let mbps = if interval_secs > 0.0 {
                        (interval_bytes as f64 * 8.0) / (interval_secs * 1_000_000.0)
                    } else {
                        0.0
                    };

                    println!(
                        "[{}] {} frames, {:.1} MB total, {:.2} Mbps{}",
                        node_name_clone,
                        frame_count,
                        bytes_sent as f64 / 1_000_000.0,
                        mbps,
                        if frame.is_keyframe { " [KEY]" } else { "" }
                    );

                    last_report_time = now;
                    last_report_bytes = bytes_sent;
                }
            }

            println!("[{}] Video stream ended", node_name_clone);
        });

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

                                // Check for recordings command (needs special handling)
                                let parts: Vec<&str> = cmd.split_whitespace().collect();
                                if !parts.is_empty() && parts[0].to_lowercase() == "recordings" {
                                    let storage = storage::Storage::new();
                                    let conn_clone = connection.clone();

                                    // Handle recordings command
                                    let response = match handle_recordings_command(&parts[1..], &storage, &conn_clone).await {
                                        Ok(msg) => format!("RESULT|ok|{}", msg),
                                        Err(e) => format!("RESULT|error|{}", e),
                                    };

                                    let mut send_stream = connection.open_uni().await?;
                                    send_stream.write_all(response.as_bytes()).await?;
                                    send_stream.finish()?;
                                } else {
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
                        }
                        Err(e) => {
                            println!("Disconnected from central: {}", e);
                            break;
                        }
                    }
                }
                _ = health_check_interval.tick() => {
                    // Log QUIC connection stats
                    quic_metrics::log_stats(&connection, &node_name);

                    // Check recorder health
                    if let Some(ref mut rec) = recorder {
                        if let Err(e) = rec.check_and_restart() {
                            eprintln!("Recorder error: {}", e);
                        }
                        // Ensure disk space by deleting old recordings if needed
                        if let Err(e) = ensure_disk_space(
                            &rec.config().output_dir,
                            rec.config().disk_reserve_percent,
                            &rec.config().file_format,
                        ) {
                            eprintln!("WARNING: Could not ensure disk space: {}", e);
                        }
                    }
                }
            }
        }

        // Cancel video sender when disconnected
        video_handle.abort();
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

    // Stop GStreamer pipeline
    gst_pipeline.set_state(gstreamer::State::Null)?;
    Ok(())
}

fn handle_command(
    cmd: &str,
    onvif: &Option<Arc<Mutex<OnvifClient>>>,
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
                // Build caps with optional framerate (only if user has set one)
                let mut builder = gstreamer::Caps::builder("video/x-raw")
                    .field("width", width)
                    .field("height", height);
                if let Some(fps) = state.params.framerate {
                    builder = builder.field("framerate", gstreamer::Fraction::new(fps, 1));
                }
                caps.set_property("caps", &builder.build());
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

            if fps < 1 {
                return Err("Minimum framerate is 1 fps".to_string());
            }

            let mut state = pipeline_state.lock().unwrap();

            // Cannot increase above source framerate (videorate can only drop, not duplicate)
            if let Some(source_fps) = state.source_framerate {
                if fps > source_fps {
                    return Err(format!(
                        "Cannot exceed source framerate of {} fps (can only reduce)",
                        source_fps
                    ));
                }
            }

            state.params.framerate = Some(fps);

            // Use videorate's max-rate property instead of capsfilter
            // This is the intended way to limit framerate with drop-only mode
            if let Some(ref rate) = state.videorate {
                rate.set_property("max-rate", fps);
                Ok(format!("Framerate limited to {} fps", fps))
            } else {
                Err("Pipeline not ready".to_string())
            }
        }

        "params" | "stream" => {
            let state = pipeline_state.lock().unwrap();
            let fps_str = match (state.params.framerate, state.source_framerate) {
                (Some(fps), _) => format!("{}", fps),
                (None, Some(source)) => format!("{} (source)", source),
                (None, None) => "passthrough".to_string(),
            };
            Ok(format!(
                "Stream: {}x{} @ {} fps, {} kbps",
                state.params.width, state.params.height, fps_str, state.params.bitrate
            ))
        }

        // PTZ and camera commands need the ONVIF client
        _ => {
            match onvif {
                Some(client) => handle_ptz_command(parts, client),
                None => Err("PTZ commands not available for direct RTSP sources".to_string()),
            }
        }
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

/// Handle recordings retrieval command
async fn handle_recordings_command(
    args: &[&str],
    storage: &storage::Storage,
    connection: &quinn::Connection,
) -> Result<String, String> {
    // Check storage availability
    let recordings_dir = storage
        .recordings_path()
        .ok_or("Storage not available")?;

    if args.is_empty() {
        return Err(
            "Usage: recordings <N> <unit> ago | recordings since yesterday | recordings <ISO8601_from> <ISO8601_to>"
                .to_string(),
        );
    }

    // Parse time range
    let range = parse_time_range(args).map_err(|e| e.to_string())?;

    println!(
        "[RECORDINGS] Searching for files from {} to {}",
        range.from.format("%Y-%m-%d %H:%M:%S"),
        range.to.format("%Y-%m-%d %H:%M:%S")
    );

    // Find matching recordings (30 second segments)
    let files = find_recordings_in_range(&recordings_dir, &range, 30).map_err(|e| e.to_string())?;

    if files.is_empty() {
        return Err(format!(
            "No recordings found between {} and {}",
            range.from.format("%Y-%m-%d %H:%M:%S"),
            range.to.format("%Y-%m-%d %H:%M:%S")
        ));
    }

    let file_count = files.len();
    let total_size: u64 = files.iter().map(|f| f.size_bytes).sum();

    println!(
        "[RECORDINGS] Found {} files ({})",
        file_count,
        format_size(total_size)
    );

    // Spawn file transfer task
    let conn_clone = connection.clone();
    let sender = FileTransferSender::new();
    let request_id = sender.next_request_id();

    tokio::spawn(async move {
        match sender.send_files(&conn_clone, &files, request_id).await {
            Ok(bytes) => {
                println!(
                    "[RECORDINGS] Transfer complete: {} bytes sent",
                    format_size(bytes)
                );
            }
            Err(e) => {
                eprintln!("[RECORDINGS] Transfer failed: {}", e);
                // Try to send error message
                let _ = FileTransferSender::send_error(
                    &conn_clone,
                    request_id,
                    TransferError::IO_ERROR,
                    &e.to_string(),
                )
                .await;
            }
        }
    });

    Ok(format!(
        "Found {} recordings ({}), transfer started",
        file_count,
        format_size(total_size)
    ))
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

/// Detect source framerate using ffprobe
fn detect_source_framerate(rtsp_url: &str) -> Result<i32> {
    use std::process::Command;

    let output = Command::new("ffprobe")
        .args([
            "-v", "error",
            "-select_streams", "v:0",
            "-show_entries", "stream=r_frame_rate",
            "-of", "csv=p=0",
            "-rtsp_transport", "tcp",
            "-i", rtsp_url,
        ])
        .output()?;

    if !output.status.success() {
        anyhow::bail!("ffprobe failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let fps_str = String::from_utf8_lossy(&output.stdout);
    let fps_str = fps_str.trim();

    // Parse fraction like "25/1" or "30000/1001"
    if let Some((num, denom)) = fps_str.split_once('/') {
        let num: f64 = num.parse().unwrap_or(0.0);
        let denom: f64 = denom.parse().unwrap_or(1.0);
        if denom > 0.0 {
            return Ok((num / denom).round() as i32);
        }
    }

    // Try parsing as plain number
    if let Ok(fps) = fps_str.parse::<f64>() {
        return Ok(fps.round() as i32);
    }

    anyhow::bail!("Could not parse framerate: {}", fps_str)
}

