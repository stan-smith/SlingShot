mod storage;

use adaptive_bitrate::{AdaptiveController, QualityChange};
use anyhow::Result;
use clap::{Parser, Subcommand};
use config_manager::{
    EncryptionConfig, IdentityConfig, OnvifConfig, RemoteConfig, RtspConfig, SourceConfig,
    StorageConfig as CfgStorageConfig,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use ffmpeg_recorder::{ensure_disk_space, Recorder, RecorderConfig, SegmentEncryptor};
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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Heartbeat interval in seconds
const HEARTBEAT_INTERVAL_SECS: u64 = 10;
/// Timeout waiting for heartbeat ACK (must be > HEARTBEAT_INTERVAL_SECS)
const HEARTBEAT_TIMEOUT_SECS: u64 = 15;
/// Reconnect attempt interval in seconds
const RECONNECT_INTERVAL_SECS: u64 = 10;

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
    /// Node name for identification (required on first run, optional after)
    #[arg(short, long)]
    name: Option<String>,

    /// Central node address (ip:port) (required on first run, optional after)
    #[arg(short, long)]
    central: Option<String>,

    /// Don't save configuration to disk
    #[arg(long)]
    no_save: bool,

    /// Show verbose metrics (QUIC stats, frame counts, bitrate)
    #[arg(long)]
    debug: bool,

    #[command(subcommand)]
    source: Option<Source>,
}

#[derive(Subcommand, Clone)]
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

/// Connection state for managing heartbeat and reconnection
struct ConnectionState {
    /// Timestamp of last sent heartbeat (for timeout detection)
    last_heartbeat_sent: Option<Instant>,
    /// Whether we're waiting for an ACK
    awaiting_ack: bool,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            last_heartbeat_sent: None,
            awaiting_ack: false,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize GStreamer
    gstreamer::init()?;

    // Load or build configuration
    let (config, save_config) = load_or_build_config(&cli)?;
    let debug = cli.debug;

    // Run async runtime
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main(config, save_config && !cli.no_save, debug))
}

/// Load existing config or build from CLI args
fn load_or_build_config(cli: &Cli) -> Result<(RemoteConfig, bool)> {
    if RemoteConfig::exists() {
        // Load existing config
        let config_path = RemoteConfig::default_path()?;
        println!("Loading configuration from {}", config_path.display());
        let mut config = RemoteConfig::load()?;

        // CLI args override config values
        if let Some(ref name) = cli.name {
            config.node_name = name.clone();
        }
        if let Some(ref central) = cli.central {
            config.central_address = central.clone();
        }
        if let Some(ref source) = cli.source {
            config.source = cli_source_to_config(source);
        }

        Ok((config, false)) // Don't save - already have config
    } else {
        // First run - require CLI args
        let name = cli.name.as_ref().ok_or_else(|| {
            anyhow::anyhow!("First run requires --name argument")
        })?;
        let central = cli.central.as_ref().ok_or_else(|| {
            anyhow::anyhow!("First run requires --central argument")
        })?;
        let source = cli.source.as_ref().ok_or_else(|| {
            anyhow::anyhow!("First run requires source subcommand (rtsp or onvif)")
        })?;

        let config = RemoteConfig {
            node_name: name.clone(),
            central_address: central.clone(),
            source: cli_source_to_config(source),
            recording: config_manager::RecordingConfig::default(),
            storage: CfgStorageConfig::default(),
            encryption_enabled: false,
            adaptive: None,
        };

        Ok((config, true)) // Will save after prompts
    }
}

/// Convert CLI Source to config SourceConfig
fn cli_source_to_config(source: &Source) -> SourceConfig {
    match source {
        Source::Rtsp { url } => SourceConfig::Rtsp(RtspConfig::new(url)),
        Source::Onvif { ip, user, pass } => {
            SourceConfig::Onvif(OnvifConfig::new(ip.clone(), user.clone(), pass))
        }
    }
}

async fn async_main(mut config: RemoteConfig, save_config: bool, debug: bool) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    println!("==========================================");
    println!("RTSP REMOTE NODE: {}", config.node_name);
    println!("==========================================");
    if debug {
        println!("Debug mode enabled (verbose metrics)");
    }
    println!();

    // Setup storage for recordings using config
    let storage = storage::Storage::with_paths_from_config(&config.storage);
    if !storage.is_available() {
        println!("Storage not configured or not available.");
        match storage.setup_interactive() {
            Ok(Some(new_storage_config)) => {
                println!("Storage ready.\n");
                config.storage = new_storage_config;
            }
            Ok(None) => println!("Storage setup skipped.\n"),
            Err(e) => println!("Storage setup failed: {}\nContinuing without storage.\n", e),
        }
    } else {
        if let Some(path) = storage.recordings_path() {
            println!("Storage available at: {}\n", path.display());
        }
    }

    // Load or generate persistent identity
    let (signing_key, fingerprint) = if IdentityConfig::exists() {
        // Load existing identity
        let identity = IdentityConfig::load()?;
        let secret_bytes = identity.secret_bytes()?;
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key: VerifyingKey = (&signing_key).into();
        let fingerprint = hex::encode(verifying_key.as_bytes());
        println!(
            "Loaded identity from {}",
            IdentityConfig::default_path()?.display()
        );
        (signing_key, fingerprint)
    } else {
        // Generate new identity and save
        let secret_bytes: [u8; 32] = rand::random();
        let identity = IdentityConfig::new(&secret_bytes);
        identity.save()?;
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key: VerifyingKey = (&signing_key).into();
        let fingerprint = hex::encode(verifying_key.as_bytes());
        println!(
            "Generated new identity, saved to {}",
            IdentityConfig::default_path()?.display()
        );
        (signing_key, fingerprint)
    };
    let _ = signing_key; // Silence unused warning - kept for potential future signing

    println!("Fingerprint: {}", &fingerprint[..32]);
    println!();

    // Get RTSP URL and optional ONVIF client based on source type
    let (camera_rtsp_url, onvif, device_info) = match &config.source {
        SourceConfig::Rtsp(rtsp_cfg) => {
            let url = rtsp_cfg.url().map_err(|e| anyhow::anyhow!("Failed to decode RTSP URL: {}", e))?;
            println!("Using direct RTSP source");
            println!("RTSP URL: {}", url);
            println!();
            (url, None, "Direct RTSP".to_string())
        }
        SourceConfig::Onvif(onvif_cfg) => {
            let pass = onvif_cfg.password().map_err(|e| anyhow::anyhow!("Failed to decode password: {}", e))?;
            let mut client = OnvifClient::new(&onvif_cfg.ip, &onvif_cfg.username, &pass);
            println!("Connecting to ONVIF camera at {}...", onvif_cfg.ip);

            let info = client.get_device_info()?;

            // Use stored profile token if available, otherwise prompt
            let selected_profile = if let Some(ref token) = onvif_cfg.profile_token {
                // Profile was configured via setup tool
                println!("Using configured profile: {}", token);
                client.set_profile(token);
                Some(token.clone())
            } else {
                // No stored profile - enumerate and prompt
                let profiles = client.get_profiles()?;

                if profiles.is_empty() {
                    println!("No profiles found, using default");
                    None
                } else if profiles.len() == 1 {
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
                }
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

    // Load encryption pubkey if available (for encrypting recordings)
    let encryption_pubkey: Option<String> = if config.encryption_enabled {
        match EncryptionConfig::load() {
            Ok(enc) => {
                println!("Encryption key loaded for recordings");
                Some(enc.x25519_pubkey)
            }
            Err(_) => {
                println!("Encryption enabled but no key yet (will get on approval)");
                None
            }
        }
    } else {
        None
    };

    // Ask about recording if not already configured
    let recording_config: Option<RecorderConfig> = if config.recording.enabled {
        // Recording already enabled in config
        if let Some(output_dir) = storage.recordings_path() {
            Some(RecorderConfig {
                rtsp_url: camera_rtsp_url.clone(),
                output_dir,
                segment_duration: 30,
                disk_reserve_percent: config.recording.disk_reserve_percent,
                file_format: "mp4".to_string(),
                encryption_pubkey: encryption_pubkey.clone(),
            })
        } else {
            println!("Recording enabled but storage not available.");
            None
        }
    } else if save_config {
        // First run - prompt for recording settings
        if prompt_yes_no("Enable local recording?")? {
            let storage = storage::Storage::with_paths_from_config(&config.storage);
            if !storage.is_available() {
                println!("Storage not available. Setting up...");
                match storage.setup_interactive() {
                    Ok(Some(new_storage_config)) => {
                        println!("Storage ready.");
                        config.storage = new_storage_config;
                    }
                    Ok(None) => {
                        println!("Storage setup skipped. Recording disabled.");
                    }
                    Err(e) => {
                        println!("Storage setup failed: {}. Recording disabled.", e);
                    }
                }
            }

            if let Some(output_dir) = storage.recordings_path() {
                let reserve_pct = prompt_number("Disk reserve % (stop when disk is X% full)", 90)?;
                config.recording.enabled = true;
                config.recording.disk_reserve_percent = reserve_pct;
                Some(RecorderConfig {
                    rtsp_url: camera_rtsp_url.clone(),
                    output_dir,
                    segment_duration: 30,
                    disk_reserve_percent: reserve_pct,
                    file_format: "mp4".to_string(),
                    encryption_pubkey: encryption_pubkey.clone(),
                })
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // Create segment encryptor if encryption is enabled and we have a key
    let mut segment_encryptor: Option<SegmentEncryptor> = if let Some(ref rec_config) = recording_config {
        if let Some(ref pubkey) = rec_config.encryption_pubkey {
            let mut enc = SegmentEncryptor::new(
                rec_config.output_dir.clone(),
                rec_config.file_format.clone(),
                pubkey.clone(),
            );
            // Scan existing files so we don't re-encrypt them
            if let Err(e) = enc.scan_existing() {
                eprintln!("Warning: Could not scan existing recordings: {}", e);
            }
            println!("Recording encryption enabled");
            Some(enc)
        } else {
            None
        }
    } else {
        None
    };
    println!();

    // Save config if this is first run
    if save_config {
        match config.save() {
            Ok(()) => {
                let path = RemoteConfig::default_path().unwrap_or_default();
                println!("Configuration saved to {}", path.display());
            }
            Err(e) => {
                eprintln!("Warning: Failed to save configuration: {}", e);
            }
        }
        println!();
    }

    // Create shared pipeline state for dynamic control
    let pipeline_state = Arc::new(Mutex::new(PipelineState {
        capsfilter: None,
        encoder: None,
        videorate: None,
        params: StreamParams::default(),
        source_framerate: None,
    }));

    // Initialize adaptive bitrate controller if enabled
    let adaptive_controller: Option<Arc<Mutex<AdaptiveController>>> =
        if let Some(ref adaptive_config) = config.adaptive {
            if adaptive_config.enabled {
                let controller = AdaptiveController::new(adaptive_config);
                // Set initial stream params from adaptive config
                {
                    let mut state = pipeline_state.lock().unwrap();
                    state.params.width = adaptive_config.target_width;
                    state.params.height = adaptive_config.target_height;
                    state.params.framerate = Some(adaptive_config.target_framerate);
                    state.params.bitrate = adaptive_config.target_bitrate;
                }
                println!(
                    "[ABR] Adaptive bitrate enabled: {}x{}@{}fps, target {} kbps",
                    adaptive_config.target_width,
                    adaptive_config.target_height,
                    adaptive_config.target_framerate,
                    adaptive_config.target_bitrate
                );
                Some(Arc::new(Mutex::new(controller)))
            } else {
                None
            }
        } else {
            None
        };

    // Track previous QUIC stats for delta calculation (ABR needs per-interval loss, not cumulative)
    // None = first sample (initialize only, don't process), Some = subsequent samples
    let prev_quic_stats: Arc<Mutex<Option<(u64, u64)>>> = Arc::new(Mutex::new(None));

    // Create channel for video frames (will be sent over QUIC)
    let (frame_tx, mut frame_rx) = mpsc::channel::<quic_video::VideoFrame>(30);

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

    // Parse remote address once (outside reconnect loop)
    let remote_addr: SocketAddr = config.central_address.parse()?;

    // Reconnection loop - keeps trying to connect to central
    'reconnect: loop {
        // Drain any stale frames from previous connection
        while frame_rx.try_recv().is_ok() {}

        println!("Connecting to central node at {}...", config.central_address);

        let client_config = match quic_common::create_client_config() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to create QUIC config: {}. Retrying in {}s...", e, RECONNECT_INTERVAL_SECS);
                tokio::time::sleep(Duration::from_secs(RECONNECT_INTERVAL_SECS)).await;
                continue 'reconnect;
            }
        };

        let bind_addr: SocketAddr = "0.0.0.0:0".parse()?;
        let endpoint = match Endpoint::client(bind_addr) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("Failed to create QUIC endpoint: {}. Retrying in {}s...", e, RECONNECT_INTERVAL_SECS);
                tokio::time::sleep(Duration::from_secs(RECONNECT_INTERVAL_SECS)).await;
                continue 'reconnect;
            }
        };

        let connection = match endpoint.connect_with(client_config, remote_addr, "localhost") {
            Ok(connecting) => match connecting.await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("Connection failed: {}. Retrying in {}s...", e, RECONNECT_INTERVAL_SECS);
                    tokio::time::sleep(Duration::from_secs(RECONNECT_INTERVAL_SECS)).await;
                    continue 'reconnect;
                }
            },
            Err(e) => {
                eprintln!("Failed to initiate connection: {}. Retrying in {}s...", e, RECONNECT_INTERVAL_SECS);
                tokio::time::sleep(Duration::from_secs(RECONNECT_INTERVAL_SECS)).await;
                continue 'reconnect;
            }
        };

        println!("Connected to central node");

        // Send authentication request: AUTH|name|fingerprint|VIDEO|ENCRYPT or NOENC
        // The "VIDEO" marker indicates this node will stream video over QUIC (not RTSP)
        // The "ENCRYPT/NOENC" marker indicates whether encryption key is requested
        let mut send_stream = match connection.open_uni().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to open auth stream: {}. Retrying in {}s...", e, RECONNECT_INTERVAL_SECS);
                tokio::time::sleep(Duration::from_secs(RECONNECT_INTERVAL_SECS)).await;
                continue 'reconnect;
            }
        };
        let encrypt_flag = if config.encryption_enabled { "ENCRYPT" } else { "NOENC" };
        let auth_request = format!(
            "AUTH|{}|{}|VIDEO|{}",
            config.node_name, fingerprint, encrypt_flag
        );
        if let Err(e) = send_stream.write_all(auth_request.as_bytes()).await {
            eprintln!("Failed to send auth request: {}. Retrying in {}s...", e, RECONNECT_INTERVAL_SECS);
            tokio::time::sleep(Duration::from_secs(RECONNECT_INTERVAL_SECS)).await;
            continue 'reconnect;
        }
        let _ = send_stream.finish();

        println!(
            "Authentication request sent (encryption: {}), waiting for approval...",
            if config.encryption_enabled {
                "requested"
            } else {
                "disabled"
            }
        );

        // Wait for approval/denial
        // Response format: APPROVED|message or APPROVED|message|pubkey_hex
        let mut recv_stream = match connection.accept_uni().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to receive auth response: {}. Retrying in {}s...", e, RECONNECT_INTERVAL_SECS);
                tokio::time::sleep(Duration::from_secs(RECONNECT_INTERVAL_SECS)).await;
                continue 'reconnect;
            }
        };
        let buffer = match recv_stream.read_to_end(1024 * 1024).await {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Failed to read auth response: {}. Retrying in {}s...", e, RECONNECT_INTERVAL_SECS);
                tokio::time::sleep(Duration::from_secs(RECONNECT_INTERVAL_SECS)).await;
                continue 'reconnect;
            }
        };
        let response = String::from_utf8_lossy(&buffer);

        if response.starts_with("APPROVED") {
            println!("Approved by central node!");

            // Parse APPROVED response for optional encryption key
            let parts: Vec<&str> = response.split('|').collect();
            if config.encryption_enabled {
                if parts.len() >= 3 {
                    let pubkey_hex = parts[2];
                    // Validate and store the encryption key
                    match EncryptionConfig::new(pubkey_hex) {
                        Ok(enc_config) => {
                            if let Err(e) = enc_config.save() {
                                eprintln!("Failed to save encryption key: {}. Retrying...", e);
                                tokio::time::sleep(Duration::from_secs(RECONNECT_INTERVAL_SECS)).await;
                                continue 'reconnect;
                            }
                            println!("Encryption key received and stored");
                        }
                        Err(e) => {
                            eprintln!("Error: Invalid encryption key from central: {}", e);
                            eprintln!("Encryption was requested but key is invalid. Aborting.");
                            break 'reconnect;
                        }
                    }
                } else {
                    eprintln!("Error: Encryption was requested but no key received from central.");
                    eprintln!("Central may not support encryption. Aborting.");
                    break 'reconnect;
                }
            }

            // Send confirmation
            let mut confirm_stream = match connection.open_uni().await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to send confirmation: {}. Retrying...", e);
                    tokio::time::sleep(Duration::from_secs(RECONNECT_INTERVAL_SECS)).await;
                    continue 'reconnect;
                }
            };
            let confirmation = format!("CONFIRM|{}|Ready - Camera: {}", config.node_name, device_info);
            let _ = confirm_stream.write_all(confirmation.as_bytes()).await;
            let _ = confirm_stream.finish();

            // Send VIDEO_STREAM marker so central knows to expect stream-per-frame video
            let mut marker_stream = match connection.open_uni().await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to send video marker: {}. Retrying...", e);
                    tokio::time::sleep(Duration::from_secs(RECONNECT_INTERVAL_SECS)).await;
                    continue 'reconnect;
                }
            };
            let _ = marker_stream.write_all(b"VIDEO_STREAM").await;
            let _ = marker_stream.finish();

            println!();
            println!("==========================================");
            println!("READY - Streaming video (stream-per-frame)");
            println!("==========================================");
            println!();

            // Video frame stats (integrated into main loop for reconnection support)
            let mut frame_count = 0u64;
            let mut bytes_sent = 0u64;
            let mut last_report_time = Instant::now();
            let mut last_report_bytes = 0u64;

            // Command loop with video sending, heartbeat, and periodic recorder health check
            let mut health_check_interval = tokio::time::interval(Duration::from_secs(3));
            let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
            let mut conn_state = ConnectionState::default();
            loop {
                tokio::select! {
                    // Send video frames over QUIC
                    Some(frame) = frame_rx.recv() => {
                        let encoded = frame.encode();
                        let frame_size = encoded.len();

                        // Open new stream for this frame, write, finish
                        match connection.open_uni().await {
                            Ok(mut stream) => {
                                if stream.write_all(&encoded).await.is_err() {
                                    println!("Failed to send video frame");
                                    break;
                                }
                                let _ = stream.finish();
                            }
                            Err(e) => {
                                println!("Failed to open stream for video: {}", e);
                                break;
                            }
                        }

                        frame_count += 1;
                        bytes_sent += frame_size as u64;

                        // Print stats every 30 frames (about once per second) - debug only
                        if debug && frame_count % 30 == 0 {
                            let now = Instant::now();
                            let interval_secs = now.duration_since(last_report_time).as_secs_f64();
                            let interval_bytes = bytes_sent - last_report_bytes;
                            let mbps = if interval_secs > 0.0 {
                                (interval_bytes as f64 * 8.0) / (interval_secs * 1_000_000.0)
                            } else {
                                0.0
                            };

                            println!(
                                "[{}] {} frames, {:.1} MB total, {:.2} Mbps{}",
                                config.node_name,
                                frame_count,
                                bytes_sent as f64 / 1_000_000.0,
                                mbps,
                                if frame.is_keyframe { " [KEY]" } else { "" }
                            );

                            last_report_time = now;
                            last_report_bytes = bytes_sent;
                        }
                    }
                    result = connection.accept_uni() => {
                        match result {
                            Ok(mut recv_stream) => {
                                let buffer = match recv_stream.read_to_end(1024 * 1024).await {
                                    Ok(b) => b,
                                    Err(e) => {
                                        eprintln!("Stream read error: {}", e);
                                        continue;
                                    }
                                };
                                let msg = String::from_utf8_lossy(&buffer);

                                // Handle heartbeat ACK from central
                                if msg.starts_with("HEARTBEAT_ACK|") {
                                    conn_state.awaiting_ack = false;
                                    continue;
                                }

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

                                        if let Ok(mut send_stream) = connection.open_uni().await {
                                            let _ = send_stream.write_all(response.as_bytes()).await;
                                            let _ = send_stream.finish();
                                        }
                                    } else {
                                        let result = handle_command(cmd, &onvif, &pipeline_state);

                                        // Send result back
                                        let response = match result {
                                            Ok(msg) => format!("RESULT|ok|{}", msg),
                                            Err(e) => format!("RESULT|error|{}", e),
                                        };
                                        if let Ok(mut send_stream) = connection.open_uni().await {
                                            let _ = send_stream.write_all(response.as_bytes()).await;
                                            let _ = send_stream.finish();
                                        }
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
                        // Log QUIC connection stats (debug only)
                        if debug {
                            quic_metrics::log_stats(&connection, &config.node_name);
                        }

                        // Adaptive bitrate control - process QUIC metrics
                        if let Some(ref controller) = adaptive_controller {
                            let stats = connection.stats();
                            let curr_lost = stats.path.lost_packets;
                            let curr_sent = stats.path.sent_packets;
                            let rtt_ms = stats.path.rtt.as_millis() as u64;

                            // Compute delta loss (per-interval, not cumulative)
                            // First sample initializes baseline, subsequent samples compute delta
                            let maybe_delta = {
                                let mut prev = prev_quic_stats.lock().unwrap();
                                match *prev {
                                    None => {
                                        // First sample: initialize baseline, skip processing
                                        *prev = Some((curr_lost, curr_sent));
                                        None
                                    }
                                    Some((prev_lost, prev_sent)) => {
                                        *prev = Some((curr_lost, curr_sent));
                                        Some((
                                            curr_lost.saturating_sub(prev_lost),
                                            curr_sent.saturating_sub(prev_sent),
                                        ))
                                    }
                                }
                            };

                            // Skip ABR processing on first sample
                            let Some((delta_lost, delta_sent)) = maybe_delta else {
                                continue;
                            };

                            let loss_pct = if delta_sent > 0 {
                                (delta_lost as f64 / delta_sent as f64) * 100.0
                            } else {
                                0.0
                            };

                            let mut ctrl = controller.lock().unwrap();
                            if let Some(change) = ctrl.process(loss_pct, rtt_ms) {
                                let mut state = pipeline_state.lock().unwrap();
                                let (action, step) = match change {
                                    QualityChange::StepDown(s) => ("down", s),
                                    QualityChange::StepUp(s) => ("up", s),
                                };

                                // Apply resolution and framerate changes together via capsfilter
                                // (matches manual command behavior)
                                let res_changed = step.width != state.params.width
                                    || step.height != state.params.height;
                                let fps_changed = Some(step.framerate) != state.params.framerate;

                                if res_changed || fps_changed {
                                    state.params.width = step.width;
                                    state.params.height = step.height;
                                    state.params.framerate = Some(step.framerate);

                                    // Build caps with resolution and framerate
                                    if let Some(ref caps) = state.capsfilter {
                                        let new_caps = gstreamer::Caps::builder("video/x-raw")
                                            .field("width", step.width)
                                            .field("height", step.height)
                                            .field("framerate", gstreamer::Fraction::new(step.framerate, 1))
                                            .build();
                                        caps.set_property("caps", &new_caps);
                                    }

                                    // Also set videorate max-rate for consistency
                                    if let Some(ref rate) = state.videorate {
                                        rate.set_property("max-rate", step.framerate);
                                    }
                                }

                                // Apply bitrate change
                                // Step down: use floor bitrate. Step up: use target bitrate
                                let new_bitrate = if action == "down" {
                                    step.min_bitrate
                                } else {
                                    // When stepping up, use target bitrate from config
                                    config.adaptive.as_ref().map(|a| a.target_bitrate).unwrap_or(step.min_bitrate)
                                };
                                if new_bitrate != state.params.bitrate {
                                    state.params.bitrate = new_bitrate;
                                    if let Some(ref encoder) = state.encoder {
                                        encoder.set_property("bitrate", new_bitrate);
                                    }
                                }

                                println!(
                                    "[ABR] Quality {} to {}x{}@{}fps, {} kbps (loss={:.1}%, rtt={}ms)",
                                    action,
                                    step.width,
                                    step.height,
                                    step.framerate,
                                    new_bitrate,
                                    loss_pct,
                                    rtt_ms
                                );
                            }
                        }

                        // Check recorder health
                        if let Some(ref mut rec) = recorder {
                            if let Err(e) = rec.check_and_restart() {
                                eprintln!("Recorder error: {}", e);
                            }
                            // Encrypt completed segments if encryption is enabled
                            if let Some(ref mut enc) = segment_encryptor {
                                match enc.process_completed() {
                                    Ok(count) if count > 0 => {
                                        // Encrypted segments logged by encryptor
                                    }
                                    Err(e) => {
                                        eprintln!("Encryption error: {}", e);
                                    }
                                    _ => {}
                                }
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
                    _ = heartbeat_interval.tick() => {
                        // Check for ACK timeout first
                        if conn_state.awaiting_ack {
                            if let Some(sent_time) = conn_state.last_heartbeat_sent {
                                let elapsed = sent_time.elapsed().as_secs();
                                if elapsed > HEARTBEAT_TIMEOUT_SECS {
                                    println!("[HEARTBEAT] Timeout - no ACK received in {}s", elapsed);
                                    break;
                                }
                            }
                            // Still waiting for ACK, don't send another heartbeat yet
                            continue;
                        }

                        // Send new heartbeat
                        let timestamp = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64;
                        let heartbeat = format!("HEARTBEAT|{}", timestamp);

                        match connection.open_uni().await {
                            Ok(mut send_stream) => {
                                if send_stream.write_all(heartbeat.as_bytes()).await.is_ok() {
                                    let _ = send_stream.finish();
                                    conn_state.last_heartbeat_sent = Some(Instant::now());
                                    conn_state.awaiting_ack = true;
                                }
                            }
                            Err(e) => {
                                println!("[HEARTBEAT] Failed to send: {}", e);
                                break;
                            }
                        }
                    }
                }
            }

            // Disconnected - will reconnect
            println!("[{}] Video stream ended, sent {} frames", config.node_name, frame_count);
        } else if response.starts_with("DENIED") {
            println!("Denied by central node: {}", response);
            break 'reconnect;  // Exit on denial - don't retry
        } else {
            println!("Unexpected response: {}", response);
        }

        // Wait before reconnecting
        println!("Reconnecting in {} seconds...", RECONNECT_INTERVAL_SECS);
        tokio::time::sleep(Duration::from_secs(RECONNECT_INTERVAL_SECS)).await;
    } // end of 'reconnect loop

    // Stop recorder if running
    if let Some(ref mut rec) = recorder {
        println!("Stopping recorder...");
        if let Err(e) = rec.stop() {
            eprintln!("Failed to stop recorder: {}", e);
        }
    }

    // Encrypt any remaining segments on shutdown
    if let Some(ref mut enc) = segment_encryptor {
        println!("Finalizing segment encryption...");
        match enc.finalize() {
            Ok(count) if count > 0 => println!("Encrypted {} remaining segment(s)", count),
            Err(e) => eprintln!("Failed to finalize encryption: {}", e),
            _ => {}
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

