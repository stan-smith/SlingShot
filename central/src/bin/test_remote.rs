//! Test Remote - Fake ONVIF Camera with Test Card or File Source
//!
//! Simulates an ONVIF camera for testing:
//! - Generates test pattern video via GStreamer (default)
//! - Or plays a video file on loop (with --file option)
//! - Streams video over QUIC (stream-per-frame) to central
//! - ONVIF HTTP server for PTZ commands (port 8082)

use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Router,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use gstreamer::prelude::*;
use gstreamer_app::AppSink;
use onvif_server::{extract_position, extract_soap_action, extract_velocity, get_local_ip};
use quick_xml::escape::escape;

/// Escape a string for safe inclusion in XML content/attributes.
fn xml_escape(s: &str) -> String {
    escape(s).to_string()
}

/// Generate SOAP fault response
fn soap_fault(code: &str, reason: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Body>
    <s:Fault>
      <s:Code>
        <s:Value>s:Sender</s:Value>
        <s:Subcode>
          <s:Value>{}</s:Value>
        </s:Subcode>
      </s:Code>
      <s:Reason>
        <s:Text xml:lang="en">{}</s:Text>
      </s:Reason>
    </s:Fault>
  </s:Body>
</s:Envelope>"#,
        xml_escape(code),
        xml_escape(reason)
    )
}
use quinn::Endpoint;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Simulated PTZ position
#[derive(Debug, Clone, Copy, Default)]
struct PtzPosition {
    pan: f32,
    tilt: f32,
    zoom: f32,
}

/// Dynamic stream parameters
#[derive(Clone)]
struct StreamParams {
    width: i32,
    height: i32,
    /// Target framerate (None = use source default)
    framerate: Option<i32>,
    bitrate: u32,
}

impl Default for StreamParams {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
            framerate: None,  // Use source default (30fps for test pattern)
            bitrate: 4000,
        }
    }
}

/// Default source framerate for test pattern
const DEFAULT_SOURCE_FRAMERATE: i32 = 30;

/// Shared state for the test camera
struct TestCameraState {
    position: PtzPosition,
    moving: bool,
    velocity: PtzPosition,
    // Pipeline elements for dynamic control
    capsfilter: Option<gstreamer::Element>,
    encoder: Option<gstreamer::Element>,
    videorate: Option<gstreamer::Element>,
    params: StreamParams,
    /// Detected source framerate (for fps command validation)
    source_framerate: i32,
}

impl Default for TestCameraState {
    fn default() -> Self {
        Self {
            position: PtzPosition::default(),
            moving: false,
            velocity: PtzPosition::default(),
            capsfilter: None,
            encoder: None,
            videorate: None,
            params: StreamParams::default(),
            source_framerate: DEFAULT_SOURCE_FRAMERATE,
        }
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    // Parse arguments: test_remote [name] [central:port] [--file path]
    let node_name = args.get(1).map(|s| s.as_str()).unwrap_or("test-cam");
    let central_addr = args.get(2).map(|s| s.as_str());

    // Parse --file option (can appear anywhere after positional args)
    let file_source: Option<PathBuf> = args.iter()
        .position(|a| a == "--file")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);

    // ONVIF port defaults to 8082
    let onvif_port = args.get(3)
        .filter(|s| !s.starts_with("--"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(8082u16);

    println!("~ TEST REMOTE - Fake ONVIF Camera (QUIC) ~");
    println!();
    println!("Usage: test_remote [name] [central:port] [--file path]");
    println!();
    println!("Configuration:");
    println!("  Node name:   {}", node_name);
    println!("  ONVIF port:  {}", onvif_port);
    if let Some(addr) = &central_addr {
        println!("  Central:     {}", addr);
    } else {
        println!("  Central:     (required for QUIC streaming)");
    }
    if let Some(ref path) = file_source {
        println!("  File source: {}", path.display());
    } else {
        println!("  Source:      SMPTE test pattern");
    }
    println!();

    // Initialize GStreamer
    gstreamer::init()?;

    // Run async runtime
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main(
            node_name.to_string(),
            central_addr.map(|s| s.to_string()),
            onvif_port,
            file_source,
        ))
}

async fn async_main(
    node_name: String,
    central_addr: Option<String>,
    onvif_port: u16,
    file_source: Option<PathBuf>,
) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Require central address for QUIC streaming
    let central = match central_addr {
        Some(addr) => addr,
        None => {
            eprintln!("Error: central address required for QUIC streaming");
            eprintln!("Usage: test_remote [name] [central:port] [--file path]");
            return Ok(());
        }
    };

    // Shared camera state
    let camera_state = Arc::new(Mutex::new(TestCameraState::default()));

    // Channel for video frames (matches real remote)
    let (frame_tx, mut frame_rx) = mpsc::channel::<quic_video::VideoFrame>(30);
    let seq = Arc::new(AtomicU32::new(0));

    // Build GStreamer pipeline
    let pipe = gstreamer::Pipeline::new();
    let params = camera_state.lock().unwrap().params.clone();

    // Common elements for both source types
    let convert = gstreamer::ElementFactory::make("videoconvert").build()?;
    let scale = gstreamer::ElementFactory::make("videoscale").build()?;
    // Configure videorate to only drop frames, never duplicate (prevents buffering)
    let rate = gstreamer::ElementFactory::make("videorate")
        .property("drop-only", true)
        .property("skip-to-first", true)
        .build()?;

    // Capsfilter: set resolution and force I420 format for browser HLS compatibility
    // (videotestsrc outputs formats that x264 encodes to High 4:4:4 which browsers can't play)
    let capsfilter = gstreamer::ElementFactory::make("capsfilter")
        .name("caps")
        .property("caps", gstreamer::Caps::builder("video/x-raw")
            .field("format", "I420")
            .field("width", params.width).field("height", params.height)
            .build())
        .build()?;

    let encoder = gstreamer::ElementFactory::make("x264enc")
        .name("encoder")
        .property("bitrate", params.bitrate)
        .property_from_str("tune", "zerolatency")
        .property_from_str("speed-preset", "ultrafast")
        .property("key-int-max", 30u32)
        .build()?;

    let parser = gstreamer::ElementFactory::make("h264parse").build()?;
    let sink = gstreamer::ElementFactory::make("appsink").build()?.dynamic_cast::<AppSink>().unwrap();
    // For file playback: sync=true to respect timestamps and play at correct speed
    // For live sources: sync=false to minimize latency
    sink.set_sync(file_source.is_some());
    sink.set_max_buffers(30);
    sink.set_drop(false);
    sink.set_caps(Some(&gstreamer::Caps::builder("video/x-h264")
        .field("stream-format", "byte-stream").field("alignment", "au").build()));

    // Build source-specific pipeline
    if let Some(ref file_path) = file_source {
        // File source pipeline: filesrc -> qtdemux -> h264parse -> avdec_h264 -> convert -> ...
        // Uses explicit software decoding (avdec_h264) to match real remote binary behavior
        // and avoid hardware decoder issues (e.g., amlv4l2h264dec on ARM/Amlogic)
        let filesrc = gstreamer::ElementFactory::make("filesrc")
            .property("location", file_path.canonicalize()?.to_str().unwrap())
            .build()?;
        let demux = gstreamer::ElementFactory::make("qtdemux").build()?;
        let h264parse_in = gstreamer::ElementFactory::make("h264parse").build()?;
        let decoder = gstreamer::ElementFactory::make("avdec_h264").build()?;

        pipe.add_many([&filesrc, &demux, &h264parse_in, &decoder, &convert, &scale, &rate, &capsfilter, &encoder, &parser, sink.upcast_ref()])?;
        // Link static elements
        gstreamer::Element::link_many([&filesrc, &demux])?;
        gstreamer::Element::link_many([&h264parse_in, &decoder, &convert, &scale, &rate, &capsfilter, &encoder, &parser, sink.upcast_ref()])?;

        // Handle dynamic pad from qtdemux (video stream)
        let h264parse_weak = h264parse_in.downgrade();
        demux.connect_pad_added(move |_demux, src_pad| {
            let Some(h264parse) = h264parse_weak.upgrade() else { return };

            // Only link video pads (h264)
            let caps = src_pad.current_caps().or_else(|| Some(src_pad.query_caps(None)));
            if let Some(caps) = caps {
                if let Some(structure) = caps.structure(0) {
                    if !structure.name().as_str().contains("h264") && !structure.name().as_str().starts_with("video/x-h264") {
                        return; // Skip non-h264 pads (audio, etc.)
                    }
                }
            }

            let sink_pad = h264parse.static_pad("sink").unwrap();
            if sink_pad.is_linked() {
                return;
            }
            if let Err(e) = src_pad.link(&sink_pad) {
                eprintln!("Failed to link qtdemux pad: {:?}", e);
            } else {
                println!("Linked video pad from file");
            }
        });
    } else {
        // Test pattern pipeline: videotestsrc -> srccaps -> textoverlay -> convert -> scale -> rate -> ...
        let src = gstreamer::ElementFactory::make("videotestsrc")
            .property("is-live", true)
            .property_from_str("pattern", "smpte")
            .build()?;
        let srccaps = gstreamer::ElementFactory::make("capsfilter")
            .property("caps", gstreamer::Caps::builder("video/x-raw")
                .field("width", 1920i32).field("height", 1080i32)
                .field("framerate", gstreamer::Fraction::new(30, 1)).build())
            .build()?;

        // Text overlay showing instance name for easy identification
        let textoverlay = gstreamer::ElementFactory::make("textoverlay")
            .property("text", node_name.as_str())
            .property("font-desc", "Sans Bold 48")
            .property_from_str("valignment", "top")
            .property_from_str("halignment", "left")
            .property("shaded-background", true)
            .build()?;

        pipe.add_many([&src, &srccaps, &textoverlay, &convert, &scale, &rate, &capsfilter, &encoder, &parser, sink.upcast_ref()])?;
        gstreamer::Element::link_many([&src, &srccaps, &textoverlay, &convert, &scale, &rate, &capsfilter, &encoder, &parser, sink.upcast_ref()])?;
    }

    // Store element references for dynamic control
    {
        let mut state = camera_state.lock().unwrap();
        state.capsfilter = Some(capsfilter.clone());
        state.encoder = Some(encoder.clone());
        state.videorate = Some(rate.clone());
    }

    // Set up appsink callback
    let seq2 = Arc::clone(&seq);
    sink.set_callbacks(gstreamer_app::AppSinkCallbacks::builder()
        .new_sample(move |s| {
            let sample = s.pull_sample().map_err(|_| gstreamer::FlowError::Error)?;
            let buf = sample.buffer().ok_or(gstreamer::FlowError::Error)?;
            let map = buf.map_readable().map_err(|_| gstreamer::FlowError::Error)?;
            let n = seq2.fetch_add(1, Ordering::Relaxed);
            let pts = buf.pts().map(|t| t.nseconds() / 11111).unwrap_or(0);
            let key = !buf.flags().contains(gstreamer::BufferFlags::DELTA_UNIT);
            let _ = frame_tx.try_send(quic_video::VideoFrame::new(n, pts, key, map.to_vec()));
            Ok(gstreamer::FlowSuccess::Ok)
        }).build());

    // Bus message handler (with EOS handling for file loop)
    let bus = pipe.bus().unwrap();
    let node_name_bus = node_name.clone();
    let pipe_weak = pipe.downgrade();
    let is_file_source = file_source.is_some();
    std::thread::spawn(move || {
        for msg in bus.iter_timed(gstreamer::ClockTime::NONE) {
            match msg.view() {
                gstreamer::MessageView::Error(e) => {
                    eprintln!("[{}] GST ERROR: {} {:?}", node_name_bus, e.error(), e.debug());
                }
                gstreamer::MessageView::StateChanged(s) => {
                    if msg.src().map(|e| e.name().as_str().starts_with("pipeline")).unwrap_or(false) {
                        println!("[{}] Pipeline: {:?} -> {:?}", node_name_bus, s.old(), s.current());
                    }
                }
                gstreamer::MessageView::Eos(_) => {
                    // Loop file playback by seeking back to start
                    if is_file_source {
                        if let Some(pipe) = pipe_weak.upgrade() {
                            println!("[{}] End of file, looping...", node_name_bus);
                            let _ = pipe.seek_simple(
                                gstreamer::SeekFlags::FLUSH | gstreamer::SeekFlags::KEY_UNIT,
                                gstreamer::ClockTime::ZERO,
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    });

    pipe.set_state(gstreamer::State::Playing)?;
    let source_desc = if file_source.is_some() { "file source (looping)" } else { "SMPTE test pattern" };
    println!("GStreamer pipeline started ({})", source_desc);
    println!();

    // Get local IP
    let local_ip = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());

    // Start ONVIF HTTP server
    let camera_state_clone = Arc::clone(&camera_state);
    let onvif_addr: SocketAddr = format!("0.0.0.0:{}", onvif_port).parse()?;

    tokio::spawn(async move {
        if let Err(e) = run_onvif_server(onvif_addr, camera_state_clone).await {
            eprintln!("ONVIF server error: {}", e);
        }
    });

    println!("ONVIF server started");
    println!("  PTZ service: http://{}:{}/onvif/ptz_service", local_ip, onvif_port);
    println!();

    println!("Connecting to central node at {}...", central);

    // Generate Ed25519 keypair for fingerprinting
    let secret_bytes: [u8; 32] = rand::random();
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key: VerifyingKey = (&signing_key).into();
    let fingerprint = hex::encode(verifying_key.as_bytes());

    println!("Fingerprint: {}", &fingerprint[..32]);

    let (client_config, _verifier) = quic_common::create_pinning_client_config(None)?;

    let bind_addr: SocketAddr = "0.0.0.0:0".parse()?;
    let endpoint = Endpoint::client(bind_addr)?;

    let remote_addr: SocketAddr = central.parse()?;
    let connection = endpoint
        .connect_with(client_config, remote_addr, "localhost")?
        .await?;

    println!("Connected to central node");

    // Send authentication with VIDEO marker
    let mut send_stream = connection.open_uni().await?;
    let auth_request = format!("AUTH|{}|{}|VIDEO", node_name, fingerprint);
    send_stream.write_all(auth_request.as_bytes()).await?;
    send_stream.finish()?;

    println!("Authentication sent, waiting for approval...");

    // Wait for response
    let mut recv_stream = connection.accept_uni().await?;
    let buffer = recv_stream.read_to_end(1024 * 1024).await?;
    let response = String::from_utf8_lossy(&buffer);

    if !response.starts_with("APPROVED") {
        if response.starts_with("DENIED") {
            println!("Denied by central node: {}", response);
        } else {
            println!("Unexpected response: {}", response);
        }
        return Ok(());
    }

    println!("Approved by central node!");

    // Send confirmation
    let mut confirm_stream = connection.open_uni().await?;
    let confirmation = format!("CONFIRM|{}|Ready - Test Camera (SMPTE pattern)", node_name);
    confirm_stream.write_all(confirmation.as_bytes()).await?;
    confirm_stream.finish()?;

    // Send VIDEO_STREAM marker
    let mut marker_stream = connection.open_uni().await?;
    marker_stream.write_all(b"VIDEO_STREAM").await?;
    marker_stream.finish()?;

    println!();
    println!("~ READY - Streaming video (stream-per-frame) ~");
    println!();

    // Spawn video sender task - one QUIC stream per frame
    let node_name_video = node_name.clone();
    let conn_clone = connection.clone();
    let video_handle = tokio::spawn(async move {
        let mut frame_count = 0u64;
        let mut bytes_sent = 0u64;
        let mut last_report_time = std::time::Instant::now();
        let mut last_report_bytes = 0u64;

        while let Some(frame) = frame_rx.recv().await {
            let encoded = frame.encode();
            let frame_size = encoded.len();

            // Open new stream for this frame
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
                    node_name_video,
                    frame_count,
                    bytes_sent as f64 / 1_000_000.0,
                    mbps,
                    if frame.is_keyframe { " [KEY]" } else { "" }
                );

                last_report_time = now;
                last_report_bytes = bytes_sent;
            }
        }

        println!("[{}] Video stream ended", node_name_video);
    });

    // Command loop
    loop {
        match connection.accept_uni().await {
            Ok(mut recv_stream) => {
                let buffer = recv_stream.read_to_end(1024 * 1024).await?;
                let msg = String::from_utf8_lossy(&buffer);

                if msg.starts_with("CMD|") {
                    // Parse CMD|timestamp|command|signature format
                    // Extract just the command part (index 2)
                    let parts: Vec<&str> = msg.splitn(4, '|').collect();
                    let cmd = if parts.len() >= 3 {
                        parts[2]  // The actual command
                    } else {
                        msg.strip_prefix("CMD|").unwrap_or("")  // Fallback for legacy format
                    };
                    println!("Received command: {}", cmd);

                    let result = handle_command(cmd, &camera_state);

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

    video_handle.abort();
    pipe.set_state(gstreamer::State::Null)?;
    Ok(())
}

/// Handle commands from central (simulated PTZ)
fn handle_command(cmd: &str, state: &Arc<Mutex<TestCameraState>>) -> Result<String, String> {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.is_empty() {
        return Err("Empty command".to_string());
    }

    let mut camera = state.lock().unwrap();

    match parts[0].to_lowercase().as_str() {
        "ptz" | "move" => {
            let pan: f32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.0);
            let tilt: f32 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0.0);
            let zoom: f32 = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0.0);
            let duration: u64 = parts.get(4).and_then(|s| s.parse().ok()).unwrap_or(500);

            camera.velocity = PtzPosition { pan, tilt, zoom };
            camera.moving = true;

            // Simulate movement
            let step = duration as f32 / 1000.0;
            camera.position.pan = (camera.position.pan + pan * step).clamp(-1.0, 1.0);
            camera.position.tilt = (camera.position.tilt + tilt * step).clamp(-1.0, 1.0);
            camera.position.zoom = (camera.position.zoom + zoom * step).clamp(0.0, 1.0);

            camera.moving = false;
            camera.velocity = PtzPosition::default();

            Ok(format!(
                "[SIM] PTZ move complete. Position: pan={:.2}, tilt={:.2}, zoom={:.2}",
                camera.position.pan, camera.position.tilt, camera.position.zoom
            ))
        }

        "stop" => {
            camera.moving = false;
            camera.velocity = PtzPosition::default();
            Ok("[SIM] PTZ stopped".to_string())
        }

        "goto" => {
            if parts.len() < 4 {
                return Err("Usage: goto <pan> <tilt> <zoom>".to_string());
            }
            let pan: f32 = parts[1].parse().map_err(|_| "Invalid pan")?;
            let tilt: f32 = parts[2].parse().map_err(|_| "Invalid tilt")?;
            let zoom: f32 = parts[3].parse().map_err(|_| "Invalid zoom")?;

            camera.position = PtzPosition { pan, tilt, zoom };
            Ok(format!(
                "[SIM] Moved to position: pan={:.2}, tilt={:.2}, zoom={:.2}",
                pan, tilt, zoom
            ))
        }

        "status" | "pos" => Ok(format!(
            "[SIM] Position: pan={:.2}, tilt={:.2}, zoom={:.2}",
            camera.position.pan, camera.position.tilt, camera.position.zoom
        )),

        "info" => Ok("[SIM] Test Camera - SMPTE Pattern Generator".to_string()),

        "home" => {
            camera.position = PtzPosition::default();
            Ok("[SIM] Returned to home position".to_string())
        }

        "left" => {
            let speed: f32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.5);
            let duration: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(500);
            let step = duration as f32 / 1000.0;
            camera.position.pan = (camera.position.pan - speed * step).clamp(-1.0, 1.0);
            Ok(format!("[SIM] Panned left. Position: pan={:.2}", camera.position.pan))
        }

        "right" => {
            let speed: f32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.5);
            let duration: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(500);
            let step = duration as f32 / 1000.0;
            camera.position.pan = (camera.position.pan + speed * step).clamp(-1.0, 1.0);
            Ok(format!("[SIM] Panned right. Position: pan={:.2}", camera.position.pan))
        }

        "up" => {
            let speed: f32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.5);
            let duration: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(500);
            let step = duration as f32 / 1000.0;
            camera.position.tilt = (camera.position.tilt + speed * step).clamp(-1.0, 1.0);
            Ok(format!("[SIM] Tilted up. Position: tilt={:.2}", camera.position.tilt))
        }

        "down" => {
            let speed: f32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.5);
            let duration: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(500);
            let step = duration as f32 / 1000.0;
            camera.position.tilt = (camera.position.tilt - speed * step).clamp(-1.0, 1.0);
            Ok(format!("[SIM] Tilted down. Position: tilt={:.2}", camera.position.tilt))
        }

        "zoomin" | "zi" => {
            let speed: f32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.5);
            let duration: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(500);
            let step = duration as f32 / 1000.0;
            camera.position.zoom = (camera.position.zoom + speed * step).clamp(0.0, 1.0);
            Ok(format!("[SIM] Zoomed in. Position: zoom={:.2}", camera.position.zoom))
        }

        "zoomout" | "zo" => {
            let speed: f32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0.5);
            let duration: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(500);
            let step = duration as f32 / 1000.0;
            camera.position.zoom = (camera.position.zoom - speed * step).clamp(0.0, 1.0);
            Ok(format!("[SIM] Zoomed out. Position: zoom={:.2}", camera.position.zoom))
        }

        // Stream control - actually change the pipeline!
        "resolution" | "res" => {
            if parts.len() < 3 {
                return Err("Usage: resolution <width> <height>".to_string());
            }
            let width: i32 = parts[1].parse().map_err(|_| "Invalid width")?;
            let height: i32 = parts[2].parse().map_err(|_| "Invalid height")?;

            camera.params.width = width;
            camera.params.height = height;

            if let Some(ref caps) = camera.capsfilter {
                // Must include format I420 for browser HLS compatibility
                let new_caps = gstreamer::Caps::builder("video/x-raw")
                    .field("format", "I420")
                    .field("width", width)
                    .field("height", height)
                    .build();
                caps.set_property("caps", &new_caps);
                Ok(format!("Resolution changed to {}x{}", width, height))
            } else {
                Err("Pipeline not ready".to_string())
            }
        }

        "bitrate" | "br" => {
            if parts.len() < 2 {
                return Err("Usage: bitrate <kbps>".to_string());
            }
            let bitrate: u32 = parts[1].parse().map_err(|_| "Invalid bitrate")?;

            camera.params.bitrate = bitrate;

            if let Some(ref encoder) = camera.encoder {
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

            // Cannot increase above source framerate
            if fps > camera.source_framerate {
                return Err(format!(
                    "Cannot exceed source framerate of {} fps (can only reduce)",
                    camera.source_framerate
                ));
            }

            camera.params.framerate = Some(fps);

            // Use videorate's max-rate property instead of capsfilter
            if let Some(ref rate) = camera.videorate {
                rate.set_property("max-rate", fps);
                Ok(format!("Framerate limited to {} fps", fps))
            } else {
                Err("Pipeline not ready".to_string())
            }
        }

        "params" | "stream" => {
            let fps_str = match camera.params.framerate {
                Some(fps) => format!("{}", fps),
                None => format!("{} (source)", camera.source_framerate),
            };
            Ok(format!(
                "Stream: {}x{} @ {} fps, {} kbps",
                camera.params.width, camera.params.height,
                fps_str, camera.params.bitrate
            ))
        }

        _ => Err(format!("Unknown command: {}", parts[0])),
    }
}

/// Run ONVIF HTTP server
async fn run_onvif_server(
    addr: SocketAddr,
    state: Arc<Mutex<TestCameraState>>,
) -> Result<()> {
    let app = Router::new()
        .route("/onvif/device_service", post(handle_device_service))
        .route("/onvif/media_service", post(handle_media_service))
        .route("/onvif/ptz_service", post(handle_ptz_service))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Handle ONVIF Device Service requests
async fn handle_device_service(body: String) -> impl IntoResponse {
    let action = extract_soap_action(&body);
    println!("[ONVIF] Device service: {}", action);

    let response = match action.as_str() {
        "GetDeviceInformation" => {
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <s:Body>
    <tds:GetDeviceInformationResponse>
      <tds:Manufacturer>TestCam</tds:Manufacturer>
      <tds:Model>Virtual-PTZ</tds:Model>
      <tds:FirmwareVersion>1.0.0</tds:FirmwareVersion>
      <tds:SerialNumber>TEST-001</tds:SerialNumber>
      <tds:HardwareId>SMPTE-Generator</tds:HardwareId>
    </tds:GetDeviceInformationResponse>
  </s:Body>
</s:Envelope>"#.to_string()
        }

        "GetCapabilities" => {
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Body>
    <tds:GetCapabilitiesResponse>
      <tds:Capabilities>
        <tt:Media>
          <tt:XAddr>http://localhost:8081/onvif/media_service</tt:XAddr>
        </tt:Media>
        <tt:PTZ>
          <tt:XAddr>http://localhost:8081/onvif/ptz_service</tt:XAddr>
        </tt:PTZ>
      </tds:Capabilities>
    </tds:GetCapabilitiesResponse>
  </s:Body>
</s:Envelope>"#.to_string()
        }

        _ => soap_fault("ActionNotSupported", &format!("Unknown action: {}", action)),
    };

    (StatusCode::OK, [("Content-Type", "application/soap+xml")], response)
}

/// Handle ONVIF Media Service requests
async fn handle_media_service(body: String) -> impl IntoResponse {
    let action = extract_soap_action(&body);
    println!("[ONVIF] Media service: {}", action);

    let response = match action.as_str() {
        "GetProfiles" => {
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Body>
    <trt:GetProfilesResponse>
      <trt:Profiles token="profile_1" fixed="true">
        <tt:Name>MainStream</tt:Name>
        <tt:VideoSourceConfiguration token="vsrc_1">
          <tt:Name>VideoSource</tt:Name>
        </tt:VideoSourceConfiguration>
        <tt:VideoEncoderConfiguration token="venc_1">
          <tt:Name>H264</tt:Name>
          <tt:Encoding>H264</tt:Encoding>
          <tt:Resolution>
            <tt:Width>1920</tt:Width>
            <tt:Height>1080</tt:Height>
          </tt:Resolution>
          <tt:RateControl>
            <tt:FrameRateLimit>30</tt:FrameRateLimit>
            <tt:BitrateLimit>4000</tt:BitrateLimit>
          </tt:RateControl>
        </tt:VideoEncoderConfiguration>
        <tt:PTZConfiguration token="ptz_1">
          <tt:Name>PTZ</tt:Name>
        </tt:PTZConfiguration>
      </trt:Profiles>
    </trt:GetProfilesResponse>
  </s:Body>
</s:Envelope>"#.to_string()
        }

        "GetStreamUri" => {
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:trt="http://www.onvif.org/ver10/media/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Body>
    <trt:GetStreamUriResponse>
      <trt:MediaUri>
        <tt:Uri>rtsp://localhost:8555/stream</tt:Uri>
        <tt:InvalidAfterConnect>false</tt:InvalidAfterConnect>
        <tt:InvalidAfterReboot>false</tt:InvalidAfterReboot>
      </trt:MediaUri>
    </trt:GetStreamUriResponse>
  </s:Body>
</s:Envelope>"#.to_string()
        }

        _ => soap_fault("ActionNotSupported", &format!("Unknown action: {}", action)),
    };

    (StatusCode::OK, [("Content-Type", "application/soap+xml")], response)
}

/// Handle ONVIF PTZ Service requests
async fn handle_ptz_service(
    State(state): State<Arc<Mutex<TestCameraState>>>,
    body: String,
) -> impl IntoResponse {
    let action = extract_soap_action(&body);
    println!("[ONVIF] PTZ service: {}", action);

    let response = match action.as_str() {
        "ContinuousMove" => {
            let (pan, tilt, zoom) = extract_velocity(&body);
            println!("[ONVIF] ContinuousMove: pan={}, tilt={}, zoom={}", pan, tilt, zoom);

            let mut camera = state.lock().unwrap();
            camera.velocity = PtzPosition { pan, tilt, zoom };
            camera.moving = true;

            // Simulate a small movement
            camera.position.pan = (camera.position.pan + pan * 0.1).clamp(-1.0, 1.0);
            camera.position.tilt = (camera.position.tilt + tilt * 0.1).clamp(-1.0, 1.0);
            camera.position.zoom = (camera.position.zoom + zoom * 0.1).clamp(0.0, 1.0);

            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl">
  <s:Body>
    <tptz:ContinuousMoveResponse/>
  </s:Body>
</s:Envelope>"#.to_string()
        }

        "Stop" => {
            println!("[ONVIF] Stop");

            let mut camera = state.lock().unwrap();
            camera.moving = false;
            camera.velocity = PtzPosition::default();

            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl">
  <s:Body>
    <tptz:StopResponse/>
  </s:Body>
</s:Envelope>"#.to_string()
        }

        "AbsoluteMove" => {
            let (pan, tilt, zoom) = extract_position(&body);
            println!("[ONVIF] AbsoluteMove: pan={}, tilt={}, zoom={}", pan, tilt, zoom);

            let mut camera = state.lock().unwrap();
            camera.position = PtzPosition { pan, tilt, zoom };

            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl">
  <s:Body>
    <tptz:AbsoluteMoveResponse/>
  </s:Body>
</s:Envelope>"#.to_string()
        }

        "GetStatus" => {
            let camera = state.lock().unwrap();
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl"
            xmlns:tt="http://www.onvif.org/ver10/schema">
  <s:Body>
    <tptz:GetStatusResponse>
      <tptz:PTZStatus>
        <tt:Position>
          <tt:PanTilt x="{:.2}" y="{:.2}"/>
          <tt:Zoom x="{:.2}"/>
        </tt:Position>
        <tt:MoveStatus>
          <tt:PanTilt>{}</tt:PanTilt>
          <tt:Zoom>{}</tt:Zoom>
        </tt:MoveStatus>
      </tptz:PTZStatus>
    </tptz:GetStatusResponse>
  </s:Body>
</s:Envelope>"#,
                camera.position.pan,
                camera.position.tilt,
                camera.position.zoom,
                if camera.moving { "MOVING" } else { "IDLE" },
                if camera.moving { "MOVING" } else { "IDLE" }
            )
        }

        "GotoHomePosition" => {
            println!("[ONVIF] GotoHomePosition");

            let mut camera = state.lock().unwrap();
            camera.position = PtzPosition::default();

            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tptz="http://www.onvif.org/ver20/ptz/wsdl">
  <s:Body>
    <tptz:GotoHomePositionResponse/>
  </s:Body>
</s:Envelope>"#.to_string()
        }

        _ => soap_fault("ActionNotSupported", &format!("Unknown action: {}", action)),
    };

    (StatusCode::OK, [("Content-Type", "application/soap+xml")], response)
}

