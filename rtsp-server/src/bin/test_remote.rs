//! Test Remote - Fake ONVIF Camera with Test Card
//!
//! Simulates an ONVIF camera for testing:
//! - RTSP server with videotestsrc (port 8555)
//! - ONVIF HTTP server for PTZ commands (port 8081)
//! - QUIC client to connect to central

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
use gstreamer_rtsp_server::prelude::*;
use onvif_server::{extract_position, extract_soap_action, extract_velocity, get_local_ip, soap_fault};
use quinn::{ClientConfig, Endpoint};
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

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

/// Shared state for the test camera
#[derive(Default)]
struct TestCameraState {
    position: PtzPosition,
    moving: bool,
    velocity: PtzPosition,
    // Pipeline elements for dynamic control
    capsfilter: Option<gstreamer::Element>,
    encoder: Option<gstreamer::Element>,
    params: StreamParams,
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let node_name = args.get(1).map(|s| s.as_str()).unwrap_or("test-cam");
    let central_addr = args.get(2).map(|s| s.as_str());
    let rtsp_port = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(8555u16);
    let onvif_port = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(8082u16);

    println!("==========================================");
    println!("TEST REMOTE - Fake ONVIF Camera");
    println!("==========================================");
    println!();
    println!("Usage: test_remote [name] [central:port] [rtsp_port] [onvif_port]");
    println!();
    println!("Configuration:");
    println!("  Node name:   {}", node_name);
    println!("  RTSP port:   {}", rtsp_port);
    println!("  ONVIF port:  {}", onvif_port);
    if let Some(addr) = &central_addr {
        println!("  Central:     {}", addr);
    } else {
        println!("  Central:     (standalone mode)");
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
            rtsp_port,
            onvif_port,
        ))
}

async fn async_main(
    node_name: String,
    central_addr: Option<String>,
    rtsp_port: u16,
    onvif_port: u16,
) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Shared camera state
    let camera_state = Arc::new(Mutex::new(TestCameraState::default()));

    // Create RTSP server with test pattern
    let rtsp_server = gstreamer_rtsp_server::RTSPServer::new();
    rtsp_server.set_service(&rtsp_port.to_string());
    let mounts = rtsp_server.mount_points().expect("Failed to get mount points");

    // Create factory with test pattern - dynamic pipeline like real remote
    let factory = gstreamer_rtsp_server::RTSPMediaFactory::new();
    let params = camera_state.lock().unwrap().params.clone();
    let pipeline = format!(
        "( videotestsrc is-live=true pattern=smpte \
           ! video/x-raw,width=1920,height=1080,framerate=30/1 \
           ! videoconvert \
           ! videoscale \
           ! videorate \
           ! capsfilter name=caps caps=video/x-raw,width={},height={},framerate={}/1 \
           ! x264enc name=encoder bitrate={} tune=zerolatency speed-preset=ultrafast \
           ! rtph264pay name=pay0 pt=96 )",
        params.width, params.height, params.framerate, params.bitrate
    );
    factory.set_launch(&pipeline);
    factory.set_shared(true);

    // Capture element references when media is configured
    let state_clone = Arc::clone(&camera_state);
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

    // Get local IP for RTSP URL
    let local_ip = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    let rtsp_url = format!("rtsp://{}:{}/stream", local_ip, rtsp_port);

    // Run GLib main loop and RTSP server in a separate thread
    let main_loop = glib::MainLoop::new(None, false);
    let main_loop_clone = main_loop.clone();
    std::thread::spawn(move || {
        // Attach RTSP server in the GLib thread context
        let _rtsp_id = rtsp_server.attach(None).expect("Failed to attach RTSP server");
        main_loop_clone.run();
    });

    // Give the GLib loop a moment to start
    std::thread::sleep(std::time::Duration::from_millis(100));

    println!("RTSP server started");
    println!("  Stream URL: {}", rtsp_url);
    println!();

    // Start ONVIF HTTP server
    let camera_state_clone = Arc::clone(&camera_state);
    let onvif_addr: SocketAddr = format!("0.0.0.0:{}", onvif_port).parse()?;

    tokio::spawn(async move {
        if let Err(e) = run_onvif_server(onvif_addr, camera_state_clone).await {
            eprintln!("ONVIF server error: {}", e);
        }
    });

    println!("ONVIF server started");
    println!("  Device service: http://{}:{}/onvif/device_service", local_ip, onvif_port);
    println!("  Media service:  http://{}:{}/onvif/media_service", local_ip, onvif_port);
    println!("  PTZ service:    http://{}:{}/onvif/ptz_service", local_ip, onvif_port);
    println!();

    // Connect to central if specified
    if let Some(central) = central_addr {
        println!("Connecting to central node at {}...", central);

        // Generate Ed25519 keypair for fingerprinting
        let secret_bytes: [u8; 32] = rand::random();
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key: VerifyingKey = (&signing_key).into();
        let fingerprint = hex::encode(verifying_key.as_bytes());

        println!("Fingerprint: {}", &fingerprint[..32]);

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

        let remote_addr: SocketAddr = central.parse()?;
        let connection = endpoint
            .connect_with(client_config, remote_addr, "localhost")?
            .await?;

        // Use the local address from the QUIC connection for RTSP URL
        // This ensures we advertise the correct IP (e.g., Tailscale IP when connecting over Tailscale)
        let connection_local_ip = connection.local_ip().map(|ip| ip.to_string())
            .unwrap_or_else(|| local_ip.clone());
        let advertised_rtsp_url = format!("rtsp://{}:{}/stream", connection_local_ip, rtsp_port);

        println!("Connected to central node");
        println!("Advertising RTSP URL: {}", advertised_rtsp_url);

        // Send authentication
        let mut send_stream = connection.open_uni().await?;
        let auth_request = format!("AUTH|{}|{}|{}", node_name, fingerprint, advertised_rtsp_url);
        send_stream.write_all(auth_request.as_bytes()).await?;
        send_stream.finish()?;

        println!("Authentication sent, waiting for approval...");

        // Wait for response
        let mut recv_stream = connection.accept_uni().await?;
        let buffer = recv_stream.read_to_end(1024 * 1024).await?;
        let response = String::from_utf8_lossy(&buffer);

        if response.starts_with("APPROVED") {
            println!("Approved by central node!");

            // Send confirmation
            let mut confirm_stream = connection.open_uni().await?;
            let confirmation = format!("CONFIRM|{}|Ready - Test Camera (SMPTE pattern)", node_name);
            confirm_stream.write_all(confirmation.as_bytes()).await?;
            confirm_stream.finish()?;

            println!();
            println!("==========================================");
            println!("READY - Listening for commands");
            println!("==========================================");
            println!();

            // Command loop
            loop {
                match connection.accept_uni().await {
                    Ok(mut recv_stream) => {
                        let buffer = recv_stream.read_to_end(1024 * 1024).await?;
                        let msg = String::from_utf8_lossy(&buffer);

                        if msg.starts_with("CMD|") {
                            let cmd = msg.strip_prefix("CMD|").unwrap_or("");
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
        } else if response.starts_with("DENIED") {
            println!("Denied by central node: {}", response);
        } else {
            println!("Unexpected response: {}", response);
        }
    } else {
        // Standalone mode - just run RTSP and ONVIF servers
        println!("Running in standalone mode (no central connection)");
        println!("Press Ctrl+C to exit");
        println!();

        // Keep running
        tokio::signal::ctrl_c().await?;
        println!("\nShutting down...");
    }

    main_loop.quit();
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
                let new_caps = gstreamer::Caps::builder("video/x-raw")
                    .field("width", width)
                    .field("height", height)
                    .field("framerate", gstreamer::Fraction::new(camera.params.framerate, 1))
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

            camera.params.framerate = fps;

            if let Some(ref caps) = camera.capsfilter {
                let new_caps = gstreamer::Caps::builder("video/x-raw")
                    .field("width", camera.params.width)
                    .field("height", camera.params.height)
                    .field("framerate", gstreamer::Fraction::new(fps, 1))
                    .build();
                caps.set_property("caps", &new_caps);
                Ok(format!("Framerate changed to {} fps", fps))
            } else {
                Err("Pipeline not ready (no clients connected?)".to_string())
            }
        }

        "params" | "stream" => {
            Ok(format!(
                "Stream: {}x{} @ {} fps, {} kbps",
                camera.params.width, camera.params.height,
                camera.params.framerate, camera.params.bitrate
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

