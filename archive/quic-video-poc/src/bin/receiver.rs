//! POC Receiver: QUIC → appsrc → RTSP server
//!
//! Usage: poc-receiver [port]
//! Example: poc-receiver 5001
//!
//! Then connect with: ffplay rtsp://127.0.0.1:8554/stream

use anyhow::Result;
use gstreamer::prelude::*;
use gstreamer_app::AppSrc;
use gstreamer_rtsp_server::prelude::*;
use quinn::{Endpoint, ServerConfig};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

fn main() -> Result<()> {
    // Parse args
    let args: Vec<String> = env::args().collect();
    let port: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5001);

    // Initialize GStreamer
    gstreamer::init()?;
    let _ = rustls::crypto::ring::default_provider().install_default();

    println!("=== QUIC Video POC - Receiver ===");
    println!();

    // Create RTSP server
    let rtsp_server = gstreamer_rtsp_server::RTSPServer::new();
    rtsp_server.set_service("8554");
    let mounts = rtsp_server.mount_points().expect("Failed to get mount points");

    // Shared state: cached keyframe and channel sender
    let cached_keyframe: Arc<std::sync::Mutex<Option<quic_video::VideoFrame>>> =
        Arc::new(std::sync::Mutex::new(None));
    let frame_tx: Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<quic_video::VideoFrame>>>> =
        Arc::new(std::sync::Mutex::new(None));

    let frame_tx_clone = Arc::clone(&frame_tx);
    let cached_keyframe_clone = Arc::clone(&cached_keyframe);

    // Create factory with appsrc pipeline
    // do-timestamp=true - let GStreamer handle timestamping based on arrival time
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

                // Get cached keyframe to push first
                let cached = cached_keyframe_clone.lock().unwrap().clone();

                // Spawn thread to push frames to appsrc
                // With do-timestamp=true, GStreamer handles timestamps based on arrival time
                std::thread::spawn(move || {
                    let mut pushed = 0u64;
                    let mut waiting_for_keyframe = true;

                    // Don't use cached keyframe - wait for live stream keyframe
                    if cached.is_some() {
                        println!("  [appsrc] Ignoring cached keyframe, waiting for live keyframe");
                    } else {
                        println!("  [appsrc] No cached keyframe, waiting for live keyframe");
                    }

                    while let Ok(frame) = rx.recv() {
                        // Skip until we get a keyframe
                        if waiting_for_keyframe {
                            if !frame.is_keyframe {
                                continue;
                            }
                            waiting_for_keyframe = false;
                            println!("  [appsrc] Got live keyframe, starting playback");
                        }

                        // Create buffer - do_timestamp=true will set PTS based on arrival
                        let mut buffer = gstreamer::Buffer::from_slice(frame.data.clone());
                        {
                            let buffer_ref = buffer.get_mut().unwrap();
                            if !frame.is_keyframe {
                                buffer_ref.set_flags(gstreamer::BufferFlags::DELTA_UNIT);
                            }
                        }

                        if appsrc.push_buffer(buffer).is_ok() {
                            pushed += 1;
                            if pushed % 30 == 0 {
                                println!("  [appsrc] Pushed {} buffers", pushed);
                            }
                        } else {
                            println!("  [appsrc] Push error");
                            break;
                        }
                    }
                    println!("  [appsrc] Thread exiting after {} buffers", pushed);
                });

                println!("RTSP media configured with appsrc");
            }
        }
    });

    mounts.add_factory("/stream", factory);

    // Run GLib main loop in background thread
    let main_loop = glib::MainLoop::new(None, false);
    let main_loop_clone = main_loop.clone();

    // Attach RTSP server and start main loop
    let _rtsp_id = rtsp_server.attach(None).expect("Failed to attach RTSP server");

    std::thread::spawn(move || {
        main_loop_clone.run();
    });

    // Give GLib a moment
    std::thread::sleep(std::time::Duration::from_millis(100));

    println!("RTSP server started on port 8554");
    println!("View stream: ffplay rtsp://127.0.0.1:8554/stream");
    println!();

    // Run tokio runtime for QUIC
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run_quic_server(port, frame_tx, cached_keyframe))?;

    main_loop.quit();
    Ok(())
}

async fn run_quic_server(
    port: u16,
    frame_tx: Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<quic_video::VideoFrame>>>>,
    cached_keyframe: Arc<std::sync::Mutex<Option<quic_video::VideoFrame>>>,
) -> Result<()> {
    // Generate self-signed certificate
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()])?;
    let cert = cert_params.self_signed(&key_pair)?;

    let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())];
    let key = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("key error: {}", e))?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    server_crypto.alpn_protocols = vec![];

    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?;
    let server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;

    println!("QUIC server listening on port {}", port);
    println!("Waiting for sender connection...");
    println!();

    // Accept connection
    let incoming = endpoint
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!("no connection"))?;
    let connection = incoming.await?;
    println!("Sender connected from {}", connection.remote_address());

    // Accept video stream
    let mut video_stream = connection.accept_uni().await?;
    println!("Video stream received, processing frames...");
    println!();

    let mut frame_count = 0u64;
    let mut bytes_received = 0u64;
    let start = std::time::Instant::now();

    // Receive frames
    let mut buffer = Vec::new();
    loop {
        // Read length prefix (4 bytes)
        while buffer.len() < 4 {
            match video_stream.read_chunk(4096, false).await? {
                Some(chunk) => buffer.extend_from_slice(&chunk.bytes),
                None => {
                    println!("Stream ended");
                    return Ok(());
                }
            }
        }
        let frame_len = u32::from_be_bytes(buffer[..4].try_into().unwrap()) as usize;
        buffer.drain(..4);

        // Read frame data
        while buffer.len() < frame_len {
            match video_stream.read_chunk(4096, false).await? {
                Some(chunk) => buffer.extend_from_slice(&chunk.bytes),
                None => {
                    println!("Stream ended during frame read");
                    return Ok(());
                }
            }
        }
        let frame_data: Vec<u8> = buffer.drain(..frame_len).collect();

        // Decode frame
        let frame = quic_video::VideoFrame::decode(&frame_data)?;

        frame_count += 1;
        bytes_received += (4 + frame_len) as u64;

        // Cache keyframes for new RTSP clients
        if frame.is_keyframe {
            *cached_keyframe.lock().unwrap() = Some(frame.clone());
        }

        // Send to RTSP pipeline
        if let Some(tx) = frame_tx.lock().unwrap().as_ref() {
            let _ = tx.send(frame.clone());
        }

        // Print stats every 30 frames
        if frame_count % 30 == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            let mbps = (bytes_received as f64 * 8.0) / (elapsed * 1_000_000.0);
            println!(
                "Received {} frames, {:.1} MB, {:.2} Mbps{}",
                frame_count,
                bytes_received as f64 / 1_000_000.0,
                mbps,
                if frame.is_keyframe { " [KEY]" } else { "" }
            );
        }
    }
}
