//! POC Sender: videotestsrc → appsink → QUIC
//!
//! Usage: poc-sender <receiver-ip:port>
//! Example: poc-sender 127.0.0.1:5001

use anyhow::Result;
use gstreamer::prelude::*;
use gstreamer_app::AppSink;
use quinn::{ClientConfig, Endpoint};
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    // Parse args
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <receiver-ip:port>", args[0]);
        eprintln!("Example: {} 127.0.0.1:5001", args[0]);
        std::process::exit(1);
    }
    let receiver_addr: SocketAddr = args[1].parse()?;

    // Initialize GStreamer
    gstreamer::init()?;
    let _ = rustls::crypto::ring::default_provider().install_default();

    println!("=== QUIC Video POC - Sender ===");
    println!();

    // Create channel for video frames
    let (frame_tx, mut frame_rx) = mpsc::channel::<quic_video::VideoFrame>(30);

    // Create GStreamer pipeline: videotestsrc → x264enc → h264parse → appsink
    let pipeline = gstreamer::Pipeline::new();

    let src = gstreamer::ElementFactory::make("videotestsrc")
        .property_from_str("pattern", "ball")
        .property("is-live", true)
        .build()?;

    let capsfilter = gstreamer::ElementFactory::make("capsfilter")
        .property(
            "caps",
            gstreamer::Caps::builder("video/x-raw")
                .field("format", "I420") // Force 4:2:0 for compatible H.264 profile
                .field("width", 640i32)
                .field("height", 480i32)
                .field("framerate", gstreamer::Fraction::new(30, 1))
                .build(),
        )
        .build()?;

    let convert = gstreamer::ElementFactory::make("videoconvert").build()?;

    let encoder = gstreamer::ElementFactory::make("x264enc")
        .property_from_str("tune", "zerolatency")
        .property_from_str("speed-preset", "ultrafast")
        .property("bitrate", 2000u32)
        .property("key-int-max", 30u32) // keyframe every 30 frames
        .build()?;

    let parser = gstreamer::ElementFactory::make("h264parse").build()?;

    let appsink = gstreamer::ElementFactory::make("appsink")
        .build()?
        .dynamic_cast::<AppSink>()
        .unwrap();

    // Configure appsink
    appsink.set_sync(false);
    appsink.set_max_buffers(1);
    appsink.set_drop(true);
    appsink.set_caps(Some(
        &gstreamer::Caps::builder("video/x-h264")
            .field("stream-format", "byte-stream")
            .field("alignment", "au")
            .build(),
    ));

    // Add elements to pipeline
    pipeline.add_many([&src, &capsfilter, &convert, &encoder, &parser, appsink.upcast_ref()])?;
    gstreamer::Element::link_many([&src, &capsfilter, &convert, &encoder, &parser, appsink.upcast_ref()])?;

    // Set up appsink callback
    let frame_tx_clone = frame_tx.clone();
    appsink.set_callbacks(
        gstreamer_app::AppSinkCallbacks::builder()
            .new_sample(move |sink| {
                let sample = sink.pull_sample().map_err(|_| gstreamer::FlowError::Error)?;
                let buffer = sample.buffer().ok_or(gstreamer::FlowError::Error)?;
                let map = buffer.map_readable().map_err(|_| gstreamer::FlowError::Error)?;

                let pts = buffer.pts().map(|t| t.nseconds() / 11111).unwrap_or(0); // ns to 90kHz
                let is_keyframe = !buffer.flags().contains(gstreamer::BufferFlags::DELTA_UNIT);

                let frame = quic_video::VideoFrame::new(pts, is_keyframe, map.as_slice().to_vec());

                // Non-blocking send
                let _ = frame_tx_clone.try_send(frame);

                Ok(gstreamer::FlowSuccess::Ok)
            })
            .build(),
    );

    // Start pipeline
    pipeline.set_state(gstreamer::State::Playing)?;
    println!("Pipeline started (videotestsrc → x264enc → appsink)");

    // Connect to receiver via QUIC
    println!("Connecting to receiver at {}...", receiver_addr);

    let mut crypto = quic_common::insecure_client_config();
    crypto.alpn_protocols = vec![];

    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
    let client_config = ClientConfig::new(Arc::new(quic_config));

    let endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    let connection = endpoint
        .connect_with(client_config, receiver_addr, "localhost")?
        .await?;

    println!("Connected to receiver!");
    println!();

    // Open a unidirectional stream for video
    let mut video_stream = connection.open_uni().await?;
    println!("Video stream opened, sending frames...");

    let mut frame_count = 0u64;
    let mut bytes_sent = 0u64;
    let start = std::time::Instant::now();

    // Send frames over QUIC
    while let Some(frame) = frame_rx.recv().await {
        let encoded = frame.encode();
        let frame_size = encoded.len();

        // Write length prefix (4 bytes) + frame data
        let len_bytes = (frame_size as u32).to_be_bytes();
        video_stream.write_all(&len_bytes).await?;
        video_stream.write_all(&encoded).await?;

        frame_count += 1;
        bytes_sent += (4 + frame_size) as u64;

        // Print stats every 30 frames
        if frame_count % 30 == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            let mbps = (bytes_sent as f64 * 8.0) / (elapsed * 1_000_000.0);
            println!(
                "Sent {} frames, {:.1} MB, {:.2} Mbps{}",
                frame_count,
                bytes_sent as f64 / 1_000_000.0,
                mbps,
                if frame.is_keyframe { " [KEY]" } else { "" }
            );
        }
    }

    pipeline.set_state(gstreamer::State::Null)?;
    Ok(())
}
