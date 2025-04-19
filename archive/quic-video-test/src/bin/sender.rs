use anyhow::Result;
use gstreamer::prelude::*;
use gstreamer_app::AppSink;
use quinn::{ClientConfig, Endpoint};
use std::sync::{atomic::{AtomicU32, Ordering}, Arc};
use tokio::sync::mpsc;

const WIDTH: i32 = 1024;
const HEIGHT: i32 = 576;
const BITRATE: u32 = 3000;

#[tokio::main]
async fn main() -> Result<()> {
    gstreamer::init()?;
    rustls::crypto::ring::default_provider().install_default().ok();

    let (tx, mut rx) = mpsc::channel::<quic_video::VideoFrame>(60);
    let seq = Arc::new(AtomicU32::new(0));

    // Build pipeline manually like main binary
    let pipe = gstreamer::Pipeline::new();

    let src = gstreamer::ElementFactory::make("rtspsrc")
        .property("location", "rtsp://root:MINI_VScam00@192.168.2.90/onvif-media/media.amp?profile=profile_1_h264&sessiontimeout=60&streamtype=unicast")
        .property("latency", 0u32)
        .build()?;
    let depay = gstreamer::ElementFactory::make("rtph264depay").build()?;
    let decode = gstreamer::ElementFactory::make("avdec_h264").build()?;
    let convert = gstreamer::ElementFactory::make("videoconvert").build()?;
    let scale = gstreamer::ElementFactory::make("videoscale").build()?;
    let rate = gstreamer::ElementFactory::make("videorate").build()?;

    let capsfilter = gstreamer::ElementFactory::make("capsfilter")
        .property("caps", gstreamer::Caps::builder("video/x-raw")
            .field("width", WIDTH).field("height", HEIGHT)
            .field("framerate", gstreamer::Fraction::new(30, 1)).build())
        .build()?;

    let encoder = gstreamer::ElementFactory::make("x264enc")
        .property("bitrate", BITRATE)
        .property_from_str("tune", "zerolatency")
        .property_from_str("speed-preset", "ultrafast")
        .property("key-int-max", 30u32)
        .build()?;

    let parser = gstreamer::ElementFactory::make("h264parse").build()?;
    let sink = gstreamer::ElementFactory::make("appsink").build()?.dynamic_cast::<AppSink>().unwrap();
    sink.set_sync(false); sink.set_max_buffers(1); sink.set_drop(true);
    sink.set_caps(Some(&gstreamer::Caps::builder("video/x-h264")
        .field("stream-format", "byte-stream").field("alignment", "au").build()));

    pipe.add_many([&src, &depay, &decode, &convert, &scale, &rate, &capsfilter, &encoder, &parser, sink.upcast_ref()])?;
    gstreamer::Element::link_many([&depay, &decode, &convert, &scale, &rate, &capsfilter, &encoder, &parser, sink.upcast_ref()])?;

    // Dynamic pad linking for rtspsrc
    let depay2 = depay.clone();
    src.connect_pad_added(move |_, pad| {
        let name = pad.name();
        eprintln!("[TX] Pad added: {}", name);
        let sinkpad = depay2.static_pad("sink").unwrap();
        if !sinkpad.is_linked() {
            match pad.link(&sinkpad) {
                Ok(_) => eprintln!("[TX] Linked {} to depay", name),
                Err(e) => eprintln!("[TX] Failed to link {}: {:?}", name, e),
            }
        }
    });

    let seq2 = Arc::clone(&seq);
    sink.set_callbacks(gstreamer_app::AppSinkCallbacks::builder()
        .new_sample(move |s| {
            let sample = s.pull_sample().map_err(|_| gstreamer::FlowError::Error)?;
            let buf = sample.buffer().ok_or(gstreamer::FlowError::Error)?;
            let map = buf.map_readable().map_err(|_| gstreamer::FlowError::Error)?;
            let n = seq2.fetch_add(1, Ordering::Relaxed);
            let pts = buf.pts().map(|t| t.nseconds() / 11111).unwrap_or(0);
            let key = !buf.flags().contains(gstreamer::BufferFlags::DELTA_UNIT);
            let _ = tx.try_send(quic_video::VideoFrame::new(n, pts, key, map.to_vec()));
            Ok(gstreamer::FlowSuccess::Ok)
        }).build());

    // Bus message handler for errors
    let bus = pipe.bus().unwrap();
    std::thread::spawn(move || {
        for msg in bus.iter_timed(gstreamer::ClockTime::NONE) {
            match msg.view() {
                gstreamer::MessageView::Error(e) => {
                    eprintln!("[TX] GST ERROR: {} {:?}", e.error(), e.debug());
                }
                gstreamer::MessageView::StateChanged(s) => {
                    if let Some(el) = msg.src() {
                        if el.name().as_str() == "pipeline0" {
                            eprintln!("[TX] Pipeline state: {:?} -> {:?}", s.old(), s.current());
                        }
                    }
                }
                gstreamer::MessageView::Eos(_) => eprintln!("[TX] EOS"),
                _ => {}
            }
        }
    });

    pipe.set_state(gstreamer::State::Playing)?;
    eprintln!("[TX] Pipeline started ({}x{} @ {}kbps), connecting to 100.88.3.48:5555...", WIDTH, HEIGHT, BITRATE);

    let mut crypto = quic_common::insecure_client_config();
    crypto.alpn_protocols = vec![];
    let cfg = ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?));
    let ep = Endpoint::client("0.0.0.0:0".parse()?)?;
    let conn = ep.connect_with(cfg, "100.88.3.48:5555".parse()?, "localhost")?.await?;
    let mut stream = conn.open_uni().await?;
    eprintln!("[TX] Connected, sending frames...");

    let mut sent = 0u64;
    let mut bytes = 0u64;
    let start = std::time::Instant::now();

    while let Some(f) = rx.recv().await {
        let enc = f.encode();
        let len = enc.len();
        let len_bytes = (len as u32).to_be_bytes();

        // Always log for comparison with RX
        eprintln!("[TX] seq={} len={} len_bytes={:02X?} key={} first8={:02X?} last8={:02X?}",
            f.sequence, len, len_bytes, f.is_keyframe,
            &enc[..8.min(len)], &enc[len.saturating_sub(8)..]);

        stream.write_all(&len_bytes).await?;
        stream.write_all(&enc).await?;

        sent += 1;
        bytes += 4 + len as u64;

        if sent % 30 == 0 {
            let mbps = (bytes as f64 * 8.0) / (start.elapsed().as_secs_f64() * 1_000_000.0);
            eprintln!("[TX] sent={} bytes={} mbps={:.2}", sent, bytes, mbps);
        }
    }
    Ok(())
}
