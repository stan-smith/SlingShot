use anyhow::Result;
use gstreamer::prelude::*;
use gstreamer_app::AppSrc;
use gstreamer_rtsp_server::prelude::*;
use quinn::{Endpoint, ServerConfig};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_FRAME_SIZE: usize = 10_000_000;

struct QosMetrics {
    last_seq: Option<u32>,
    frames_received: u64,
    frames_dropped: u64,
    gaps: u64,
    out_of_order: u64,
    bytes_received: u64,
    start_time: Instant,
    last_report: Instant,
}

impl QosMetrics {
    fn new() -> Self {
        let now = Instant::now();
        Self { last_seq: None, frames_received: 0, frames_dropped: 0, gaps: 0, out_of_order: 0, bytes_received: 0, start_time: now, last_report: now }
    }

    fn record(&mut self, seq: u32, size: usize) {
        if let Some(last) = self.last_seq {
            if seq <= last { self.out_of_order += 1; }
            else if seq > last + 1 { self.gaps += (seq - last - 1) as u64; }
        }
        self.last_seq = Some(seq);
        self.frames_received += 1;
        self.bytes_received += size as u64;
    }

    fn drop_frame(&mut self) { self.frames_dropped += 1; }

    fn report_if_due(&mut self) {
        if self.last_report.elapsed() >= Duration::from_secs(5) {
            let elapsed = self.start_time.elapsed().as_secs_f64();
            let fps = self.frames_received as f64 / elapsed;
            let total = self.frames_received + self.gaps;
            let loss = if total > 0 { (self.gaps as f64 / total as f64) * 100.0 } else { 0.0 };
            let mbps = (self.bytes_received as f64 * 8.0) / (elapsed * 1_000_000.0);
            eprintln!("[QoS] fps={:.1} loss={:.1}% gaps={} ooo={} dropped={} bitrate={:.2}mbps",
                fps, loss, self.gaps, self.out_of_order, self.frames_dropped, mbps);
            self.last_report = Instant::now();
        }
    }
}

fn main() -> Result<()> {
    gstreamer::init()?;
    rustls::crypto::ring::default_provider().install_default().ok();

    let rtsp = gstreamer_rtsp_server::RTSPServer::new();
    rtsp.set_service("8555");
    let mounts = rtsp.mount_points().unwrap();

    let frame_tx: Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<quic_video::VideoFrame>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let cached_key: Arc<std::sync::Mutex<Option<quic_video::VideoFrame>>> =
        Arc::new(std::sync::Mutex::new(None));

    let tx2 = Arc::clone(&frame_tx);
    let ck2 = Arc::clone(&cached_key);

    let factory = gstreamer_rtsp_server::RTSPMediaFactory::new();
    factory.set_launch("( appsrc name=src is-live=true format=time do-timestamp=true \
        caps=video/x-h264,stream-format=byte-stream,alignment=au ! h264parse ! rtph264pay name=pay0 pt=96 )");
    factory.set_shared(true);

    factory.connect_media_configure(move |_, media| {
        let el = media.element();
        if let Some(bin) = el.downcast_ref::<gstreamer::Bin>() {
            if let Some(src) = bin.by_name("src") {
                let appsrc = src.dynamic_cast::<AppSrc>().unwrap();
                let (tx, rx) = std::sync::mpsc::channel::<quic_video::VideoFrame>();
                *tx2.lock().unwrap() = Some(tx);

                if let Some(kf) = ck2.lock().unwrap().take() {
                    eprintln!("[GST] pushing cached keyframe");
                    let _ = appsrc.push_buffer(gstreamer::Buffer::from_slice(kf.data));
                }

                std::thread::spawn(move || {
                    let mut n = 0u64;
                    while let Ok(f) = rx.recv() {
                        let mut buf = gstreamer::Buffer::from_slice(f.data.clone());
                        { let r = buf.get_mut().unwrap(); if !f.is_keyframe { r.set_flags(gstreamer::BufferFlags::DELTA_UNIT); } }
                        if appsrc.push_buffer(buf).is_err() { eprintln!("[GST] push error"); break; }
                        n += 1;
                        if n % 150 == 0 { eprintln!("[GST] pushed={}", n); }
                    }
                });
                eprintln!("[GST] media configured");
            }
        }
    });

    mounts.add_factory("/stream", factory);
    let main_loop = glib::MainLoop::new(None, false);
    let ml2 = main_loop.clone();
    rtsp.attach(None).unwrap();
    std::thread::spawn(move || ml2.run());
    std::thread::sleep(Duration::from_millis(100));

    eprintln!("[RX] RTSP on 8555, QUIC on 5555. View: ffplay rtsp://127.0.0.1:8555/stream");

    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(run_quic(frame_tx, cached_key))?;
    main_loop.quit();
    Ok(())
}

async fn run_quic(
    frame_tx: Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<quic_video::VideoFrame>>>>,
    cached_key: Arc<std::sync::Mutex<Option<quic_video::VideoFrame>>>,
) -> Result<()> {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])?.self_signed(&kp)?;
    let chain = vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())];
    let key = rustls::pki_types::PrivateKeyDer::try_from(kp.serialize_der()).unwrap();

    let mut crypto = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(chain, key)?;
    crypto.alpn_protocols = vec![];
    let qcfg = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?;
    let mut scfg = ServerConfig::with_crypto(Arc::new(qcfg));

    // Allow many concurrent streams (one per frame in flight)
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(1000u32.into());
    scfg.transport_config(Arc::new(transport));

    let ep = Endpoint::server(scfg, "0.0.0.0:5555".parse()?)?;
    eprintln!("[RX] Waiting for connection...");

    let conn = ep.accept().await.unwrap().await?;
    eprintln!("[RX] Connected from {}", conn.remote_address());

    let mut qos = QosMetrics::new();

    loop {
        // Accept next stream (one frame per stream)
        let mut stream = match conn.accept_uni().await {
            Ok(s) => s,
            Err(e) => { eprintln!("[RX] Connection closed: {}", e); break; }
        };

        // Read entire frame (QUIC handles framing)
        let data = match stream.read_to_end(MAX_FRAME_SIZE).await {
            Ok(d) => d,
            Err(e) => { eprintln!("[RX] Read error: {}", e); qos.drop_frame(); continue; }
        };

        // Decode frame
        let f = match quic_video::VideoFrame::decode(&data) {
            Ok(f) => f,
            Err(e) => { eprintln!("[RX] Decode error: {}", e); qos.drop_frame(); continue; }
        };

        qos.record(f.sequence, data.len());

        // Cache keyframes
        if f.is_keyframe { *cached_key.lock().unwrap() = Some(f.clone()); }

        // Send to gstreamer
        if let Some(tx) = frame_tx.lock().unwrap().as_ref() { let _ = tx.send(f); }

        qos.report_if_due();
    }

    Ok(())
}
