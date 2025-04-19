use anyhow::Result;
use gstreamer::prelude::*;
use gstreamer_app::AppSrc;
use gstreamer_rtsp_server::prelude::*;
use quinn::{Endpoint, ServerConfig};
use quic_video::QosMetrics;
use std::sync::Arc;
use std::time::Duration;

const MAX_FRAME_SIZE: usize = 10_000_000;

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
    scfg.transport_config(Arc::new(quic_common::video_transport_config()));

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

        if let Some(report) = qos.report_if_due() {
            eprintln!("[QoS] {}", report);
        }
    }

    Ok(())
}
