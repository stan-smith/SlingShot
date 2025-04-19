use anyhow::Result;
use gstreamer::prelude::*;
use gstreamer_app::AppSrc;
use gstreamer_rtsp_server::prelude::*;
use quinn::{Endpoint, ServerConfig};
use std::sync::Arc;

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

                // Push cached keyframe first if available
                if let Some(kf) = ck2.lock().unwrap().take() {
                    eprintln!("[GST] pushing cached keyframe");
                    let buf = gstreamer::Buffer::from_slice(kf.data);
                    let _ = appsrc.push_buffer(buf);
                }

                std::thread::spawn(move || {
                    let mut n = 0u64;
                    while let Ok(f) = rx.recv() {
                        let mut buf = gstreamer::Buffer::from_slice(f.data.clone());
                        { let r = buf.get_mut().unwrap(); if !f.is_keyframe { r.set_flags(gstreamer::BufferFlags::DELTA_UNIT); } }
                        if appsrc.push_buffer(buf).is_err() { eprintln!("[GST] push error"); break; }
                        n += 1;
                        if n % 30 == 0 { eprintln!("[GST] pushed={}", n); }
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
    std::thread::sleep(std::time::Duration::from_millis(100));

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
    let scfg = ServerConfig::with_crypto(Arc::new(qcfg));

    let ep = Endpoint::server(scfg, "0.0.0.0:5555".parse()?)?;
    eprintln!("[RX] Waiting for connection...");

    let conn = ep.accept().await.unwrap().await?;
    eprintln!("[RX] Connected from {}", conn.remote_address());

    let mut stream = conn.accept_uni().await?;
    let mut buf: Vec<u8> = Vec::new();
    let mut frames = 0u64;
    let mut bytes = 0u64;
    let mut expect_seq: Option<u32> = None;
    let start = std::time::Instant::now();

    loop {
        while buf.len() < 4 {
            match stream.read_chunk(8192, false).await? {
                Some(c) => buf.extend_from_slice(&c.bytes),
                None => { eprintln!("[RX] stream ended"); return Ok(()); }
            }
        }
        let flen = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;

        if flen < 29 || flen > 10_000_000 {
            eprintln!("[RX] DESYNC! flen={} bytes={:02X?} total_bytes={}", flen, &buf[..32.min(buf.len())], bytes);
            std::process::exit(1);
        }
        buf.drain(..4);

        while buf.len() < flen {
            match stream.read_chunk(8192, false).await? {
                Some(c) => buf.extend_from_slice(&c.bytes),
                None => { eprintln!("[RX] stream ended mid-frame"); return Ok(()); }
            }
        }
        let data: Vec<u8> = buf.drain(..flen).collect();

        let f = match quic_video::VideoFrame::decode(&data) {
            Ok(f) => f,
            Err(quic_video::DecodeError::ChecksumMismatch { expected, actual, sequence }) => {
                eprintln!("[RX] CRC FAIL seq={} exp={:08X} got={:08X} flen={} first32={:02X?}",
                    sequence, expected, actual, flen, &data[..32.min(data.len())]);
                std::process::exit(1);
            }
            Err(e) => { eprintln!("[RX] decode err: {}", e); std::process::exit(1); }
        };

        // Always log for comparison with TX
        eprintln!("[RX] seq={} len={} key={} first8={:02X?} last8={:02X?}",
            f.sequence, flen, f.is_keyframe, &data[..8.min(flen)], &data[flen.saturating_sub(8)..]);

        if let Some(exp) = expect_seq {
            if f.sequence != exp {
                eprintln!("[RX] SEQ GAP: expected {} got {} (gap={})", exp, f.sequence, f.sequence.wrapping_sub(exp));
            }
        }
        expect_seq = Some(f.sequence.wrapping_add(1));

        frames += 1;
        bytes += 4 + flen as u64;

        // Cache keyframes for late RTSP clients
        if f.is_keyframe { *cached_key.lock().unwrap() = Some(f.clone()); }

        // Send to gstreamer if connected
        if let Some(tx) = frame_tx.lock().unwrap().as_ref() { let _ = tx.send(f); }

        if frames % 30 == 0 {
            let mbps = (bytes as f64 * 8.0) / (start.elapsed().as_secs_f64() * 1_000_000.0);
            eprintln!("[RX] frames={} bytes={} mbps={:.2}", frames, bytes, mbps);
        }
    }
}
