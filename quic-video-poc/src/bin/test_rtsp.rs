//! Simple RTSP server test - no QUIC, just videotestsrc directly
//! If this works, the issue is with appsrc

use anyhow::Result;
use gstreamer_rtsp_server::prelude::*;

fn main() -> Result<()> {
    gstreamer::init()?;

    println!("=== Simple RTSP Test Server ===");

    // Create RTSP server with direct videotestsrc pipeline (no appsrc)
    let rtsp_server = gstreamer_rtsp_server::RTSPServer::new();
    rtsp_server.set_service("8555");
    let mounts = rtsp_server.mount_points().expect("Failed to get mount points");

    let factory = gstreamer_rtsp_server::RTSPMediaFactory::new();
    // Direct pipeline - no appsrc involved
    factory.set_launch(
        "( videotestsrc pattern=ball is-live=true \
           ! video/x-raw,width=640,height=480,framerate=30/1 \
           ! videoconvert \
           ! x264enc tune=zerolatency speed-preset=ultrafast bitrate=2000 key-int-max=30 \
           ! h264parse \
           ! rtph264pay name=pay0 pt=96 )",
    );
    factory.set_shared(true);

    mounts.add_factory("/test", factory);

    let main_loop = glib::MainLoop::new(None, false);
    let _rtsp_id = rtsp_server.attach(None).expect("Failed to attach RTSP server");

    println!("RTSP test server on port 8555");
    println!("Test: gst-launch-1.0 rtspsrc location=rtsp://127.0.0.1:8555/test protocols=tcp latency=0 ! rtph264depay ! h264parse ! avdec_h264 ! videoconvert ! fakesink sync=false");
    println!();

    main_loop.run();
    Ok(())
}
