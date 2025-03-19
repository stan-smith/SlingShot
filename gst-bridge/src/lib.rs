//! GStreamer ↔ Rust channel bridges
//!
//! Provides helpers for bridging GStreamer appsink/appsrc elements to Rust async channels.

use gstreamer::{Buffer, ClockTime, FlowError, FlowSuccess};
use gstreamer_app::{AppSink, AppSrc};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Video buffer with timestamp and metadata
#[derive(Debug, Clone)]
pub struct VideoBuffer {
    /// Presentation timestamp in nanoseconds
    pub pts: Option<u64>,
    /// Decode timestamp in nanoseconds (optional)
    pub dts: Option<u64>,
    /// Whether this buffer contains a keyframe
    pub is_keyframe: bool,
    /// Raw buffer data (H.264 NALUs)
    pub data: Vec<u8>,
}

impl VideoBuffer {
    /// Convert PTS from nanoseconds to 90kHz clock (RTP convention)
    pub fn pts_90khz(&self) -> u64 {
        self.pts.map(|ns| ns / 11111).unwrap_or(0) // ns to 90kHz: divide by (1e9/90000)
    }

    /// Convert DTS from nanoseconds to 90kHz clock
    pub fn dts_90khz(&self) -> Option<u64> {
        self.dts.map(|ns| ns / 11111)
    }
}

/// Bridge from GStreamer appsink to a Rust channel
///
/// Captures buffers from an appsink and sends them to a channel.
pub struct SinkBridge {
    _appsink: AppSink,
}

impl SinkBridge {
    /// Create a new sink bridge
    ///
    /// Sets up callbacks on the appsink to send buffers to the returned receiver.
    /// The appsink should be configured with `sync=false` and appropriate caps.
    pub fn new(appsink: &AppSink, buffer_size: usize) -> (Self, mpsc::Receiver<VideoBuffer>) {
        let (tx, rx) = mpsc::channel(buffer_size);

        let tx = Arc::new(tx);
        let tx_clone = Arc::clone(&tx);

        appsink.set_callbacks(
            gstreamer_app::AppSinkCallbacks::builder()
                .new_sample(move |sink| {
                    let sample = sink.pull_sample().map_err(|_| FlowError::Error)?;
                    let buffer = sample.buffer().ok_or(FlowError::Error)?;
                    let map = buffer.map_readable().map_err(|_| FlowError::Error)?;

                    let pts = buffer.pts().map(|t| t.nseconds());
                    let dts = buffer.dts().map(|t| t.nseconds());

                    // Check for keyframe flag
                    let is_keyframe = !buffer.flags().contains(gstreamer::BufferFlags::DELTA_UNIT);

                    let video_buf = VideoBuffer {
                        pts,
                        dts,
                        is_keyframe,
                        data: map.as_slice().to_vec(),
                    };

                    // Non-blocking send - drop frame if channel full
                    let _ = tx_clone.try_send(video_buf);

                    Ok(FlowSuccess::Ok)
                })
                .build(),
        );

        (Self { _appsink: appsink.clone() }, rx)
    }
}

/// Bridge from a Rust channel to GStreamer appsrc
///
/// Receives buffers from a channel and pushes them to an appsrc.
pub struct SrcBridge {
    appsrc: AppSrc,
}

impl SrcBridge {
    /// Create a new source bridge
    ///
    /// The appsrc should be configured with appropriate caps and `is-live=true`.
    pub fn new(appsrc: &AppSrc) -> Self {
        Self {
            appsrc: appsrc.clone(),
        }
    }

    /// Push a video buffer to the appsrc
    ///
    /// Returns an error if the push fails.
    pub fn push(&self, video_buf: VideoBuffer) -> Result<(), gstreamer::FlowError> {
        let mut buffer = Buffer::from_slice(video_buf.data);
        {
            let buffer_ref = buffer.get_mut().unwrap();
            if let Some(pts) = video_buf.pts {
                buffer_ref.set_pts(ClockTime::from_nseconds(pts));
            }
            if let Some(dts) = video_buf.dts {
                buffer_ref.set_dts(ClockTime::from_nseconds(dts));
            }
            if !video_buf.is_keyframe {
                buffer_ref.set_flags(gstreamer::BufferFlags::DELTA_UNIT);
            }
        }

        self.appsrc.push_buffer(buffer)?;
        Ok(())
    }

    /// Signal end of stream
    pub fn end_stream(&self) -> Result<(), gstreamer::FlowError> {
        self.appsrc.end_of_stream()?;
        Ok(())
    }
}

/// Configure an appsink for low-latency video capture
pub fn configure_appsink(appsink: &AppSink) {
    appsink.set_sync(false);
    appsink.set_max_buffers(1);
    appsink.set_drop(true);
}

/// Configure an appsrc for low-latency video injection
pub fn configure_appsrc(appsrc: &AppSrc, caps: &gstreamer::Caps) {
    appsrc.set_caps(Some(caps));
    appsrc.set_is_live(true);
    appsrc.set_format(gstreamer::Format::Time);
    appsrc.set_do_timestamp(false);
}
