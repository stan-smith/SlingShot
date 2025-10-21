use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::Mutex;

use crate::error::HlsError;
use crate::live::LiveHlsStream;

/// Shared state for HLS server operations.
///
/// This is shared across all HTTP handlers and manages:
/// - Live HLS transcoding processes (one per node)
pub struct HlsState {
    /// Base directory for HLS output files
    pub hls_dir: PathBuf,

    /// RTSP server port
    pub rtsp_port: u16,

    /// Active live HLS streams (node_name -> stream)
    live_streams: Mutex<HashMap<String, LiveHlsStream>>,
}

impl HlsState {
    /// Create a new HLS state.
    ///
    /// # Arguments
    /// * `hls_dir` - Directory for HLS output files (e.g., /tmp/hls)
    /// * `rtsp_port` - RTSP server port (default: 8554)
    pub fn new(hls_dir: PathBuf, rtsp_port: u16) -> Self {
        Self {
            hls_dir,
            rtsp_port,
            live_streams: Mutex::new(HashMap::new()),
        }
    }

    /// Remove a node's live stream when it disconnects.
    pub async fn remove_node(&self, node: &str) {
        // Stop live stream if running
        if let Some(mut stream) = self.live_streams.lock().await.remove(node) {
            stream.stop().await;
            let _ = stream.cleanup().await;
        }
    }

    /// Ensure a live HLS stream is running for a node.
    ///
    /// Starts the ffmpeg transcoding process if not already running.
    pub async fn ensure_live_stream(&self, node: &str) -> Result<(), HlsError> {
        let mut streams = self.live_streams.lock().await;

        // Check if stream exists and is healthy
        if let Some(stream) = streams.get_mut(node) {
            if stream.check_health().await {
                return Ok(());
            }
            // Stream died, remove it
            stream.stop().await;
            let _ = stream.cleanup().await;
            streams.remove(node);
        }

        // Start new stream
        let mut stream = LiveHlsStream::new(node.to_string(), self.rtsp_port, &self.hls_dir);
        stream.start().await?;
        streams.insert(node.to_string(), stream);

        Ok(())
    }

    /// Stop a live HLS stream for a node.
    pub async fn stop_live_stream(&self, node: &str) {
        if let Some(mut stream) = self.live_streams.lock().await.remove(node) {
            stream.stop().await;
            let _ = stream.cleanup().await;
        }
    }

    /// Clean up all HLS resources.
    pub async fn shutdown(&self) {
        // Stop all live streams
        let mut streams = self.live_streams.lock().await;
        for (_, mut stream) in streams.drain() {
            stream.stop().await;
            let _ = stream.cleanup().await;
        }

        // Clean up base directory
        if self.hls_dir.exists() {
            let _ = tokio::fs::remove_dir_all(&self.hls_dir).await;
        }
    }
}

impl Drop for HlsState {
    fn drop(&mut self) {
        // Note: async cleanup should be done via shutdown() before drop
        // This is just a safety fallback
        if self.hls_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.hls_dir);
        }
    }
}
