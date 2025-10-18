use bytes::Bytes;
use quinn::Connection;
use recording_retrieval::{RecordingFile, TimeRange};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::error::HlsError;
use crate::live::LiveHlsStream;
use crate::recording::RecordingSession;

/// Shared state for HLS server operations.
///
/// This is shared across all HTTP handlers and manages:
/// - Live HLS transcoding processes (one per node)
/// - Node QUIC connections (for recording retrieval)
/// - Decryption keys (per node)
pub struct HlsState {
    /// Base directory for HLS output files
    pub hls_dir: PathBuf,

    /// RTSP server port
    pub rtsp_port: u16,

    /// Active live HLS streams (node_name -> stream)
    live_streams: Mutex<HashMap<String, LiveHlsStream>>,

    /// QUIC connections to edge nodes (node_name -> connection)
    node_connections: Mutex<HashMap<String, Arc<Connection>>>,

    /// Decryption keys for encrypted recordings (node_name -> hex key)
    decryption_keys: Mutex<HashMap<String, String>>,
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
            node_connections: Mutex::new(HashMap::new()),
            decryption_keys: Mutex::new(HashMap::new()),
        }
    }

    /// Register a node's QUIC connection for recording retrieval.
    ///
    /// Called by central when a node connects.
    pub async fn add_node_connection(
        &self,
        node: String,
        conn: Arc<Connection>,
        decryption_key: Option<String>,
    ) {
        tracing::info!("Adding node connection for HLS: {}", node);
        self.node_connections
            .lock()
            .await
            .insert(node.clone(), conn);

        if let Some(key) = decryption_key {
            self.decryption_keys.lock().await.insert(node, key);
        }
    }

    /// Remove a node's connection when it disconnects.
    ///
    /// Also stops any live stream for the node.
    pub async fn remove_node_connection(&self, node: &str) {
        tracing::info!("Removing node connection for HLS: {}", node);
        self.node_connections.lock().await.remove(node);
        self.decryption_keys.lock().await.remove(node);

        // Stop live stream if running
        if let Some(mut stream) = self.live_streams.lock().await.remove(node) {
            stream.stop().await;
            let _ = stream.cleanup().await;
        }
    }

    /// Check if a node is connected.
    pub async fn is_node_connected(&self, node: &str) -> bool {
        self.node_connections.lock().await.contains_key(node)
    }

    /// Get list of connected nodes.
    pub async fn connected_nodes(&self) -> Vec<String> {
        self.node_connections
            .lock()
            .await
            .keys()
            .cloned()
            .collect()
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

    /// Fetch the recording list for a node in a time range.
    pub async fn fetch_recording_list(
        &self,
        node: &str,
        time_range: &TimeRange,
    ) -> Result<Vec<RecordingFile>, HlsError> {
        let conn = self
            .node_connections
            .lock()
            .await
            .get(node)
            .cloned()
            .ok_or_else(|| HlsError::NodeNotConnected(node.to_string()))?;

        let key = self.decryption_keys.lock().await.get(node).cloned();

        let session = RecordingSession::new(node.to_string(), conn, key);
        session.fetch_recording_list(time_range).await
    }

    /// Fetch a recording segment from an edge node.
    ///
    /// Returns decrypted MP4 data ready for transmuxing.
    pub async fn fetch_recording_segment(
        &self,
        node: &str,
        timestamp: &str,
    ) -> Result<Bytes, HlsError> {
        let conn = self
            .node_connections
            .lock()
            .await
            .get(node)
            .cloned()
            .ok_or_else(|| HlsError::NodeNotConnected(node.to_string()))?;

        let key = self.decryption_keys.lock().await.get(node).cloned();

        let session = RecordingSession::new(node.to_string(), conn, key);
        session.fetch_segment(timestamp).await
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
