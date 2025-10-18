use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::{Child, Command};

use crate::error::HlsError;

/// Manages a live RTSP-to-HLS transcoding session for a single node.
///
/// Uses ffmpeg to pull from the RTSP server and output HLS segments.
/// Segments are written to a temporary directory and served via HTTP.
pub struct LiveHlsStream {
    node_name: String,
    rtsp_url: String,
    ffmpeg_process: Option<Child>,
    pub hls_dir: PathBuf,
}

impl LiveHlsStream {
    /// Create a new live HLS stream configuration.
    ///
    /// # Arguments
    /// * `node_name` - Name of the camera/node
    /// * `rtsp_port` - Port of the RTSP server (default: 8554)
    /// * `hls_base_dir` - Base directory for HLS output (e.g., /tmp/hls)
    pub fn new(node_name: String, rtsp_port: u16, hls_base_dir: &PathBuf) -> Self {
        let rtsp_url = format!("rtsp://127.0.0.1:{}/{}/stream", rtsp_port, node_name);
        let hls_dir = hls_base_dir.join(&node_name);

        Self {
            node_name,
            rtsp_url,
            ffmpeg_process: None,
            hls_dir,
        }
    }

    /// Start the ffmpeg transcoding process.
    ///
    /// This spawns ffmpeg to:
    /// 1. Connect to the RTSP server
    /// 2. Copy the H.264 stream (no re-encoding)
    /// 3. Output HLS segments to the temp directory
    pub async fn start(&mut self) -> Result<(), HlsError> {
        // Create output directory
        tokio::fs::create_dir_all(&self.hls_dir)
            .await
            .map_err(|e| HlsError::Io(e))?;

        let segment_pattern = self.hls_dir.join("segment_%03d.ts");
        let playlist_path = self.hls_dir.join("stream.m3u8");

        tracing::info!(
            "Starting HLS transcode for {} from {}",
            self.node_name,
            self.rtsp_url
        );

        let process = Command::new("ffmpeg")
            .args([
                "-hide_banner",
                "-loglevel",
                "warning",
                // Input settings
                "-rtsp_transport",
                "tcp",
                "-i",
                &self.rtsp_url,
                // Output settings - no re-encoding
                "-c",
                "copy",
                // HLS output
                "-f",
                "hls",
                "-hls_time",
                "2", // 2-second segments for low latency
                "-hls_list_size",
                "5", // Keep 5 segments in playlist
                "-hls_flags",
                "delete_segments+append_list",
                "-hls_segment_filename",
                segment_pattern.to_str().unwrap(),
                // Use hls_base_url to prefix segment URLs in playlist
                "-hls_base_url",
                "segment/",
                playlist_path.to_str().unwrap(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| HlsError::Ffmpeg(format!("Failed to spawn ffmpeg: {}", e)))?;

        self.ffmpeg_process = Some(process);
        Ok(())
    }

    /// Stop the ffmpeg transcoding process.
    pub async fn stop(&mut self) {
        if let Some(mut proc) = self.ffmpeg_process.take() {
            tracing::info!("Stopping HLS transcode for {}", self.node_name);
            let _ = proc.kill().await;
        }
    }

    /// Check if the transcoding process is running.
    pub fn is_running(&self) -> bool {
        self.ffmpeg_process.is_some()
    }

    /// Check if the process is still alive and producing fresh output.
    ///
    /// Returns false if:
    /// - Process has exited
    /// - Playlist file is older than 10 seconds (stale stream)
    pub async fn check_health(&mut self) -> bool {
        if let Some(ref mut proc) = self.ffmpeg_process {
            match proc.try_wait() {
                Ok(Some(_status)) => {
                    // Process has exited
                    self.ffmpeg_process = None;
                    return false;
                }
                Ok(None) => {
                    // Process is running, check if output is fresh
                }
                Err(_) => {
                    return false;
                }
            }

            // Check if playlist was modified recently (within 10 seconds)
            let playlist = self.playlist_path();
            if let Ok(metadata) = tokio::fs::metadata(&playlist).await {
                if let Ok(modified) = metadata.modified() {
                    let age = std::time::SystemTime::now()
                        .duration_since(modified)
                        .unwrap_or_default();
                    if age.as_secs() > 10 {
                        // Playlist is stale - ffmpeg is stuck
                        tracing::warn!(
                            "HLS stream {} is stale ({}s old), marking unhealthy",
                            self.node_name,
                            age.as_secs()
                        );
                        return false;
                    }
                }
            }

            true
        } else {
            false
        }
    }

    /// Get the path to the HLS playlist file.
    pub fn playlist_path(&self) -> PathBuf {
        self.hls_dir.join("stream.m3u8")
    }

    /// Get the node name.
    pub fn node_name(&self) -> &str {
        &self.node_name
    }

    /// Clean up HLS files on disk.
    pub async fn cleanup(&self) -> Result<(), HlsError> {
        if self.hls_dir.exists() {
            tokio::fs::remove_dir_all(&self.hls_dir)
                .await
                .map_err(|e| HlsError::Io(e))?;
        }
        Ok(())
    }
}

impl Drop for LiveHlsStream {
    fn drop(&mut self) {
        // Try to kill the process synchronously on drop
        if let Some(ref mut proc) = self.ffmpeg_process {
            let _ = proc.start_kill();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_stream_configuration() {
        let temp_dir = TempDir::new().unwrap();
        let stream = LiveHlsStream::new("cam1".to_string(), 8554, &temp_dir.path().to_path_buf());

        assert_eq!(stream.node_name(), "cam1");
        assert!(!stream.is_running());
        assert!(stream
            .playlist_path()
            .to_string_lossy()
            .contains("stream.m3u8"));
    }
}
