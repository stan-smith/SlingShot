use bytes::Bytes;
use chrono::{DateTime, Local};
use quinn::Connection;
use recording_retrieval::{RecordingFile, TimeRange};
use std::sync::Arc;

use crate::error::HlsError;

/// Session for streaming recordings from an edge node.
///
/// This handles:
/// 1. Querying the edge node for available recordings
/// 2. Fetching individual MP4 chunks over QUIC
/// 3. Decrypting encrypted recordings
pub struct RecordingSession {
    pub node_name: String,
    pub connection: Arc<Connection>,
    pub decryption_key: Option<String>,
}

impl RecordingSession {
    /// Create a new recording session for a node.
    pub fn new(
        node_name: String,
        connection: Arc<Connection>,
        decryption_key: Option<String>,
    ) -> Self {
        Self {
            node_name,
            connection,
            decryption_key,
        }
    }

    /// Request the list of recordings available in a time range from the edge node.
    ///
    /// This sends a command to the remote node and parses the response.
    pub async fn fetch_recording_list(
        &self,
        time_range: &TimeRange,
    ) -> Result<Vec<RecordingFile>, HlsError> {
        // Format the time range as a recordings command
        let from_str = time_range.from.format("%Y-%m-%dT%H:%M:%S").to_string();
        let to_str = time_range.to.format("%Y-%m-%dT%H:%M:%S").to_string();
        let command = format!("list_recordings {} {}", from_str, to_str);

        // Open a bidirectional stream to send the command
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| HlsError::Quic(format!("Failed to open stream: {}", e)))?;

        // Send command
        send.write_all(command.as_bytes())
            .await
            .map_err(|e| HlsError::Quic(format!("Failed to send command: {}", e)))?;
        send.finish()
            .map_err(|e| HlsError::Quic(format!("Failed to finish send: {}", e)))?;

        // Read response
        let response = recv
            .read_to_end(1024 * 1024) // 1MB max
            .await
            .map_err(|e| HlsError::Quic(format!("Failed to read response: {}", e)))?;

        // Parse response as JSON list of recordings
        let response_str = String::from_utf8_lossy(&response);

        // Parse each line as a recording file entry
        // Format: "timestamp|size|encrypted"
        let mut recordings = Vec::new();
        for line in response_str.lines() {
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 2 {
                if let Ok(start) =
                    chrono::NaiveDateTime::parse_from_str(parts[0], "%Y-%m-%d_%H-%M-%S")
                {
                    let start_time = DateTime::<Local>::from_naive_utc_and_offset(
                        start,
                        *Local::now().offset(),
                    );
                    let end_time = start_time + chrono::Duration::seconds(30);
                    let size: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                    let encrypted = parts.get(2).map(|s| *s == "true").unwrap_or(false);

                    let extension = if encrypted { ".mp4.enc" } else { ".mp4" };
                    let path = std::path::PathBuf::from(format!("{}{}", parts[0], extension));

                    recordings.push(RecordingFile {
                        path,
                        start_time,
                        end_time,
                        size_bytes: size,
                    });
                }
            }
        }

        Ok(recordings)
    }

    /// Fetch a single recording segment from the edge node.
    ///
    /// # Arguments
    /// * `timestamp` - The timestamp identifier (e.g., "2024-12-01_15-30-00")
    ///
    /// # Returns
    /// Decrypted MP4 data ready for transmuxing
    pub async fn fetch_segment(&self, timestamp: &str) -> Result<Bytes, HlsError> {
        // Try fetching as encrypted first, then plain
        let encrypted_filename = format!("{}.mp4.enc", timestamp);
        let plain_filename = format!("{}.mp4", timestamp);

        // Try encrypted version first if we have a key
        if self.decryption_key.is_some() {
            match self.request_file(&encrypted_filename).await {
                Ok(data) => {
                    return self.decrypt_data(data).await;
                }
                Err(_) => {
                    // Fall through to try plain version
                }
            }
        }

        // Try plain version
        match self.request_file(&plain_filename).await {
            Ok(data) => Ok(data),
            Err(e) => Err(HlsError::RecordingNotFound(format!(
                "Recording {} not found: {}",
                timestamp, e
            ))),
        }
    }

    /// Request a file from the edge node over QUIC.
    async fn request_file(&self, filename: &str) -> Result<Bytes, HlsError> {
        let command = format!("get_recording {}", filename);

        // Open a bidirectional stream
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| HlsError::Quic(format!("Failed to open stream: {}", e)))?;

        // Send request
        send.write_all(command.as_bytes())
            .await
            .map_err(|e| HlsError::Quic(format!("Failed to send request: {}", e)))?;
        send.finish()
            .map_err(|e| HlsError::Quic(format!("Failed to finish send: {}", e)))?;

        // Read response - recordings can be large (up to 50MB for 30s of high-quality video)
        let data = recv
            .read_to_end(50 * 1024 * 1024)
            .await
            .map_err(|e| HlsError::Quic(format!("Failed to read file: {}", e)))?;

        if data.is_empty() {
            return Err(HlsError::RecordingNotFound(filename.to_string()));
        }

        // Check for error response
        if data.starts_with(b"ERROR:") {
            let msg = String::from_utf8_lossy(&data);
            return Err(HlsError::RecordingNotFound(msg.to_string()));
        }

        Ok(Bytes::from(data))
    }

    /// Decrypt encrypted recording data.
    async fn decrypt_data(&self, encrypted_data: Bytes) -> Result<Bytes, HlsError> {
        let key = self.decryption_key.as_ref().ok_or_else(|| {
            HlsError::DecryptionFailed("No decryption key available".to_string())
        })?;

        // Use kaiju-encryption to decrypt
        let decrypted = kaiju_encryption::open_with_hex_key(&encrypted_data, key)
            .map_err(|e| HlsError::DecryptionFailed(format!("Decryption failed: {}", e)))?;

        Ok(Bytes::from(decrypted))
    }
}

/// Parse a time range from ISO8601 strings.
pub fn parse_time_range(from: &str, to: &str) -> Result<TimeRange, HlsError> {
    let from_dt = DateTime::parse_from_rfc3339(from)
        .map(|dt| dt.with_timezone(&Local))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(from, "%Y-%m-%dT%H:%M:%S")
                .map(|dt| DateTime::<Local>::from_naive_utc_and_offset(dt, *Local::now().offset()))
        })
        .map_err(|e| HlsError::InvalidTimeRange(format!("Invalid 'from' time: {}", e)))?;

    let to_dt = DateTime::parse_from_rfc3339(to)
        .map(|dt| dt.with_timezone(&Local))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(to, "%Y-%m-%dT%H:%M:%S")
                .map(|dt| DateTime::<Local>::from_naive_utc_and_offset(dt, *Local::now().offset()))
        })
        .map_err(|e| HlsError::InvalidTimeRange(format!("Invalid 'to' time: {}", e)))?;

    Ok(TimeRange {
        from: from_dt,
        to: to_dt,
    })
}
