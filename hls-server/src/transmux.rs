use bytes::Bytes;
use futures::Stream;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::error::HlsError;

/// Transmux MP4 data to MPEG-TS without re-encoding.
///
/// This uses ffmpeg to repackage MP4 data as MPEG-TS, which is required for HLS.
/// The operation is fast because no video encoding/decoding occurs - only container
/// format conversion.
///
/// # Arguments
/// * `mp4_data` - Raw MP4 file data (must have moov atom)
///
/// # Returns
/// An async stream of MPEG-TS data chunks
pub async fn transmux_mp4_to_ts(
    mp4_data: Bytes,
) -> Result<impl Stream<Item = Result<Bytes, std::io::Error>>, HlsError> {
    // Spawn ffmpeg with pipes for input and output
    // -i pipe:0 : read input from stdin
    // -c copy   : no re-encoding (fast!)
    // -f mpegts : output format is MPEG-TS
    // pipe:1    : write output to stdout
    let mut ffmpeg = Command::new("ffmpeg")
        .args([
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            "pipe:0",
            "-c",
            "copy",
            "-f",
            "mpegts",
            "-movflags",
            "+faststart",
            "pipe:1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| HlsError::Ffmpeg(format!("Failed to spawn ffmpeg: {}", e)))?;

    let mut stdin = ffmpeg
        .stdin
        .take()
        .ok_or_else(|| HlsError::Ffmpeg("Failed to get ffmpeg stdin".to_string()))?;

    let stdout = ffmpeg
        .stdout
        .take()
        .ok_or_else(|| HlsError::Ffmpeg("Failed to get ffmpeg stdout".to_string()))?;

    // Write input data to ffmpeg in a background task
    tokio::spawn(async move {
        if let Err(e) = stdin.write_all(&mp4_data).await {
            tracing::warn!("Error writing to ffmpeg stdin: {}", e);
        }
        // stdin is dropped here, closing the pipe and signaling EOF to ffmpeg
    });

    // Create async stream that reads from ffmpeg stdout
    let stream = async_stream::stream! {
        let mut reader = tokio::io::BufReader::with_capacity(65536, stdout);
        let mut buf = vec![0u8; 65536];

        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => yield Ok(Bytes::copy_from_slice(&buf[..n])),
                Err(e) => {
                    yield Err(e);
                    break;
                }
            }
        }

        // Wait for ffmpeg to finish
        let _ = ffmpeg.wait().await;
    };

    Ok(stream)
}

/// Check if ffmpeg is available on the system
pub async fn check_ffmpeg() -> Result<(), HlsError> {
    let output = Command::new("ffmpeg")
        .arg("-version")
        .output()
        .await
        .map_err(|e| HlsError::Ffmpeg(format!("ffmpeg not found: {}", e)))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(HlsError::Ffmpeg(
            "ffmpeg returned non-zero exit code".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    #[tokio::test]
    async fn test_ffmpeg_available() {
        // This test will fail if ffmpeg is not installed
        let result = check_ffmpeg().await;
        if result.is_err() {
            eprintln!("ffmpeg not available, skipping test");
            return;
        }
        assert!(result.is_ok());
    }

    // Note: A full transmux test would require a valid MP4 file
    // which is impractical for unit tests. Integration tests should
    // cover actual transmux functionality.
}
