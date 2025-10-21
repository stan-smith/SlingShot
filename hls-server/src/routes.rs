use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use std::sync::Arc;
use tokio_util::io::ReaderStream;

use crate::error::HlsError;
use crate::state::HlsState;

/// Create the HLS router with all endpoints.
pub fn hls_router(state: Arc<HlsState>) -> Router {
    Router::new()
        // Live streaming endpoints
        .route("/{node}/stream.m3u8", get(live_playlist_handler))
        .route("/{node}/segment/{segment}", get(live_segment_handler))
        .with_state(state)
}

/// Serve the live HLS playlist for a node.
///
/// This endpoint:
/// 1. Ensures the RTSP-to-HLS transcoding is running
/// 2. Returns the current m3u8 playlist
async fn live_playlist_handler(
    Path(node): Path<String>,
    State(state): State<Arc<HlsState>>,
) -> Result<impl IntoResponse, HlsErrorResponse> {
    // Ensure transcoding is running for this node
    state.ensure_live_stream(&node).await?;

    // Wait a moment for ffmpeg to create the playlist
    let playlist_path = state.hls_dir.join(&node).join("stream.m3u8");

    // Wait for playlist to exist (with timeout)
    let mut attempts = 0;
    while !playlist_path.exists() && attempts < 50 {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        attempts += 1;
    }

    if !playlist_path.exists() {
        return Err(HlsError::StreamNotRunning(format!(
            "Playlist not ready for node {}",
            node
        ))
        .into());
    }

    let playlist = tokio::fs::read_to_string(&playlist_path)
        .await
        .map_err(|e| HlsError::Io(e))?;

    Ok((
        [(header::CONTENT_TYPE, "application/vnd.apple.mpegurl")],
        playlist,
    ))
}

/// Serve a live HLS segment.
async fn live_segment_handler(
    Path((node, segment)): Path<(String, String)>,
    State(state): State<Arc<HlsState>>,
) -> Result<impl IntoResponse, HlsErrorResponse> {
    let segment_path = state.hls_dir.join(&node).join(&segment);

    if !segment_path.exists() {
        return Err(HlsError::SegmentNotFound(format!("Segment not found: {}", segment)).into());
    }

    let file = tokio::fs::File::open(&segment_path)
        .await
        .map_err(|e| HlsError::Io(e))?;

    let stream = ReaderStream::new(file);

    Ok(([(header::CONTENT_TYPE, "video/mp2t")], Body::from_stream(stream)))
}

/// Error response wrapper for HlsError
pub struct HlsErrorResponse(HlsError);

impl From<HlsError> for HlsErrorResponse {
    fn from(e: HlsError) -> Self {
        HlsErrorResponse(e)
    }
}

impl IntoResponse for HlsErrorResponse {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match &self.0 {
            HlsError::NodeNotFound(_) | HlsError::NodeNotConnected(_) => {
                (StatusCode::NOT_FOUND, self.0.to_string())
            }
            HlsError::SegmentNotFound(_) => (StatusCode::NOT_FOUND, self.0.to_string()),
            HlsError::StreamNotRunning(_) => (StatusCode::SERVICE_UNAVAILABLE, self.0.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_string()),
        };

        tracing::warn!("HLS error: {}", self.0);

        (status, message).into_response()
    }
}
