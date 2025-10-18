//! HLS Server for Kaiju video streaming.
//!
//! This crate provides HTTP Live Streaming (HLS) functionality for the Kaiju
//! video surveillance system. It handles:
//!
//! - **Live streaming**: Transcodes RTSP streams to HLS using ffmpeg
//! - **Recording playback**: Generates HLS playlists from edge node recordings
//!
//! # Architecture
//!
//! ```text
//! Browser <--HLS--> hls-server <--RTSP--> central <--QUIC--> edge
//!                       |                                      |
//!                       +------------ QUIC (recordings) -------+
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use hls_server::{HlsState, routes::hls_router};
//! use std::sync::Arc;
//! use std::path::PathBuf;
//!
//! let hls_state = Arc::new(HlsState::new(
//!     PathBuf::from("/tmp/hls"),
//!     8554, // RTSP port
//! ));
//!
//! // Add to your Axum router
//! let app = Router::new()
//!     .nest("/hls", hls_router(hls_state));
//! ```
//!
//! # Endpoints
//!
//! | Endpoint | Description |
//! |----------|-------------|
//! | `GET /hls/<node>/stream.m3u8` | Live HLS playlist |
//! | `GET /hls/<node>/live/<segment>.ts` | Live segment |
//! | `GET /hls/<node>/recording.m3u8?from=<ISO>&to=<ISO>` | Recording VOD playlist |
//! | `GET /hls/<node>/recording/<timestamp>.ts` | Recording segment |

pub mod error;
pub mod live;
pub mod playlist;
pub mod recording;
pub mod routes;
mod state;
pub mod transmux;

pub use error::HlsError;
pub use state::HlsState;

/// Check if all required dependencies (ffmpeg) are available.
pub async fn check_dependencies() -> Result<(), HlsError> {
    transmux::check_ffmpeg().await
}
