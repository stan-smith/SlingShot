//! HLS Server for Slingshot video streaming.
//!
//! This crate provides HTTP Live Streaming (HLS) functionality for the Slingshot
//! video surveillance system. It handles:
//!
//! - **Live streaming**: Transcodes RTSP streams to HLS using ffmpeg
//!
//! # Architecture
//!
//! ```text
//! Browser <--HLS--> hls-server <--RTSP--> central <--QUIC--> edge
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
//! | `GET /hls/<node>/segment/<segment>.ts` | Live segment |

pub mod error;
pub mod live;
pub mod playlist;
pub mod routes;
mod state;

pub use error::HlsError;
pub use state::HlsState;

/// Check if all required dependencies (ffmpeg) are available.
pub async fn check_dependencies() -> Result<(), HlsError> {
    live::check_ffmpeg().await
}
