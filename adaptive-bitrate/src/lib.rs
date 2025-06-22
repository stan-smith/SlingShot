//! Adaptive Bitrate Control for Video Streaming
//!
//! This crate provides adaptive bitrate control based on QUIC QoS metrics.
//! It monitors packet loss and RTT to dynamically adjust video quality.
//!
//! # Components
//!
//! - [`config`]: Configuration types for adaptive streaming
//! - [`floors`]: Bitrate floor data for various resolution/framerate combinations
//! - [`ladder`]: Quality ladder generation based on priority mode
//! - [`controller`]: ABR state machine and adaptation logic

mod config;
mod controller;
mod floors;
mod ladder;

pub use config::{AdaptiveConfig, AdaptivePriority};
pub use controller::{AdaptiveController, ControllerState, QualityChange};
pub use floors::BitrateFloors;
pub use ladder::{QualityLadder, QualityStep};
