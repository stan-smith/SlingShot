//! SQLite-backed fingerprint storage for kaiju central node
//!
//! Stores approved node fingerprints for auto-approval on reconnection.

mod db;
mod error;

pub use db::{ApprovedNode, FingerprintStore, UserInfo};
pub use error::StoreError;
