//! Audit logging for kaiju central node
//!
//! Provides structured audit logging with SQLite backend for security events,
//! command tracking, and compliance requirements.

mod error;
mod event;
mod logger;

pub use error::AuditError;
pub use event::{AuditEvent, EventType, Severity, Source, StoredEvent};
pub use logger::AuditLogger;
