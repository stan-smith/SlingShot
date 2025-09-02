use serde::{Deserialize, Serialize};

/// An audit event to be logged
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub event_type: EventType,
    pub severity: Severity,
    pub source: Source,
    pub source_addr: Option<String>,
    pub username: Option<String>,
    pub node_name: Option<String>,
    pub fingerprint: Option<String>,
    pub details: Option<serde_json::Value>,
    pub success: Option<bool>,
}

impl AuditEvent {
    /// Create a new audit event with required fields
    pub fn new(event_type: EventType, source: Source) -> Self {
        Self {
            event_type,
            severity: event_type.default_severity(),
            source,
            source_addr: None,
            username: None,
            node_name: None,
            fingerprint: None,
            details: None,
            success: None,
        }
    }

    /// Set source address
    pub fn with_source_addr(mut self, addr: impl Into<String>) -> Self {
        self.source_addr = Some(addr.into());
        self
    }

    /// Set authenticated username
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Set target node name
    pub fn with_node(mut self, node: impl Into<String>) -> Self {
        self.node_name = Some(node.into());
        self
    }

    /// Set node fingerprint
    pub fn with_fingerprint(mut self, fp: impl Into<String>) -> Self {
        self.fingerprint = Some(fp.into());
        self
    }

    /// Set event details as JSON
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Set success/failure status
    pub fn with_success(mut self, success: bool) -> Self {
        self.success = Some(success);
        self
    }
}

/// Type of audit event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    NodeConnected,
    NodeDisconnected,
    NodeApproved,
    NodeRejected,
    CommandSent,
    CommandResult,
    FileTransferStarted,
    FileTransferCompleted,
    FileTransferError,
    AuthFailure,
}

impl EventType {
    /// Get the default severity for this event type
    pub fn default_severity(self) -> Severity {
        match self {
            Self::NodeConnected => Severity::Info,
            Self::NodeDisconnected => Severity::Info,
            Self::NodeApproved => Severity::High,
            Self::NodeRejected => Severity::High,
            Self::CommandSent => Severity::Info,
            Self::CommandResult => Severity::Info,
            Self::FileTransferStarted => Severity::Info,
            Self::FileTransferCompleted => Severity::Info,
            Self::FileTransferError => Severity::Warn,
            Self::AuthFailure => Severity::High,
        }
    }

    /// Get string representation for database storage
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NodeConnected => "NodeConnected",
            Self::NodeDisconnected => "NodeDisconnected",
            Self::NodeApproved => "NodeApproved",
            Self::NodeRejected => "NodeRejected",
            Self::CommandSent => "CommandSent",
            Self::CommandResult => "CommandResult",
            Self::FileTransferStarted => "FileTransferStarted",
            Self::FileTransferCompleted => "FileTransferCompleted",
            Self::FileTransferError => "FileTransferError",
            Self::AuthFailure => "AuthFailure",
        }
    }

    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "NodeConnected" => Some(Self::NodeConnected),
            "NodeDisconnected" => Some(Self::NodeDisconnected),
            "NodeApproved" => Some(Self::NodeApproved),
            "NodeRejected" => Some(Self::NodeRejected),
            "CommandSent" => Some(Self::CommandSent),
            "CommandResult" => Some(Self::CommandResult),
            "FileTransferStarted" => Some(Self::FileTransferStarted),
            "FileTransferCompleted" => Some(Self::FileTransferCompleted),
            "FileTransferError" => Some(Self::FileTransferError),
            "AuthFailure" => Some(Self::AuthFailure),
            _ => None,
        }
    }
}

/// Severity level of an event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warn,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::High => "HIGH",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "INFO" => Some(Self::Info),
            "WARN" => Some(Self::Warn),
            "HIGH" => Some(Self::High),
            _ => None,
        }
    }
}

/// Source of the audit event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    Quic,
    AdminWeb,
    Onvif,
    Cli,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quic => "quic",
            Self::AdminWeb => "admin_web",
            Self::Onvif => "onvif",
            Self::Cli => "cli",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "quic" => Some(Self::Quic),
            "admin_web" => Some(Self::AdminWeb),
            "onvif" => Some(Self::Onvif),
            "cli" => Some(Self::Cli),
            _ => None,
        }
    }
}

/// A stored audit event with ID and timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    pub id: i64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: EventType,
    pub severity: Severity,
    pub source: Source,
    pub source_addr: Option<String>,
    pub username: Option<String>,
    pub node_name: Option<String>,
    pub fingerprint: Option<String>,
    pub details: Option<serde_json::Value>,
    pub success: Option<bool>,
}
