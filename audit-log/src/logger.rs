use crate::error::AuditError;
use crate::event::{AuditEvent, EventType, Severity, Source, StoredEvent};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

/// Audit logger backed by SQLite
pub struct AuditLogger {
    conn: Connection,
}

impl AuditLogger {
    /// Get the default database path
    pub fn default_path() -> Result<PathBuf, AuditError> {
        let data_dir = dirs::data_dir().ok_or(AuditError::NoDataDir)?;
        Ok(data_dir.join("slingshot").join("audit.db"))
    }

    /// Open the audit logger at the default path
    pub fn open() -> Result<Self, AuditError> {
        let path = Self::default_path()?;
        Self::open_at(&path)
    }

    /// Open the audit logger at a specific path
    pub fn open_at(path: &Path) -> Result<Self, AuditError> {
        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        let logger = Self { conn };
        logger.init_schema()?;
        Ok(logger)
    }

    /// Initialize the database schema
    fn init_schema(&self) -> Result<(), AuditError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                source_addr TEXT,
                username TEXT,
                node_name TEXT,
                fingerprint TEXT,
                details TEXT,
                success INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type);
            CREATE INDEX IF NOT EXISTS idx_audit_node ON audit_events(node_name);
            CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_events(username);",
        )?;
        Ok(())
    }

    /// Log an audit event
    pub fn log(&self, event: AuditEvent) -> Result<i64, AuditError> {
        let timestamp = Utc::now().to_rfc3339();
        let details_json = event
            .details
            .as_ref()
            .map(|d| serde_json::to_string(d))
            .transpose()?;

        self.conn.execute(
            "INSERT INTO audit_events
             (timestamp, event_type, severity, source, source_addr, username, node_name, fingerprint, details, success)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                timestamp,
                event.event_type.as_str(),
                event.severity.as_str(),
                event.source.as_str(),
                event.source_addr,
                event.username,
                event.node_name,
                event.fingerprint,
                details_json,
                event.success.map(|b| if b { 1 } else { 0 }),
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Query recent events
    pub fn query_recent(&self, limit: usize) -> Result<Vec<StoredEvent>, AuditError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, event_type, severity, source, source_addr, username, node_name, fingerprint, details, success
             FROM audit_events
             ORDER BY timestamp DESC
             LIMIT ?",
        )?;

        let events = stmt
            .query_map([limit], |row| {
                Ok(Self::row_to_event(row))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(events)
    }

    /// Query events by node name
    pub fn query_by_node(&self, node: &str, limit: usize) -> Result<Vec<StoredEvent>, AuditError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, event_type, severity, source, source_addr, username, node_name, fingerprint, details, success
             FROM audit_events
             WHERE node_name = ?
             ORDER BY timestamp DESC
             LIMIT ?",
        )?;

        let events = stmt
            .query_map(params![node, limit], |row| {
                Ok(Self::row_to_event(row))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(events)
    }

    /// Query events by username
    pub fn query_by_username(&self, username: &str, limit: usize) -> Result<Vec<StoredEvent>, AuditError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, event_type, severity, source, source_addr, username, node_name, fingerprint, details, success
             FROM audit_events
             WHERE username = ?
             ORDER BY timestamp DESC
             LIMIT ?",
        )?;

        let events = stmt
            .query_map(params![username, limit], |row| {
                Ok(Self::row_to_event(row))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(events)
    }

    /// Prune events older than the specified number of days
    pub fn prune_older_than(&self, days: u32) -> Result<usize, AuditError> {
        let cutoff = Utc::now() - chrono::Duration::days(days as i64);
        let cutoff_str = cutoff.to_rfc3339();

        let deleted = self.conn.execute(
            "DELETE FROM audit_events WHERE timestamp < ?",
            [cutoff_str],
        )?;

        Ok(deleted)
    }

    /// Get the total number of events
    pub fn count(&self) -> Result<usize, AuditError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM audit_events",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Convert a database row to a StoredEvent
    fn row_to_event(row: &rusqlite::Row) -> StoredEvent {
        let id: i64 = row.get(0).unwrap_or(0);
        let timestamp_str: String = row.get(1).unwrap_or_default();
        let event_type_str: String = row.get(2).unwrap_or_default();
        let severity_str: String = row.get(3).unwrap_or_default();
        let source_str: String = row.get(4).unwrap_or_default();
        let source_addr: Option<String> = row.get(5).ok();
        let username: Option<String> = row.get(6).ok();
        let node_name: Option<String> = row.get(7).ok();
        let fingerprint: Option<String> = row.get(8).ok();
        let details_str: Option<String> = row.get(9).ok();
        let success_int: Option<i32> = row.get(10).ok();

        let timestamp = timestamp_str
            .parse::<DateTime<Utc>>()
            .unwrap_or_else(|_| Utc::now());

        let details = details_str
            .and_then(|s| serde_json::from_str(&s).ok());

        StoredEvent {
            id,
            timestamp,
            event_type: EventType::from_str(&event_type_str).unwrap_or(EventType::NodeConnected),
            severity: Severity::from_str(&severity_str).unwrap_or(Severity::Info),
            source: Source::from_str(&source_str).unwrap_or(Source::Quic),
            source_addr,
            username,
            node_name,
            fingerprint,
            details,
            success: success_int.map(|i| i != 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{tempdir, TempDir};

    fn test_logger() -> (AuditLogger, TempDir) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_audit.db");
        let logger = AuditLogger::open_at(&path).unwrap();
        (logger, dir)
    }

    #[test]
    fn test_log_and_query() {
        let (logger, _dir) = test_logger();

        let event = AuditEvent::new(EventType::NodeConnected, Source::Quic)
            .with_node("test-node")
            .with_source_addr("192.168.1.1:5000")
            .with_fingerprint("abc123");

        let id = logger.log(event).unwrap();
        assert!(id > 0);

        let events = logger.query_recent(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, EventType::NodeConnected);
        assert_eq!(events[0].node_name, Some("test-node".to_string()));
    }

    #[test]
    fn test_query_by_node() {
        let (logger, _dir) = test_logger();

        logger.log(AuditEvent::new(EventType::CommandSent, Source::Cli)
            .with_node("node1")).unwrap();
        logger.log(AuditEvent::new(EventType::CommandSent, Source::Cli)
            .with_node("node2")).unwrap();
        logger.log(AuditEvent::new(EventType::CommandResult, Source::Quic)
            .with_node("node1")).unwrap();

        let node1_events = logger.query_by_node("node1", 10).unwrap();
        assert_eq!(node1_events.len(), 2);

        let node2_events = logger.query_by_node("node2", 10).unwrap();
        assert_eq!(node2_events.len(), 1);
    }

    #[test]
    fn test_query_by_username() {
        let (logger, _dir) = test_logger();

        logger.log(AuditEvent::new(EventType::CommandSent, Source::AdminWeb)
            .with_username("admin")).unwrap();
        logger.log(AuditEvent::new(EventType::CommandSent, Source::Onvif)
            .with_username("onvif")).unwrap();

        let admin_events = logger.query_by_username("admin", 10).unwrap();
        assert_eq!(admin_events.len(), 1);
        assert_eq!(admin_events[0].source, Source::AdminWeb);
    }

    #[test]
    fn test_prune() {
        let (logger, _dir) = test_logger();

        // Log some events
        logger.log(AuditEvent::new(EventType::NodeConnected, Source::Quic)).unwrap();
        logger.log(AuditEvent::new(EventType::NodeConnected, Source::Quic)).unwrap();

        assert_eq!(logger.count().unwrap(), 2);

        // Prune with 30 days - events just created should NOT be deleted
        let deleted = logger.prune_older_than(30).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(logger.count().unwrap(), 2);
    }

    #[test]
    fn test_event_with_details() {
        let (logger, _dir) = test_logger();

        let details = serde_json::json!({
            "command": "res 1280 720",
            "source_node": "khadas"
        });

        let event = AuditEvent::new(EventType::CommandSent, Source::AdminWeb)
            .with_username("admin")
            .with_node("khadas")
            .with_details(details.clone())
            .with_success(true);

        logger.log(event).unwrap();

        let events = logger.query_recent(1).unwrap();
        assert_eq!(events[0].details, Some(details));
        assert_eq!(events[0].success, Some(true));
    }
}
