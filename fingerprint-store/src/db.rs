//! SQLite-backed fingerprint storage

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};

use crate::error::StoreError;

/// Maximum length for fingerprint (Ed25519 public key as hex = 64 chars)
const MAX_FINGERPRINT_LEN: usize = 64;
/// Maximum length for node name
const MAX_NODE_NAME_LEN: usize = 64;
/// Maximum length for approved_by field
const MAX_APPROVED_BY_LEN: usize = 64;

/// Approved node record
#[derive(Debug, Clone)]
pub struct ApprovedNode {
    pub fingerprint: String,
    pub node_name: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub approved_by: Option<String>,
}

/// SQLite-backed fingerprint store
pub struct FingerprintStore {
    conn: Connection,
}

impl FingerprintStore {
    /// Open or create database at default XDG location
    /// ~/.local/share/kaiju/approved_nodes.db
    pub fn open() -> Result<Self, StoreError> {
        let path = Self::default_path()?;
        Self::open_at(&path)
    }

    /// Get default database path
    pub fn default_path() -> Result<PathBuf, StoreError> {
        let data_dir = dirs::data_dir()
            .ok_or(StoreError::NoDataDir)?
            .join("kaiju");
        Ok(data_dir.join("approved_nodes.db"))
    }

    /// Open or create database at specific path
    pub fn open_at(path: &Path) -> Result<Self, StoreError> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Initialize database schema
    fn init_schema(&self) -> Result<(), StoreError> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS approved_nodes (
                fingerprint TEXT PRIMARY KEY,
                node_name TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                approved_by TEXT
            )",
            [],
        )?;

        // Index for quick node_name lookup
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_node_name ON approved_nodes(node_name)",
            [],
        )?;

        Ok(())
    }

    /// Check if fingerprint is approved (returns node info if found)
    pub fn is_approved(&self, fingerprint: &str) -> Result<Option<ApprovedNode>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT fingerprint, node_name, first_seen, last_seen, approved_by
             FROM approved_nodes WHERE fingerprint = ?",
        )?;

        let result = stmt.query_row([fingerprint], |row| {
            Ok(ApprovedNode {
                fingerprint: row.get(0)?,
                node_name: row.get(1)?,
                first_seen: row
                    .get::<_, String>(2)?
                    .parse()
                    .unwrap_or_else(|_| Utc::now()),
                last_seen: row
                    .get::<_, String>(3)?
                    .parse()
                    .unwrap_or_else(|_| Utc::now()),
                approved_by: row.get(4)?,
            })
        });

        match result {
            Ok(node) => Ok(Some(node)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Add or update an approved node
    pub fn approve(
        &self,
        fingerprint: &str,
        node_name: &str,
        approved_by: Option<&str>,
    ) -> Result<(), StoreError> {
        // Validate field lengths
        if fingerprint.len() > MAX_FINGERPRINT_LEN {
            return Err(StoreError::FieldTooLong {
                field: "fingerprint",
                max: MAX_FINGERPRINT_LEN,
                actual: fingerprint.len(),
            });
        }
        if node_name.len() > MAX_NODE_NAME_LEN {
            return Err(StoreError::FieldTooLong {
                field: "node_name",
                max: MAX_NODE_NAME_LEN,
                actual: node_name.len(),
            });
        }
        if let Some(by) = approved_by {
            if by.len() > MAX_APPROVED_BY_LEN {
                return Err(StoreError::FieldTooLong {
                    field: "approved_by",
                    max: MAX_APPROVED_BY_LEN,
                    actual: by.len(),
                });
            }
        }

        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            "INSERT INTO approved_nodes (fingerprint, node_name, first_seen, last_seen, approved_by)
             VALUES (?1, ?2, ?3, ?3, ?4)
             ON CONFLICT(fingerprint) DO UPDATE SET
                node_name = ?2,
                last_seen = ?3,
                approved_by = COALESCE(?4, approved_by)",
            params![fingerprint, node_name, now, approved_by],
        )?;

        Ok(())
    }

    /// Update last_seen timestamp for reconnecting node
    pub fn update_last_seen(&self, fingerprint: &str) -> Result<(), StoreError> {
        let now = Utc::now().to_rfc3339();

        let rows = self.conn.execute(
            "UPDATE approved_nodes SET last_seen = ? WHERE fingerprint = ?",
            params![now, fingerprint],
        )?;

        if rows == 0 {
            return Err(StoreError::NotFound(fingerprint.to_string()));
        }

        Ok(())
    }

    /// Revoke approval for a fingerprint
    pub fn revoke(&self, fingerprint: &str) -> Result<bool, StoreError> {
        let rows = self
            .conn
            .execute("DELETE FROM approved_nodes WHERE fingerprint = ?", [fingerprint])?;
        Ok(rows > 0)
    }

    /// List all approved nodes
    pub fn list_approved(&self) -> Result<Vec<ApprovedNode>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT fingerprint, node_name, first_seen, last_seen, approved_by
             FROM approved_nodes ORDER BY last_seen DESC",
        )?;

        let nodes = stmt.query_map([], |row| {
            Ok(ApprovedNode {
                fingerprint: row.get(0)?,
                node_name: row.get(1)?,
                first_seen: row
                    .get::<_, String>(2)?
                    .parse()
                    .unwrap_or_else(|_| Utc::now()),
                last_seen: row
                    .get::<_, String>(3)?
                    .parse()
                    .unwrap_or_else(|_| Utc::now()),
                approved_by: row.get(4)?,
            })
        })?;

        nodes.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}
