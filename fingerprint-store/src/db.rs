//! SQLite-backed fingerprint storage

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use kaiju_encryption::X25519KeyPair;
use rusqlite::{params, Connection};

use crate::error::StoreError;

/// Expected length for fingerprint (Ed25519 public key as hex = 64 chars)
const FINGERPRINT_LEN: usize = 64;
/// Maximum length for node name
const MAX_NODE_NAME_LEN: usize = 64;
/// Maximum length for approved_by field
const MAX_APPROVED_BY_LEN: usize = 64;

/// Validate fingerprint format (must be exactly 64 hex characters)
fn validate_fingerprint(fingerprint: &str) -> Result<(), StoreError> {
    if fingerprint.len() != FINGERPRINT_LEN {
        return Err(StoreError::InvalidFingerprint(format!(
            "expected {} hex chars, got {}",
            FINGERPRINT_LEN,
            fingerprint.len()
        )));
    }
    if hex::decode(fingerprint).is_err() {
        return Err(StoreError::InvalidFingerprint(
            "not valid hexadecimal".to_string(),
        ));
    }
    Ok(())
}

/// Parse timestamp string with warning on failure
fn parse_timestamp(s: &str, field: &str, fingerprint: &str) -> DateTime<Utc> {
    match s.parse() {
        Ok(dt) => dt,
        Err(e) => {
            eprintln!(
                "[WARNING] Failed to parse {} for {}...: '{}' ({}). Using current time.",
                field,
                &fingerprint[..16.min(fingerprint.len())],
                s,
                e
            );
            Utc::now()
        }
    }
}

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
                approved_by TEXT,
                x25519_secret TEXT,
                x25519_public TEXT
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
        validate_fingerprint(fingerprint)?;
        let mut stmt = self.conn.prepare(
            "SELECT fingerprint, node_name, first_seen, last_seen, approved_by
             FROM approved_nodes WHERE fingerprint = ?",
        )?;

        let result = stmt.query_row([fingerprint], |row| {
            let fp: String = row.get(0)?;
            let first_seen_str: String = row.get(2)?;
            let last_seen_str: String = row.get(3)?;
            Ok((fp, row.get::<_, String>(1)?, first_seen_str, last_seen_str, row.get(4)?))
        });

        match result {
            Ok((fp, node_name, first_seen_str, last_seen_str, approved_by)) => {
                Ok(Some(ApprovedNode {
                    fingerprint: fp.clone(),
                    node_name,
                    first_seen: parse_timestamp(&first_seen_str, "first_seen", &fp),
                    last_seen: parse_timestamp(&last_seen_str, "last_seen", &fp),
                    approved_by,
                }))
            }
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
        // Validate fingerprint format
        validate_fingerprint(fingerprint)?;

        // Validate field lengths
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

        // Check for node name changes (for audit logging)
        if let Ok(Some(existing)) = self.is_approved(fingerprint) {
            if existing.node_name != node_name {
                eprintln!(
                    "[SECURITY] Node name changed: '{}' -> '{}' (fingerprint: {}...)",
                    existing.node_name,
                    node_name,
                    &fingerprint[..16.min(fingerprint.len())]
                );
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
        validate_fingerprint(fingerprint)?;
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
        validate_fingerprint(fingerprint)?;
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

        // First collect raw data from DB
        let raw_nodes = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;

        // Then transform with timestamp parsing (can log warnings)
        let mut nodes = Vec::new();
        for result in raw_nodes {
            let (fp, node_name, first_seen_str, last_seen_str, approved_by) = result?;
            nodes.push(ApprovedNode {
                fingerprint: fp.clone(),
                node_name,
                first_seen: parse_timestamp(&first_seen_str, "first_seen", &fp),
                last_seen: parse_timestamp(&last_seen_str, "last_seen", &fp),
                approved_by,
            });
        }

        Ok(nodes)
    }

    /// Generate and store an X25519 encryption keypair for a remote node.
    /// If a keypair already exists for this fingerprint, returns the existing public key.
    /// Returns the hex-encoded public key.
    pub fn generate_encryption_key(&self, fingerprint: &str) -> Result<String, StoreError> {
        validate_fingerprint(fingerprint)?;
        // Check if key already exists
        if let Some(pubkey) = self.get_encryption_pubkey(fingerprint)? {
            return Ok(pubkey);
        }

        // Generate new keypair
        let keypair = X25519KeyPair::generate();
        let secret_hex = keypair.secret_hex();
        let public_hex = keypair.public_hex();

        // Store in database
        let rows = self.conn.execute(
            "UPDATE approved_nodes SET x25519_secret = ?, x25519_public = ? WHERE fingerprint = ?",
            params![secret_hex, public_hex, fingerprint],
        )?;

        // Critical: verify the key was actually stored
        if rows == 0 {
            return Err(StoreError::NotFound(format!(
                "Cannot store encryption key: fingerprint {} not in approved_nodes",
                fingerprint
            )));
        }

        Ok(public_hex)
    }

    /// Get the encryption keypair (secret and public) for a remote node.
    /// Returns (secret_hex, public_hex) if exists.
    /// Used by central when decrypting retrieved recordings.
    pub fn get_encryption_keypair(
        &self,
        fingerprint: &str,
    ) -> Result<Option<(String, String)>, StoreError> {
        validate_fingerprint(fingerprint)?;
        let mut stmt = self.conn.prepare(
            "SELECT x25519_secret, x25519_public FROM approved_nodes WHERE fingerprint = ?",
        )?;

        let result = stmt.query_row([fingerprint], |row| {
            let secret: Option<String> = row.get(0)?;
            let public: Option<String> = row.get(1)?;
            Ok((secret, public))
        });

        match result {
            Ok((Some(secret), Some(public))) => Ok(Some((secret, public))),
            Ok(_) => Ok(None), // One or both keys missing
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get only the public encryption key for a remote node.
    /// Used when re-sending pubkey on reconnection.
    pub fn get_encryption_pubkey(&self, fingerprint: &str) -> Result<Option<String>, StoreError> {
        validate_fingerprint(fingerprint)?;
        let mut stmt = self
            .conn
            .prepare("SELECT x25519_public FROM approved_nodes WHERE fingerprint = ?")?;

        let result = stmt.query_row([fingerprint], |row| row.get::<_, Option<String>>(0));

        match result {
            Ok(pubkey) => Ok(pubkey),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_store() -> (FingerprintStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let store = FingerprintStore::open_at(&path).unwrap();
        (store, dir)
    }

    #[test]
    fn test_approve_and_lookup() {
        let (store, _dir) = test_store();
        let fingerprint = "a".repeat(64);

        // Not approved yet
        assert!(store.is_approved(&fingerprint).unwrap().is_none());

        // Approve
        store.approve(&fingerprint, "test-node", Some("admin")).unwrap();

        // Now approved
        let node = store.is_approved(&fingerprint).unwrap().unwrap();
        assert_eq!(node.node_name, "test-node");
        assert_eq!(node.approved_by, Some("admin".to_string()));
    }

    #[test]
    fn test_generate_encryption_key_success() {
        let (store, _dir) = test_store();
        let fingerprint = "b".repeat(64);

        // Must approve first
        store.approve(&fingerprint, "test-node", None).unwrap();

        // Generate key
        let pubkey = store.generate_encryption_key(&fingerprint).unwrap();
        assert_eq!(pubkey.len(), 64); // 32 bytes as hex

        // Key should be retrievable
        let (secret, public) = store.get_encryption_keypair(&fingerprint).unwrap().unwrap();
        assert_eq!(public, pubkey);
        assert_eq!(secret.len(), 64);
    }

    #[test]
    fn test_generate_encryption_key_returns_existing() {
        let (store, _dir) = test_store();
        let fingerprint = "c".repeat(64);

        store.approve(&fingerprint, "test-node", None).unwrap();

        let pubkey1 = store.generate_encryption_key(&fingerprint).unwrap();
        let pubkey2 = store.generate_encryption_key(&fingerprint).unwrap();

        // Should return same key, not generate new one
        assert_eq!(pubkey1, pubkey2);
    }

    #[test]
    fn test_generate_encryption_key_fails_for_unknown_fingerprint() {
        let (store, _dir) = test_store();
        let fingerprint = "d".repeat(64);

        // Don't approve - try to generate key directly
        let result = store.generate_encryption_key(&fingerprint);

        // Should fail with NotFound
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, StoreError::NotFound(_)));
    }

    #[test]
    fn test_revoke() {
        let (store, _dir) = test_store();
        let fingerprint = "e".repeat(64);

        store.approve(&fingerprint, "test-node", None).unwrap();
        assert!(store.is_approved(&fingerprint).unwrap().is_some());

        store.revoke(&fingerprint).unwrap();
        assert!(store.is_approved(&fingerprint).unwrap().is_none());
    }

    #[test]
    fn test_field_length_validation() {
        let (store, _dir) = test_store();
        let fingerprint = "a".repeat(64);

        // Long node name should fail with FieldTooLong
        let long_name = "x".repeat(100);
        let result = store.approve(&fingerprint, &long_name, None);
        assert!(matches!(result, Err(StoreError::FieldTooLong { .. })));
    }

    #[test]
    fn test_fingerprint_validation_wrong_length() {
        let (store, _dir) = test_store();

        // Too short
        let short = "a".repeat(63);
        let result = store.is_approved(&short);
        assert!(matches!(result, Err(StoreError::InvalidFingerprint(_))));

        // Too long
        let long = "a".repeat(65);
        let result = store.approve(&long, "test", None);
        assert!(matches!(result, Err(StoreError::InvalidFingerprint(_))));
    }

    #[test]
    fn test_fingerprint_validation_invalid_hex() {
        let (store, _dir) = test_store();

        // Not valid hex (contains 'g')
        let invalid = "g".repeat(64);
        let result = store.is_approved(&invalid);
        assert!(matches!(result, Err(StoreError::InvalidFingerprint(_))));
    }

    #[test]
    fn test_fingerprint_validation_valid() {
        let (store, _dir) = test_store();

        // Valid 64-char hex string
        let valid = "0123456789abcdef".repeat(4);
        assert_eq!(valid.len(), 64);

        // Should not error on validation (may return None since not approved)
        let result = store.is_approved(&valid);
        assert!(result.is_ok());
    }
}
