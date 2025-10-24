//! SQLite-backed fingerprint storage

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use kaiju_encryption::X25519KeyPair;
use rand::Rng;
use rusqlite::{params, Connection};
use totp_rs::{Algorithm, TOTP};

use crate::error::StoreError;

/// Expected length for fingerprint (Ed25519 public key as hex = 64 chars)
const FINGERPRINT_LEN: usize = 64;
/// Maximum length for node name
const MAX_NODE_NAME_LEN: usize = 64;
/// Maximum length for approved_by field
const MAX_APPROVED_BY_LEN: usize = 64;
/// Maximum length for username
const MAX_USERNAME_LEN: usize = 64;
/// Maximum length for user description
const MAX_DESCRIPTION_LEN: usize = 255;
/// TOTP issuer name for QR codes
const TOTP_ISSUER: &str = "SlingShot";

/// User information
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub role: String,
    pub description: Option<String>,
    pub created_at: String,
}

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

        // Set restrictive permissions (0600) - DB contains X25519 secret keys
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }

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

        // Admin users table (TOTP-based authentication)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS admin_users (
                username TEXT PRIMARY KEY,
                totp_secret TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                description TEXT,
                created_at TEXT NOT NULL
            )",
            [],
        )?;

        // Admin sessions table
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS admin_sessions (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (username) REFERENCES admin_users(username)
            )",
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

    // ========== Admin User Management (TOTP) ==========

    /// Generate a random session token (64 hex chars = 32 bytes)
    fn generate_session_token() -> String {
        let mut rng = rand::thread_rng();
        let bytes: [u8; 32] = rng.gen();
        hex::encode(bytes)
    }

    /// Generate a TOTP secret for a new user.
    /// Returns (base32_secret, qr_png_bytes).
    pub fn generate_totp_secret(username: &str) -> Result<(String, Vec<u8>), StoreError> {
        // Generate random 20-byte secret
        let mut rng = rand::thread_rng();
        let secret_bytes: [u8; 20] = rng.gen();
        let base32_secret = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &secret_bytes);

        // Create TOTP for QR code generation
        let totp = TOTP::new(
            Algorithm::SHA256,
            6,
            1,
            30,
            secret_bytes.to_vec(),
            Some(TOTP_ISSUER.to_string()),
            username.to_string(),
        )
        .map_err(|e| StoreError::TotpError(e.to_string()))?;

        // Generate QR code PNG
        let qr_png = totp
            .get_qr_png()
            .map_err(|e| StoreError::TotpError(e))?;

        Ok((base32_secret, qr_png))
    }

    /// Verify a TOTP code against a known secret (doesn't require database lookup).
    /// Used during initial setup before user is created.
    pub fn verify_totp_code(secret: &str, code: &str) -> Result<bool, StoreError> {
        // Decode base32 secret
        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
            .ok_or_else(|| StoreError::TotpError("Invalid base32 secret".to_string()))?;

        // Create TOTP and verify
        let totp = TOTP::new(
            Algorithm::SHA256,
            6,
            1,
            30,
            secret_bytes,
            Some(TOTP_ISSUER.to_string()),
            "setup".to_string(),
        )
        .map_err(|e| StoreError::TotpError(e.to_string()))?;

        Ok(totp.check_current(code).unwrap_or(false))
    }

    /// Verify a TOTP code for a user.
    /// Returns true if the code is valid.
    pub fn verify_totp(&self, username: &str, code: &str) -> Result<bool, StoreError> {
        // Get user's TOTP secret
        let secret: String = match self.conn.query_row(
            "SELECT totp_secret FROM admin_users WHERE username = ?",
            [username],
            |row| row.get(0),
        ) {
            Ok(s) => s,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(false),
            Err(e) => return Err(e.into()),
        };

        // Decode base32 secret
        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret)
            .ok_or_else(|| StoreError::TotpError("Invalid base32 secret".to_string()))?;

        // Create TOTP and verify
        let totp = TOTP::new(
            Algorithm::SHA256,
            6,
            1,
            30,
            secret_bytes,
            Some(TOTP_ISSUER.to_string()),
            username.to_string(),
        )
        .map_err(|e| StoreError::TotpError(e.to_string()))?;

        Ok(totp.check_current(code).unwrap_or(false))
    }

    /// Check if any users exist
    pub fn any_users_exist(&self) -> Result<bool, StoreError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM admin_users", [], |row| row.get(0))?;
        Ok(count > 0)
    }

    /// Count admin users (for last-admin protection)
    pub fn count_admins(&self) -> Result<usize, StoreError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM admin_users WHERE role = 'admin'",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Create a user with TOTP authentication
    pub fn create_user(
        &self,
        username: &str,
        totp_secret: &str,
        role: &str,
        description: &str,
    ) -> Result<(), StoreError> {
        // Validate field lengths
        if username.len() > MAX_USERNAME_LEN {
            return Err(StoreError::FieldTooLong {
                field: "username",
                max: MAX_USERNAME_LEN,
                actual: username.len(),
            });
        }
        if description.len() > MAX_DESCRIPTION_LEN {
            return Err(StoreError::FieldTooLong {
                field: "description",
                max: MAX_DESCRIPTION_LEN,
                actual: description.len(),
            });
        }
        if role != "admin" && role != "user" {
            return Err(StoreError::InvalidRole(role.to_string()));
        }

        let now = Utc::now().to_rfc3339();
        let desc = if description.is_empty() {
            None
        } else {
            Some(description)
        };

        self.conn.execute(
            "INSERT INTO admin_users (username, totp_secret, role, description, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![username, totp_secret, role, desc, now],
        )?;

        Ok(())
    }

    /// Get user info by username
    pub fn get_user(&self, username: &str) -> Result<Option<UserInfo>, StoreError> {
        let result = self.conn.query_row(
            "SELECT username, role, description, created_at FROM admin_users WHERE username = ?",
            [username],
            |row| {
                Ok(UserInfo {
                    username: row.get(0)?,
                    role: row.get(1)?,
                    description: row.get(2)?,
                    created_at: row.get(3)?,
                })
            },
        );

        match result {
            Ok(user) => Ok(Some(user)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List all users
    pub fn list_users(&self) -> Result<Vec<UserInfo>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT username, role, description, created_at FROM admin_users ORDER BY created_at",
        )?;

        let users = stmt
            .query_map([], |row| {
                Ok(UserInfo {
                    username: row.get(0)?,
                    role: row.get(1)?,
                    description: row.get(2)?,
                    created_at: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(users)
    }

    /// Update user role
    pub fn update_user_role(&self, username: &str, role: &str) -> Result<(), StoreError> {
        if role != "admin" && role != "user" {
            return Err(StoreError::InvalidRole(role.to_string()));
        }

        // Check last admin protection
        if role == "user" {
            let user = self.get_user(username)?;
            if let Some(u) = user {
                if u.role == "admin" && self.count_admins()? <= 1 {
                    return Err(StoreError::LastAdmin);
                }
            }
        }

        let rows = self.conn.execute(
            "UPDATE admin_users SET role = ? WHERE username = ?",
            params![role, username],
        )?;

        if rows == 0 {
            return Err(StoreError::NotFound(username.to_string()));
        }

        Ok(())
    }

    /// Update user description
    pub fn update_user_description(&self, username: &str, description: &str) -> Result<(), StoreError> {
        if description.len() > MAX_DESCRIPTION_LEN {
            return Err(StoreError::FieldTooLong {
                field: "description",
                max: MAX_DESCRIPTION_LEN,
                actual: description.len(),
            });
        }

        let desc = if description.is_empty() {
            None
        } else {
            Some(description)
        };

        let rows = self.conn.execute(
            "UPDATE admin_users SET description = ? WHERE username = ?",
            params![desc, username],
        )?;

        if rows == 0 {
            return Err(StoreError::NotFound(username.to_string()));
        }

        Ok(())
    }

    /// Delete a user
    pub fn delete_user(&self, username: &str) -> Result<(), StoreError> {
        // Check last admin protection
        let user = self.get_user(username)?;
        if let Some(u) = user {
            if u.role == "admin" && self.count_admins()? <= 1 {
                return Err(StoreError::LastAdmin);
            }
        } else {
            return Err(StoreError::NotFound(username.to_string()));
        }

        // Delete sessions first (foreign key)
        self.conn.execute(
            "DELETE FROM admin_sessions WHERE username = ?",
            [username],
        )?;

        // Delete user
        self.conn.execute(
            "DELETE FROM admin_users WHERE username = ?",
            [username],
        )?;

        Ok(())
    }

    /// Create a new session for a user, returns the session token
    pub fn create_session(&self, username: &str) -> Result<String, StoreError> {
        // Get user's role
        let role: String = self.conn.query_row(
            "SELECT role FROM admin_users WHERE username = ?",
            [username],
            |row| row.get(0),
        )?;

        let token = Self::generate_session_token();
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            "INSERT INTO admin_sessions (token, username, role, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![token, username, role, now],
        )?;

        Ok(token)
    }

    /// Verify a session token, returns (username, role) if valid
    pub fn verify_session(&self, token: &str) -> Result<Option<(String, String)>, StoreError> {
        let result = self.conn.query_row(
            "SELECT username, role FROM admin_sessions WHERE token = ?",
            [token],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        );

        match result {
            Ok((username, role)) => Ok(Some((username, role))),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete a session (logout)
    pub fn delete_session(&self, token: &str) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM admin_sessions WHERE token = ?", [token])?;
        Ok(())
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

    #[test]
    fn test_totp_generation_and_verification() {
        // Generate a TOTP secret
        let (secret, qr_png) = FingerprintStore::generate_totp_secret("testuser").unwrap();

        // Secret should be base32 encoded (uppercase letters A-Z and digits 2-7)
        assert!(!secret.is_empty());
        assert!(secret.chars().all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)));

        // QR PNG should be valid PNG data
        assert!(!qr_png.is_empty());
        assert!(qr_png.starts_with(&[0x89, b'P', b'N', b'G'])); // PNG magic bytes

        // Generate a valid code and verify it
        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret).unwrap();
        let totp = totp_rs::TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some("SlingShot".to_string()),
            "testuser".to_string(),
        ).unwrap();

        let code = totp.generate_current().unwrap();
        assert!(FingerprintStore::verify_totp_code(&secret, &code).unwrap());

        // Wrong code should fail
        assert!(!FingerprintStore::verify_totp_code(&secret, "000000").unwrap());
    }

    #[test]
    fn test_user_creation_and_totp_auth() {
        let (store, _dir) = test_store();

        // Initially no users exist
        assert!(store.any_users_exist().is_ok());
        assert!(!store.any_users_exist().unwrap());

        // Generate TOTP secret
        let (secret, _) = FingerprintStore::generate_totp_secret("admin").unwrap();

        // Create admin user
        store.create_user("admin", &secret, "admin", "Test admin").unwrap();

        // Now users exist
        assert!(store.any_users_exist().unwrap());

        // Can get user info
        let user = store.get_user("admin").unwrap().unwrap();
        assert_eq!(user.username, "admin");
        assert_eq!(user.role, "admin");
        assert_eq!(user.description.as_deref(), Some("Test admin"));

        // Admin count is 1
        assert_eq!(store.count_admins().unwrap(), 1);

        // List users returns the admin
        let users = store.list_users().unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "admin");

        // TOTP verification works
        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret).unwrap();
        let totp = totp_rs::TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some("SlingShot".to_string()),
            "admin".to_string(),
        ).unwrap();
        let code = totp.generate_current().unwrap();
        assert!(store.verify_totp("admin", &code).unwrap());
    }

    #[test]
    fn test_last_admin_protection() {
        let (store, _dir) = test_store();

        let (secret, _) = FingerprintStore::generate_totp_secret("admin").unwrap();
        store.create_user("admin", &secret, "admin", "").unwrap();

        // Cannot demote last admin
        let result = store.update_user_role("admin", "user");
        assert!(matches!(result, Err(StoreError::LastAdmin)));

        // Cannot delete last admin
        let result = store.delete_user("admin");
        assert!(matches!(result, Err(StoreError::LastAdmin)));

        // Create second admin
        let (secret2, _) = FingerprintStore::generate_totp_secret("admin2").unwrap();
        store.create_user("admin2", &secret2, "admin", "").unwrap();

        // Now can demote first admin
        assert!(store.update_user_role("admin", "user").is_ok());

        // But cannot demote/delete the remaining admin
        let result = store.update_user_role("admin2", "user");
        assert!(matches!(result, Err(StoreError::LastAdmin)));
    }
}
