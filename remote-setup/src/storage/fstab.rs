//! Fstab entry management.

use std::io::{Error, ErrorKind};
use std::process::Command;

const FSTAB_PATH: &str = "/etc/fstab";

#[derive(Debug, Clone)]
pub struct FstabEntry {
    pub uuid: String,
    pub mountpoint: String,
    pub fstype: String,
    pub options: String,
    pub dump: u8,
    pub pass: u8,
}

impl FstabEntry {
    /// Create a new fstab entry with sensible defaults for recording storage
    pub fn new(uuid: &str, mountpoint: &str) -> Self {
        Self {
            uuid: uuid.to_string(),
            mountpoint: mountpoint.to_string(),
            fstype: "ext4".to_string(),
            options: "defaults,nofail".to_string(),
            dump: 0,
            pass: 2,
        }
    }

    /// Convert to fstab line format
    pub fn to_line(&self) -> String {
        format!(
            "UUID={}  {}  {}  {}  {}  {}",
            self.uuid, self.mountpoint, self.fstype, self.options, self.dump, self.pass
        )
    }
}

/// Check if UUID already exists in fstab
pub fn entry_exists_in_fstab(uuid: &str) -> Result<bool, Error> {
    let content = std::fs::read_to_string(FSTAB_PATH)?;
    let search = format!("UUID={}", uuid);
    Ok(content.contains(&search))
}

/// Add entry to fstab using sudo tee
pub fn add_fstab_entry(entry: &FstabEntry) -> Result<(), Error> {
    // Check if entry already exists
    if entry_exists_in_fstab(&entry.uuid)? {
        // Entry already exists, nothing to do
        return Ok(());
    }

    // Build the lines to append
    let append_text = format!(
        "\n# Storage for recordings (added by slingshot-remote-setup)\n{}\n",
        entry.to_line()
    );

    // Use sudo tee -a to append to fstab
    let mut child = Command::new("sudo")
        .arg("tee")
        .arg("-a")
        .arg(FSTAB_PATH)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()?;

    if let Some(stdin) = child.stdin.as_mut() {
        use std::io::Write;
        stdin.write_all(append_text.as_bytes())?;
    }

    let status = child.wait()?;
    if !status.success() {
        return Err(Error::new(
            ErrorKind::Other,
            "Failed to write to fstab",
        ));
    }

    Ok(())
}
