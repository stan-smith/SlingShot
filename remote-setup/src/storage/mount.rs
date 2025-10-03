//! Mountpoint creation and device mounting.

use std::io::{Error, ErrorKind};
use std::path::Path;
use std::process::Command;

/// Create mountpoint directory if it doesn't exist
pub fn create_mountpoint(path: &Path) -> Result<(), Error> {
    if path.exists() {
        return Ok(());
    }

    // Use sudo mkdir since mountpoints are typically in system directories
    let output = Command::new("sudo")
        .arg("mkdir")
        .arg("-p")
        .arg(path)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::new(
            ErrorKind::Other,
            format!("Failed to create mountpoint: {}", stderr),
        ));
    }

    Ok(())
}

/// Mount device at mountpoint and set ownership to current user
pub fn mount_device(device: &str, mountpoint: &Path) -> Result<(), Error> {
    let output = Command::new("sudo")
        .arg("mount")
        .arg(device)
        .arg(mountpoint)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::new(
            ErrorKind::Other,
            format!("mount failed: {}", stderr),
        ));
    }

    // Set ownership to current user so they can write to it
    let current_user = std::env::var("USER").map_err(|_| {
        Error::new(ErrorKind::Other, "USER environment variable not set, you need to manually add user perms for the storage mount, so 'sudo chown (your username) /path/to/recs' - Stan")
    })?;
    let output = Command::new("sudo")
        .arg("chown")
        .arg(&current_user)
        .arg(mountpoint)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::new(
            ErrorKind::Other,
            format!("Failed to set ownership: {}", stderr),
        ));
    }

    Ok(())
}

