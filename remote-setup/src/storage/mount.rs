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

/// Check if device is already mounted at the specified mountpoint
fn is_mounted_at(device: &str, mountpoint: &Path) -> bool {
    let output = Command::new("findmnt")
        .arg("-n")
        .arg("-o")
        .arg("SOURCE")
        .arg(mountpoint)
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let source = String::from_utf8_lossy(&out.stdout);
            source.trim() == device
        }
        _ => false,
    }
}

/// Mount device at mountpoint and set ownership to current user
pub fn mount_device(device: &str, mountpoint: &Path) -> Result<(), Error> {
    // Check if already mounted at this location
    if is_mounted_at(device, mountpoint) {
        // Already mounted correctly, just ensure ownership
        return set_ownership(mountpoint);
    }

    let output = Command::new("sudo")
        .arg("mount")
        .arg(device)
        .arg(mountpoint)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Double-check if it's an "already mounted" error and we're at the right place
        if stderr.contains("already mounted") && is_mounted_at(device, mountpoint) {
            return set_ownership(mountpoint);
        }
        return Err(Error::new(
            ErrorKind::Other,
            format!("mount failed: {}", stderr),
        ));
    }

    set_ownership(mountpoint)
}

/// Set ownership of mountpoint to current user
fn set_ownership(mountpoint: &Path) -> Result<(), Error> {

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

