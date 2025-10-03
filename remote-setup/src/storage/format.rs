//! Filesystem detection, formatting, and device management.

use std::io::{Error, ErrorKind};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct FilesystemInfo {
    pub fstype: Option<String>,
    pub uuid: Option<String>,
    pub label: Option<String>,
}

impl FilesystemInfo {
    pub fn has_filesystem(&self) -> bool {
        self.fstype.is_some()
    }

    pub fn is_ext4(&self) -> bool {
        self.fstype.as_deref() == Some("ext4")
    }
}

/// Detect filesystem on a device using blkid
pub fn detect_filesystem(device: &str) -> Result<FilesystemInfo, Error> {
    let output = Command::new("blkid")
        .arg("-o")
        .arg("export")
        .arg(device)
        .output()?;

    let mut info = FilesystemInfo {
        fstype: None,
        uuid: None,
        label: None,
    };

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some((key, value)) = line.split_once('=') {
                match key {
                    "TYPE" => info.fstype = Some(value.to_string()),
                    "UUID" => info.uuid = Some(value.to_string()),
                    "LABEL" => info.label = Some(value.to_string()),
                    _ => {}
                }
            }
        }
    }

    Ok(info)
}

/// Get UUID of a device
pub fn get_uuid(device: &str) -> Result<Option<String>, Error> {
    let output = Command::new("blkid")
        .arg("-s")
        .arg("UUID")
        .arg("-o")
        .arg("value")
        .arg(device)
        .output()?;

    if output.status.success() {
        let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if uuid.is_empty() {
            Ok(None)
        } else {
            Ok(Some(uuid))
        }
    } else {
        Ok(None)
    }
}

/// Format device as ext4 with label, returns UUID
pub fn format_ext4(device: &str, label: &str) -> Result<String, Error> {
    let output = Command::new("sudo")
        .arg("mkfs.ext4")
        .arg("-L")
        .arg(label)
        .arg(device)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::new(
            ErrorKind::Other,
            format!("mkfs.ext4 failed: {}", stderr),
        ));
    }

    // Get the UUID after formatting
    get_uuid(device)?.ok_or_else(|| {
        Error::new(
            ErrorKind::Other,
            "Failed to get UUID after formatting",
        )
    })
}

/// Get mountpoint of a device
pub fn get_mountpoint(device: &str) -> Result<Option<String>, Error> {
    let output = Command::new("findmnt")
        .arg("-n")
        .arg("-o")
        .arg("TARGET")
        .arg(device)
        .output()?;

    if output.status.success() {
        let mp = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if mp.is_empty() {
            Ok(None)
        } else {
            Ok(Some(mp))
        }
    } else {
        Ok(None)
    }
}

/// Get all partitions of a device (e.g., /dev/sda -> [/dev/sda1, /dev/sda2, ...])
fn get_partitions(device: &str) -> Result<Vec<String>, Error> {
    let output = Command::new("lsblk")
        .arg("-ln")
        .arg("-o")
        .arg("NAME,TYPE")
        .arg(device)
        .output()?;

    let mut partitions = Vec::new();
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[1] == "part" {
                partitions.push(format!("/dev/{}", parts[0]));
            }
        }
    }
    Ok(partitions)
}

/// Unmount a device and all its partitions.
/// Returns list of unmounted devices with their previous mountpoints.
pub fn unmount_device_and_partitions(device: &str) -> Result<Vec<String>, Error> {
    let mut unmounted = Vec::new();

    // Get all partitions
    let partitions = get_partitions(device)?;

    // Unmount partitions first
    for part in &partitions {
        if let Some(mp) = get_mountpoint(part)? {
            let output = Command::new("sudo").arg("umount").arg(part).output()?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Failed to unmount {}: {}", part, stderr),
                ));
            }
            unmounted.push(format!("{} (was mounted at {})", part, mp));
        }
    }

    // Unmount the device itself if mounted
    if let Some(mp) = get_mountpoint(device)? {
        let output = Command::new("sudo").arg("umount").arg(device).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::new(
                ErrorKind::Other,
                format!("Failed to unmount {}: {}", device, stderr),
            ));
        }
        unmounted.push(format!("{} (was mounted at {})", device, mp));
    }

    Ok(unmounted)
}
