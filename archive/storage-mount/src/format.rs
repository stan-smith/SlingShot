use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FormatError {
    #[error("Failed to execute command: {0}")]
    CommandFailed(#[from] std::io::Error),
    #[error("Command returned error: {0}")]
    CommandError(String),
    #[error("Failed to detect filesystem")]
    DetectionFailed,
}

#[derive(Debug, Clone)]
pub struct FilesystemInfo {
    pub fstype: Option<String>,
    pub uuid: Option<String>,
    pub label: Option<String>,
    pub used_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
}

impl FilesystemInfo {
    pub fn has_filesystem(&self) -> bool {
        self.fstype.is_some()
    }

    pub fn is_ext4(&self) -> bool {
        self.fstype.as_deref() == Some("ext4")
    }

    pub fn usage_string(&self) -> Option<String> {
        match (self.used_bytes, self.total_bytes) {
            (Some(used), Some(total)) => {
                let used_gb = used as f64 / 1_073_741_824.0;
                let total_gb = total as f64 / 1_073_741_824.0;
                Some(format!("{:.1}G / {:.1}G", used_gb, total_gb))
            }
            _ => None,
        }
    }
}

pub fn detect_filesystem(device: &str, dry_run: bool) -> Result<FilesystemInfo, FormatError> {
    if dry_run {
        println!("[DRY-RUN] Would execute: blkid {}", device);
    }

    let output = Command::new("blkid")
        .arg("-o")
        .arg("export")
        .arg(device)
        .output()?;

    let mut info = FilesystemInfo {
        fstype: None,
        uuid: None,
        label: None,
        used_bytes: None,
        total_bytes: None,
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

pub fn get_uuid(device: &str) -> Result<Option<String>, FormatError> {
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

pub fn format_ext4(device: &str, label: &str, dry_run: bool) -> Result<String, FormatError> {
    if dry_run {
        println!("[DRY-RUN] Would execute: mkfs.ext4 -L {} {}", label, device);
        return Ok("dry-run-uuid".to_string());
    }

    let output = Command::new("mkfs.ext4")
        .arg("-L")
        .arg(label)
        .arg(device)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(FormatError::CommandError(stderr.to_string()));
    }

    // Get the UUID after formatting
    get_uuid(device)?.ok_or(FormatError::DetectionFailed)
}

pub fn is_mounted(device: &str) -> Result<bool, FormatError> {
    let output = Command::new("findmnt")
        .arg("-n")
        .arg("-o")
        .arg("TARGET")
        .arg(device)
        .output()?;

    Ok(output.status.success() && !output.stdout.is_empty())
}

pub fn get_mountpoint(device: &str) -> Result<Option<String>, FormatError> {
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
pub fn get_partitions(device: &str) -> Result<Vec<String>, FormatError> {
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

/// Unmount a device and all its partitions
pub fn unmount_device_and_partitions(device: &str, dry_run: bool) -> Result<Vec<String>, FormatError> {
    let mut unmounted = Vec::new();

    // Get all partitions
    let partitions = get_partitions(device)?;

    // Unmount partitions first
    for part in &partitions {
        if let Some(mp) = get_mountpoint(part)? {
            if dry_run {
                println!("[DRY-RUN] Would execute: umount {}", part);
            } else {
                let output = Command::new("umount").arg(part).output()?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    return Err(FormatError::CommandError(format!(
                        "Failed to unmount {}: {}",
                        part, stderr
                    )));
                }
            }
            unmounted.push(format!("{} (was mounted at {})", part, mp));
        }
    }

    // Unmount the device itself if mounted
    if let Some(mp) = get_mountpoint(device)? {
        if dry_run {
            println!("[DRY-RUN] Would execute: umount {}", device);
        } else {
            let output = Command::new("umount").arg(device).output()?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(FormatError::CommandError(format!(
                    "Failed to unmount {}: {}",
                    device, stderr
                )));
            }
        }
        unmounted.push(format!("{} (was mounted at {})", device, mp));
    }

    Ok(unmounted)
}
