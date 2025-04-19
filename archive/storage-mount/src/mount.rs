use std::path::Path;
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MountError {
    #[error("Failed to execute command: {0}")]
    CommandFailed(#[from] std::io::Error),
    #[error("Mount failed: {0}")]
    MountFailed(String),
    #[error("Unmount failed: {0}")]
    UnmountFailed(String),
    #[error("Failed to create mountpoint: {0}")]
    CreateMountpointFailed(String),
}

pub fn create_mountpoint(path: &Path, dry_run: bool) -> Result<(), MountError> {
    if dry_run {
        println!("[DRY-RUN] Would execute: mkdir -p {}", path.display());
        return Ok(());
    }

    if path.exists() {
        return Ok(());
    }

    std::fs::create_dir_all(path).map_err(|e| MountError::CreateMountpointFailed(e.to_string()))
}

pub fn mount_device(device: &str, mountpoint: &Path, dry_run: bool) -> Result<(), MountError> {
    if dry_run {
        println!(
            "[DRY-RUN] Would execute: mount {} {}",
            device,
            mountpoint.display()
        );
        return Ok(());
    }

    let output = Command::new("mount").arg(device).arg(mountpoint).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(MountError::MountFailed(stderr.to_string()));
    }

    Ok(())
}

pub fn unmount_device(mountpoint: &Path, dry_run: bool) -> Result<(), MountError> {
    if dry_run {
        println!("[DRY-RUN] Would execute: umount {}", mountpoint.display());
        return Ok(());
    }

    let output = Command::new("umount").arg(mountpoint).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(MountError::UnmountFailed(stderr.to_string()));
    }

    Ok(())
}

pub fn is_mountpoint_in_use(mountpoint: &Path) -> Result<bool, MountError> {
    let output = Command::new("findmnt")
        .arg("-n")
        .arg("-o")
        .arg("SOURCE")
        .arg(mountpoint)
        .output()?;

    Ok(output.status.success() && !output.stdout.is_empty())
}
