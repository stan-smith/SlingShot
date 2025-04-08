use std::path::{Path, PathBuf};

/// Delete the oldest recording file in the given directory
/// Returns the path of the deleted file, or None if no files found
pub fn delete_oldest_recording(dir: &Path, file_format: &str) -> Result<Option<PathBuf>, DiskError> {
    // Find all recording files
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| DiskError::IoError(e.to_string()))?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.path().extension()
                .map(|ext| ext == file_format)
                .unwrap_or(false)
        })
        .filter_map(|entry| {
            let metadata = entry.metadata().ok()?;
            let modified = metadata.modified().ok()?;
            Some((entry.path(), modified))
        })
        .collect();

    if files.is_empty() {
        return Ok(None);
    }

    // Sort by modified time (oldest first)
    files.sort_by_key(|(_, modified)| *modified);

    // Delete the oldest file
    let (oldest_path, _) = &files[0];
    let deleted_path = oldest_path.clone();

    std::fs::remove_file(oldest_path)
        .map_err(|e| DiskError::IoError(format!("Failed to delete {}: {}", oldest_path.display(), e)))?;

    Ok(Some(deleted_path))
}

/// Ensure disk space by deleting oldest recordings until space is available
/// Returns the number of files deleted
pub fn ensure_disk_space(dir: &Path, reserve_percent: u8, file_format: &str) -> Result<usize, DiskError> {
    let mut deleted_count = 0;

    while !has_disk_space(dir, reserve_percent) {
        match delete_oldest_recording(dir, file_format)? {
            Some(path) => {
                eprintln!("Deleted old recording to free space: {}", path.display());
                deleted_count += 1;
            }
            None => {
                return Err(DiskError::NoFilesToDelete);
            }
        }
    }

    Ok(deleted_count)
}

/// Check if there's enough disk space to continue recording
/// Returns true if disk usage is below the reserve threshold
pub fn has_disk_space(path: &Path, reserve_percent: u8) -> bool {
    match get_disk_usage(path) {
        Ok(usage) => usage < reserve_percent,
        Err(e) => {
            eprintln!("Warning: Could not check disk space: {}", e);
            true // Continue recording if we can't check
        }
    }
}

/// Get disk usage percentage for the filesystem containing the given path
pub fn get_disk_usage(path: &Path) -> Result<u8, DiskError> {
    use nix::sys::statvfs::statvfs;

    let stat = statvfs(path).map_err(|e| DiskError::StatvfsFailed(e.to_string()))?;

    let total_blocks = stat.blocks();
    let available_blocks = stat.blocks_available();

    if total_blocks == 0 {
        return Err(DiskError::InvalidFilesystem);
    }

    let used_blocks = total_blocks - available_blocks;
    let usage_percent = ((used_blocks as f64 / total_blocks as f64) * 100.0) as u8;

    Ok(usage_percent)
}

/// Get available disk space in bytes
pub fn get_available_bytes(path: &Path) -> Result<u64, DiskError> {
    use nix::sys::statvfs::statvfs;

    let stat = statvfs(path).map_err(|e| DiskError::StatvfsFailed(e.to_string()))?;

    let available = stat.blocks_available() as u64 * stat.block_size() as u64;
    Ok(available)
}

/// Get total disk space in bytes
pub fn get_total_bytes(path: &Path) -> Result<u64, DiskError> {
    use nix::sys::statvfs::statvfs;

    let stat = statvfs(path).map_err(|e| DiskError::StatvfsFailed(e.to_string()))?;

    let total = stat.blocks() as u64 * stat.block_size() as u64;
    Ok(total)
}

/// Format bytes as human-readable string
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.1}TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

/// Get a disk usage summary string
pub fn disk_usage_summary(path: &Path) -> Result<String, DiskError> {
    let total = get_total_bytes(path)?;
    let available = get_available_bytes(path)?;
    let used = total - available;
    let usage_percent = get_disk_usage(path)?;

    Ok(format!(
        "{} / {} ({}% used, {} available)",
        format_bytes(used),
        format_bytes(total),
        usage_percent,
        format_bytes(available)
    ))
}

#[derive(Debug, thiserror::Error)]
pub enum DiskError {
    #[error("Failed to get filesystem stats: {0}")]
    StatvfsFailed(String),
    #[error("Invalid filesystem")]
    InvalidFilesystem,
    #[error("IO error: {0}")]
    IoError(String),
    #[error("No recording files to delete")]
    NoFilesToDelete,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500B");
        assert_eq!(format_bytes(1024), "1.0KB");
        assert_eq!(format_bytes(1536), "1.5KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0GB");
    }

    #[test]
    fn test_disk_usage() {
        // This will only work on Unix systems
        let path = Path::new("/tmp");
        if path.exists() {
            let usage = get_disk_usage(path);
            assert!(usage.is_ok());
            let usage = usage.unwrap();
            assert!(usage <= 100);
        }
    }
}
