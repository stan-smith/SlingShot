#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

const STORAGE_CONFIG_PATH: &str = "/etc/rtsp-remote/storage.toml";
const DEFAULT_MOUNTPOINT: &str = "/media/recordings";

#[derive(Debug)]
pub struct StorageConfig {
    pub device: String,
    pub mountpoint: PathBuf,
    pub uuid: Option<String>,
    pub available: bool,
}

pub struct Storage {
    config_path: PathBuf,
    mountpoint: PathBuf,
}

impl Storage {
    pub fn new() -> Self {
        Self {
            config_path: PathBuf::from(STORAGE_CONFIG_PATH),
            mountpoint: PathBuf::from(DEFAULT_MOUNTPOINT),
        }
    }

    pub fn with_paths(config_path: &Path, mountpoint: &Path) -> Self {
        Self {
            config_path: config_path.to_path_buf(),
            mountpoint: mountpoint.to_path_buf(),
        }
    }

    /// Check if storage is already configured
    pub fn is_configured(&self) -> bool {
        self.config_path.exists()
    }

    /// Check if storage is currently mounted and available
    pub fn is_available(&self) -> bool {
        if !self.mountpoint.exists() {
            return false;
        }

        // Check if mountpoint is actually mounted
        let output = Command::new("findmnt")
            .arg("-n")
            .arg("-o")
            .arg("SOURCE")
            .arg(&self.mountpoint)
            .output();

        match output {
            Ok(o) => o.status.success() && !o.stdout.is_empty(),
            Err(_) => false,
        }
    }

    /// Get the recordings directory path
    pub fn recordings_path(&self) -> Option<PathBuf> {
        if self.is_available() {
            Some(self.mountpoint.clone())
        } else {
            None
        }
    }

    /// Run interactive storage setup (select device, format, mount)
    /// Returns Ok(true) if setup completed, Ok(false) if skipped
    pub fn setup_interactive(&self) -> Result<bool, String> {
        println!("\n========================================");
        println!("STORAGE SETUP");
        println!("========================================\n");

        if self.is_configured() && self.is_available() {
            println!("Storage already configured and available at {}", self.mountpoint.display());
            return Ok(true);
        }

        // Ensure config directory exists
        if let Some(parent) = self.config_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create config directory: {}", e))?;
            }
        }

        // Step 1: Run storage-selector
        println!("Select a storage device for recordings...\n");

        let selector_result = Command::new("storage-selector")
            .arg("-o")
            .arg(&self.config_path)
            .status();

        match selector_result {
            Ok(status) if status.success() => {
                println!("\nDevice selected.");
            }
            Ok(status) => {
                return Err(format!("Storage selection failed with exit code: {:?}", status.code()));
            }
            Err(e) => {
                return Err(format!("Failed to run storage-selector: {}. Is it installed?", e));
            }
        }

        // Step 2: Run storage-mount setup
        println!("\nSetting up storage mount...\n");

        let mount_result = Command::new("storage-mount")
            .arg("-c")
            .arg(&self.config_path)
            .arg("-m")
            .arg(&self.mountpoint)
            .arg("setup")
            .status();

        match mount_result {
            Ok(status) if status.success() => {
                println!("\nStorage setup complete!");
                println!("Recordings will be saved to: {}", self.mountpoint.display());
                Ok(true)
            }
            Ok(status) => {
                Err(format!("Storage mount failed with exit code: {:?}", status.code()))
            }
            Err(e) => {
                Err(format!("Failed to run storage-mount: {}. Is it installed?", e))
            }
        }
    }

    /// Run non-interactive setup (for automation)
    pub fn setup_auto(&self) -> Result<bool, String> {
        if self.is_configured() && self.is_available() {
            return Ok(true);
        }

        // Ensure config directory exists
        if let Some(parent) = self.config_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create config directory: {}", e))?;
            }
        }

        // Auto-select first unmounted disk
        let selector_result = Command::new("storage-selector")
            .arg("--non-interactive")
            .arg("--yes")
            .arg("-o")
            .arg(&self.config_path)
            .status();

        if !selector_result.map(|s| s.success()).unwrap_or(false) {
            return Err("Failed to auto-select storage device".to_string());
        }

        // Auto-mount with --yes to skip prompts
        let mount_result = Command::new("storage-mount")
            .arg("-c")
            .arg(&self.config_path)
            .arg("-m")
            .arg(&self.mountpoint)
            .arg("--yes")
            .arg("setup")
            .status();

        match mount_result {
            Ok(status) if status.success() => Ok(true),
            _ => Err("Failed to setup storage mount".to_string()),
        }
    }

    /// Get current storage status
    pub fn status(&self) -> StorageConfig {
        let device = self.read_device_from_config().unwrap_or_default();
        let uuid = self.read_uuid_from_config();

        StorageConfig {
            device,
            mountpoint: self.mountpoint.clone(),
            uuid,
            available: self.is_available(),
        }
    }

    fn read_device_from_config(&self) -> Option<String> {
        let content = std::fs::read_to_string(&self.config_path).ok()?;
        for line in content.lines() {
            if line.starts_with("device = ") {
                return Some(line.trim_start_matches("device = ").trim_matches('"').to_string());
            }
        }
        None
    }

    fn read_uuid_from_config(&self) -> Option<String> {
        let content = std::fs::read_to_string(&self.config_path).ok()?;
        for line in content.lines() {
            if line.starts_with("uuid = ") {
                return Some(line.trim_start_matches("uuid = ").trim_matches('"').to_string());
            }
        }
        None
    }
}

impl Default for Storage {
    fn default() -> Self {
        Self::new()
    }
}

/// Print storage status
pub fn print_status(storage: &Storage) {
    let status = storage.status();
    println!("Storage Status:");
    println!("  Device:     {}", if status.device.is_empty() { "not configured" } else { &status.device });
    println!("  Mountpoint: {}", status.mountpoint.display());
    println!("  Available:  {}", if status.available { "yes" } else { "no" });
    if let Some(uuid) = &status.uuid {
        println!("  UUID:       {}", uuid);
    }
}
