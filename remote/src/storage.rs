#![allow(dead_code)]

use config_manager::StorageConfig as CfgStorageConfig;
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_MOUNTPOINT: &str = "/media/recordings";

#[derive(Debug)]
pub struct StorageStatus {
    pub device: String,
    pub mountpoint: PathBuf,
    pub uuid: Option<String>,
    pub available: bool,
}

pub struct Storage {
    mountpoint: PathBuf,
    device: Option<String>,
    uuid: Option<String>,
}

impl Storage {
    pub fn new() -> Self {
        Self {
            mountpoint: PathBuf::from(DEFAULT_MOUNTPOINT),
            device: None,
            uuid: None,
        }
    }

    /// Create storage from config-manager StorageConfig
    pub fn with_paths_from_config(config: &CfgStorageConfig) -> Self {
        Self {
            mountpoint: config.mountpoint.clone(),
            device: if config.device.is_empty() {
                None
            } else {
                Some(config.device.clone())
            },
            uuid: if config.uuid.is_empty() {
                None
            } else {
                Some(config.uuid.clone())
            },
        }
    }

    pub fn with_paths(_config_path: &Path, mountpoint: &Path) -> Self {
        Self {
            mountpoint: mountpoint.to_path_buf(),
            device: None,
            uuid: None,
        }
    }

    /// Check if storage is already configured
    pub fn is_configured(&self) -> bool {
        self.device.is_some()
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
    /// Returns Ok(Some(config)) if setup completed with new config, Ok(None) if skipped
    pub fn setup_interactive(&self) -> Result<Option<CfgStorageConfig>, String> {
        println!("\n========================================");
        println!("STORAGE SETUP");
        println!("========================================\n");

        if self.is_configured() && self.is_available() {
            println!(
                "Storage already configured and available at {}",
                self.mountpoint.display()
            );
            return Ok(Some(CfgStorageConfig::new(
                self.device.clone().unwrap_or_default(),
                self.uuid.clone().unwrap_or_default(),
                self.mountpoint.clone(),
            )));
        }

        // For now, just check if the mountpoint is available
        // The storage-selector/storage-mount tools are archived
        if self.mountpoint.exists() && self.is_available() {
            println!("Storage available at {}", self.mountpoint.display());
            return Ok(Some(CfgStorageConfig::new(
                String::new(),
                String::new(),
                self.mountpoint.clone(),
            )));
        }

        println!("Storage setup requires manual configuration.");
        println!("Please ensure {} is mounted and try again.", self.mountpoint.display());
        Ok(None)
    }

    /// Run non-interactive setup (for automation)
    pub fn setup_auto(&self) -> Result<Option<CfgStorageConfig>, String> {
        if self.is_configured() && self.is_available() {
            return Ok(Some(CfgStorageConfig::new(
                self.device.clone().unwrap_or_default(),
                self.uuid.clone().unwrap_or_default(),
                self.mountpoint.clone(),
            )));
        }

        if self.mountpoint.exists() && self.is_available() {
            return Ok(Some(CfgStorageConfig::new(
                String::new(),
                String::new(),
                self.mountpoint.clone(),
            )));
        }

        Err("Storage not available".to_string())
    }

    /// Get current storage status
    pub fn status(&self) -> StorageStatus {
        StorageStatus {
            device: self.device.clone().unwrap_or_default(),
            mountpoint: self.mountpoint.clone(),
            uuid: self.uuid.clone(),
            available: self.is_available(),
        }
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
    println!(
        "  Device:     {}",
        if status.device.is_empty() {
            "not configured"
        } else {
            &status.device
        }
    );
    println!("  Mountpoint: {}", status.mountpoint.display());
    println!(
        "  Available:  {}",
        if status.available { "yes" } else { "no" }
    );
    if let Some(ref uuid) = status.uuid {
        println!("  UUID:       {}", uuid);
    }
}
