pub mod config;
pub mod format;
pub mod fstab;
pub mod monitor;
pub mod mount;

pub use config::{ConfigError, MountInfo, StorageConfig};
pub use format::{detect_filesystem, format_ext4, get_uuid, is_mounted, unmount_device_and_partitions, FilesystemInfo, FormatError};
pub use fstab::{add_entry, entry_exists, remove_entry, FstabEntry, FstabError};
pub use monitor::{check_device_available, watch_device, DeviceMonitor, MonitorError, StorageEvent};
pub use mount::{create_mountpoint, mount_device, unmount_device, MountError};

use dialoguer::{theme::ColorfulTheme, Confirm, Select};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SetupError {
    #[error("Config error: {0}")]
    Config(#[from] ConfigError),
    #[error("Format error: {0}")]
    Format(#[from] FormatError),
    #[error("Mount error: {0}")]
    Mount(#[from] MountError),
    #[error("Fstab error: {0}")]
    Fstab(#[from] FstabError),
    #[error("Monitor error: {0}")]
    Monitor(#[from] MonitorError),
    #[error("Device is already mounted at {0}")]
    AlreadyMounted(String),
    #[error("User cancelled operation")]
    Cancelled,
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    #[error("Interactive prompt failed: {0}")]
    InteractiveFailed(String),
}

pub struct StorageManager {
    config_path: PathBuf,
    mountpoint: PathBuf,
}

impl StorageManager {
    pub fn new(config_path: &Path, mountpoint: &Path) -> Self {
        Self {
            config_path: config_path.to_path_buf(),
            mountpoint: mountpoint.to_path_buf(),
        }
    }

    pub fn setup(&self, dry_run: bool, skip_confirm: bool) -> Result<(), SetupError> {
        // Read config
        let mut config = StorageConfig::read_from_file(&self.config_path)?;
        let device = &config.device;

        println!("\nReading config from {}...", self.config_path.display());
        println!("  Device: {}", device);
        println!("  Size:   {}", config.size);
        if let Some(model) = &config.model {
            println!("  Model:  {}", model);
        }

        // Check if device exists
        if !Path::new(device).exists() {
            return Err(SetupError::DeviceNotFound(device.clone()));
        }

        // Check if already mounted
        if let Some(mp) = format::get_mountpoint(device)? {
            if mp == self.mountpoint.to_string_lossy() {
                println!("\nDevice is already mounted at {}", mp);
                return Ok(());
            }
            return Err(SetupError::AlreadyMounted(mp));
        }

        // Detect filesystem
        println!("\nChecking device status...");
        let fs_info = detect_filesystem(device, dry_run)?;

        let uuid = if fs_info.has_filesystem() {
            println!("  Filesystem: {}", fs_info.fstype.as_deref().unwrap_or("unknown"));
            if let Some(usage) = fs_info.usage_string() {
                println!("  Used: {}", usage);
            }

            if fs_info.is_ext4() {
                // Device has ext4 - offer to use as-is or format
                println!("  Device contains existing data!");

                if !skip_confirm {
                    let options = vec![
                        "Use existing filesystem (recommended)",
                        "Format and erase all data",
                    ];

                    let selection = Select::with_theme(&ColorfulTheme::default())
                        .with_prompt("What would you like to do?")
                        .items(&options)
                        .default(0)
                        .interact()
                        .map_err(|e| SetupError::InteractiveFailed(e.to_string()))?;

                    if selection == 0 {
                        // Use existing filesystem
                        println!("\nUsing existing ext4 filesystem...");
                        fs_info.uuid.clone().ok_or(SetupError::Format(FormatError::DetectionFailed))?
                    } else {
                        // Format
                        self.do_format(device, dry_run, skip_confirm)?
                    }
                } else {
                    // Skip confirm - use existing
                    fs_info.uuid.clone().ok_or(SetupError::Format(FormatError::DetectionFailed))?
                }
            } else {
                // Non-ext4 filesystem
                println!("  Filesystem type {} is not supported", fs_info.fstype.as_deref().unwrap_or("unknown"));

                if !skip_confirm {
                    let confirmed = Confirm::with_theme(&ColorfulTheme::default())
                        .with_prompt("Format device as ext4? ALL DATA WILL BE LOST!")
                        .default(false)
                        .interact()
                        .map_err(|e| SetupError::InteractiveFailed(e.to_string()))?;

                    if !confirmed {
                        return Err(SetupError::Cancelled);
                    }
                }

                self.do_format(device, dry_run, skip_confirm)?
            }
        } else {
            // No filesystem - format
            println!("  Device has no filesystem");
            self.do_format(device, dry_run, skip_confirm)?
        };

        // Create mountpoint
        println!("\nCreating mountpoint...");
        create_mountpoint(&self.mountpoint, dry_run)?;

        // Mount device
        println!("Mounting device...");
        mount_device(device, &self.mountpoint, dry_run)?;

        // Add to fstab
        println!("Adding to fstab...");
        let entry = FstabEntry::new(&uuid, &self.mountpoint.to_string_lossy());

        if !dry_run && entry_exists(&uuid)? {
            println!("  Entry already exists in fstab");
        } else {
            add_entry(&entry, dry_run)?;
        }

        // Update config with mount info
        config.mount = Some(MountInfo {
            mountpoint: self.mountpoint.to_string_lossy().to_string(),
            uuid: uuid.clone(),
            mounted_at: chrono::Utc::now().to_rfc3339(),
            in_fstab: true,
        });

        if !dry_run {
            config.write_to_file(&self.config_path)?;
        } else {
            println!("[DRY-RUN] Would update config with mount info");
        }

        println!("\nSetup complete!");
        println!("  Mountpoint: {}", self.mountpoint.display());
        println!("  UUID: {}", uuid);

        Ok(())
    }

    fn do_format(&self, device: &str, dry_run: bool, skip_confirm: bool) -> Result<String, SetupError> {
        if !skip_confirm && !dry_run {
            println!("\nThis will FORMAT {} as ext4. ALL DATA WILL BE LOST!", device);
            let confirmed = Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Type 'yes' to continue")
                .default(false)
                .interact()
                .map_err(|e| SetupError::InteractiveFailed(e.to_string()))?;

            if !confirmed {
                return Err(SetupError::Cancelled);
            }
        }

        // Unmount device and any partitions before formatting
        println!("\nUnmounting device and partitions...");
        let unmounted = unmount_device_and_partitions(device, dry_run)?;
        if !unmounted.is_empty() {
            for u in &unmounted {
                println!("  Unmounted: {}", u);
            }
        } else {
            println!("  No mounted partitions found");
        }

        println!("\nFormatting device...");
        let uuid = format_ext4(device, "recordings", dry_run)?;
        Ok(uuid)
    }

    pub fn is_available(&self) -> bool {
        let config = match StorageConfig::read_from_file(&self.config_path) {
            Ok(c) => c,
            Err(_) => return false,
        };

        if let Some(mount_info) = &config.mount {
            check_device_available(&mount_info.uuid)
        } else {
            false
        }
    }

    pub fn recordings_path(&self) -> Option<PathBuf> {
        if self.mountpoint.exists() && mount::is_mountpoint_in_use(&self.mountpoint).unwrap_or(false) {
            Some(self.mountpoint.clone())
        } else {
            None
        }
    }

    pub fn monitor(&self) -> Result<Receiver<StorageEvent>, SetupError> {
        let config = StorageConfig::read_from_file(&self.config_path)?;
        let mount_info = config.mount.ok_or(SetupError::Config(ConfigError::ReadFailed(
            std::io::Error::new(std::io::ErrorKind::NotFound, "No mount info in config"),
        )))?;

        Ok(watch_device(&mount_info.uuid)?)
    }

    pub fn status(&self) -> Result<StorageStatus, SetupError> {
        let config = StorageConfig::read_from_file(&self.config_path)?;
        let device = &config.device;

        let mounted = format::get_mountpoint(device)?.is_some();
        let available = if let Some(mount_info) = &config.mount {
            check_device_available(&mount_info.uuid)
        } else {
            Path::new(device).exists()
        };

        Ok(StorageStatus {
            device: device.clone(),
            size: config.size.clone(),
            model: config.model.clone(),
            mounted,
            available,
            mount_info: config.mount,
        })
    }
}

#[derive(Debug)]
pub struct StorageStatus {
    pub device: String,
    pub size: String,
    pub model: Option<String>,
    pub mounted: bool,
    pub available: bool,
    pub mount_info: Option<MountInfo>,
}

impl StorageStatus {
    pub fn print(&self) {
        println!("Storage Status:");
        println!("  Device:    {}", self.device);
        println!("  Size:      {}", self.size);
        if let Some(model) = &self.model {
            println!("  Model:     {}", model);
        }
        println!(
            "  Available: {}",
            if self.available { "yes" } else { "no" }
        );
        println!(
            "  Mounted:   {}",
            if self.mounted { "yes" } else { "no" }
        );
        if let Some(mount_info) = &self.mount_info {
            println!("  Mountpoint: {}", mount_info.mountpoint);
            println!("  UUID:       {}", mount_info.uuid);
            println!(
                "  In fstab:   {}",
                if mount_info.in_fstab { "yes" } else { "no" }
            );
        }
    }
}
