pub mod config;
pub mod lsblk;

pub use config::{ConfigError, StorageConfig};
pub use lsblk::{filter_selectable_devices, list_block_devices, BlockDevice, LsblkError, SelectableDevice};

use dialoguer::{theme::ColorfulTheme, Select};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SelectorError {
    #[error("Failed to list devices: {0}")]
    ListFailed(#[from] LsblkError),
    #[error("Failed to write config: {0}")]
    ConfigFailed(#[from] ConfigError),
    #[error("No devices available for selection")]
    NoDevices,
    #[error("User cancelled selection")]
    Cancelled,
    #[error("Interactive selection failed: {0}")]
    InteractiveFailed(String),
}

pub fn list_devices() -> Result<Vec<BlockDevice>, SelectorError> {
    Ok(list_block_devices()?)
}

pub fn select_device_interactive() -> Result<StorageConfig, SelectorError> {
    let devices = list_block_devices()?;
    let selectable = filter_selectable_devices(&devices);

    if selectable.is_empty() {
        return Err(SelectorError::NoDevices);
    }

    let items: Vec<String> = selectable.iter().map(|s| s.display_line()).collect();

    println!("\nWhere would you like to record to?\n");
    println!(
        "  {:<15} {:>4}   {:>10}   {:<24} MOUNT",
        "DEVICE", "TYPE", "SIZE", "MODEL"
    );
    println!();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .items(&items)
        .default(0)
        .interact_opt()
        .map_err(|e| SelectorError::InteractiveFailed(e.to_string()))?;

    match selection {
        Some(idx) => {
            let selected = &selectable[idx];
            Ok(StorageConfig::from_selection(selected))
        }
        None => Err(SelectorError::Cancelled),
    }
}

pub fn select_first_unmounted() -> Result<StorageConfig, SelectorError> {
    let devices = list_block_devices()?;
    let selectable = filter_selectable_devices(&devices);

    for s in &selectable {
        if !s.device.is_mounted() && s.device.is_disk() {
            return Ok(StorageConfig::from_selection(s));
        }
    }

    for s in &selectable {
        if !s.device.is_mounted() {
            return Ok(StorageConfig::from_selection(s));
        }
    }

    Err(SelectorError::NoDevices)
}

pub fn write_config(config: &StorageConfig, path: &Path) -> Result<(), SelectorError> {
    config.write_to_file(path)?;
    Ok(())
}

pub fn write_config_json(config: &StorageConfig, path: &Path) -> Result<(), SelectorError> {
    config.write_json_to_file(path)?;
    Ok(())
}
