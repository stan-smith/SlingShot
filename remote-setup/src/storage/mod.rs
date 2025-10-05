//! Storage device selection, formatting, and mounting functionality.
//!
//! This module provides interactive storage configuration for the remote-setup wizard,
//! including device enumeration, filesystem detection, formatting, and fstab management.

mod fstab;
mod format;
mod lsblk;
mod mount;

pub use fstab::{add_fstab_entry, entry_exists_in_fstab, FstabEntry};
pub use format::{detect_filesystem, format_ext4, unmount_device_and_partitions};
pub use lsblk::{filter_selectable_devices, list_block_devices, SelectableDevice};
pub use mount::{create_mountpoint, mount_device};

use anyhow::{bail, Result};
use config_manager::StorageConfig;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use std::path::PathBuf;

/// Configure storage interactively, with device selection, formatting, and mounting.
/// Falls back to manual path entry if device detection fails.
pub fn configure_storage_interactive(
    existing: &Option<config_manager::RemoteConfig>,
) -> Result<StorageConfig> {
    println!();
    println!("~ Storage Configuration ~");
    println!();
    println!("Detecting available storage devices...");

    // Try to list block devices
    match list_block_devices() {
        Ok(devices) => {
            let selectable = filter_selectable_devices(&devices);

            if selectable.is_empty() {
                println!("No suitable block devices found.");
                return configure_storage_manual(existing);
            }

            // Offer choice: select device or manual entry
            let options = vec!["Select from detected devices", "Enter path manually"];

            let choice = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Storage configuration method")
                .items(&options)
                .default(0)
                .interact()?;

            match choice {
                0 => configure_storage_device_selection(existing, &selectable),
                1 => configure_storage_manual(existing),
                _ => unreachable!(),
            }
        }
        Err(e) => {
            println!("Warning: Could not detect block devices: {}", e);
            println!("Falling back to manual configuration.");
            configure_storage_manual(existing)
        }
    }
}

/// Interactive device selection and setup flow
fn configure_storage_device_selection(
    existing: &Option<config_manager::RemoteConfig>,
    selectable: &[SelectableDevice],
) -> Result<StorageConfig> {
    // Display device selection header
    println!();
    println!("Available storage devices:");
    println!(
        "  {:<15} {:>4}   {:>10}   {:<24} MOUNT",
        "DEVICE", "TYPE", "SIZE", "MODEL"
    );
    println!();

    // Build selection items
    let items: Vec<String> = selectable.iter().map(|s| s.display_line()).collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select storage device")
        .items(&items)
        .default(0)
        .interact()?;

    let selected = &selectable[selection];
    let device_path = selected.device.device_path();

    println!();
    println!(
        "Selected: {} ({})",
        device_path,
        selected.device.size_str()
    );

    // Check filesystem
    let fs_info = detect_filesystem(&device_path)?;

    let uuid = if fs_info.has_filesystem() {
        println!(
            "Detected filesystem: {}",
            fs_info.fstype.as_deref().unwrap_or("unknown")
        );

        if fs_info.is_ext4() {
            // Offer to use existing or format
            let options = vec![
                "Use existing filesystem",
                "Format as ext4 (ERASES ALL DATA)",
            ];

            let choice = Select::with_theme(&ColorfulTheme::default())
                .with_prompt("This device has an ext4 filesystem")
                .items(&options)
                .default(0)
                .interact()?;

            if choice == 0 {
                fs_info.uuid.clone().unwrap_or_default()
            } else {
                do_format_flow(&device_path)?
            }
        } else {
            // Non-ext4 filesystem, must format
            println!(
                "Filesystem type {} is not supported for recordings.",
                fs_info.fstype.as_deref().unwrap_or("unknown")
            );

            let confirm = Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Format device as ext4? ALL DATA WILL BE LOST!")
                .default(false)
                .interact()?;

            if !confirm {
                bail!("Storage configuration cancelled");
            }

            do_format_flow(&device_path)?
        }
    } else {
        // No filesystem
        println!("Device has no filesystem.");

        let confirm = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Format device as ext4?")
            .default(true)
            .interact()?;

        if !confirm {
            bail!("Storage configuration cancelled");
        }

        do_format_flow(&device_path)?
    };

    // Configure mountpoint
    let default_mountpoint = existing
        .as_ref()
        .map(|c| c.storage.mountpoint.to_string_lossy().to_string())
        .unwrap_or_else(|| "/media/recordings".to_string());

    let mountpoint: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Mountpoint for recordings")
        .default(default_mountpoint)
        .interact_text()?;

    let mountpoint_path = PathBuf::from(&mountpoint);

    // Create mountpoint and mount
    println!();
    println!("Setting up mount...");
    create_mountpoint(&mountpoint_path)?;
    mount_device(&device_path, &mountpoint_path)?;

    println!("Device mounted at {}", mountpoint);

    // Offer fstab configuration
    let add_to_fstab = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Add to /etc/fstab for automatic mounting on boot?")
        .default(true)
        .interact()?;

    if add_to_fstab {
        if entry_exists_in_fstab(&uuid)? {
            println!("Entry already exists in fstab.");
        } else {
            let entry = FstabEntry::new(&uuid, &mountpoint);
            add_fstab_entry(&entry)?;
            println!("Added to /etc/fstab.");
        }
    }

    Ok(StorageConfig::new(device_path, uuid, mountpoint_path))
}

/// Format flow with unmount and confirmation
fn do_format_flow(device_path: &str) -> Result<String> {
    // Check for mounted partitions
    println!();
    println!("Checking for mounted partitions...");

    let unmounted = unmount_device_and_partitions(device_path)?;
    if !unmounted.is_empty() {
        println!("Unmounted:");
        for u in &unmounted {
            println!("  {}", u);
        }
    } else {
        println!("No mounted partitions found.");
    }

    // Final confirmation for format
    println!();
    println!("WARNING: This will ERASE ALL DATA on {}", device_path);

    let confirm = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Are you sure you want to format?")
        .default(false)
        .interact()?;

    if !confirm {
        bail!("Format cancelled");
    }

    println!("Formatting as ext4...");
    let uuid = format_ext4(device_path, "recordings")?;
    println!("Format complete. UUID: {}", uuid);

    Ok(uuid)
}

/// Manual storage configuration - just prompts for mountpoint path
fn configure_storage_manual(
    existing: &Option<config_manager::RemoteConfig>,
) -> Result<StorageConfig> {
    println!();
    println!("Manual storage configuration.");
    println!("Note: You are responsible for mounting the storage device.");
    println!();

    let existing_storage = existing.as_ref().map(|c| &c.storage);
    let default_path = existing_storage
        .map(|s| s.mountpoint.to_string_lossy().to_string())
        .unwrap_or_else(|| "/media/recordings".to_string());

    let mountpoint: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Storage mountpoint for recordings")
        .default(default_path)
        .interact_text()?;

    // For manual entry, device and UUID remain empty
    Ok(StorageConfig::new(
        String::new(),
        String::new(),
        PathBuf::from(mountpoint),
    ))
}
