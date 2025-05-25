use anyhow::Result;
use config_manager::{
    OnvifConfig, RecordingConfig, RemoteConfig, RtspConfig, SourceConfig, StorageConfig,
};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password, Select};
use onvif_client::OnvifClient;
use std::path::PathBuf;

/// Run the full configuration wizard
pub fn run_wizard() -> Result<()> {
    println!();
    println!("--- Node Configuration ---");
    println!();

    // Load existing config if available for defaults
    let existing = RemoteConfig::load().ok();

    // Node name
    let node_name: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Node name")
        .default(existing.as_ref().map(|c| c.node_name.clone()).unwrap_or_default())
        .interact_text()?;

    // Central address
    let central_address: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Central node address (ip:port)")
        .default(
            existing
                .as_ref()
                .map(|c| c.central_address.clone())
                .unwrap_or_default(),
        )
        .validate_with(|input: &String| -> Result<(), &str> {
            if input.parse::<std::net::SocketAddr>().is_ok() {
                Ok(())
            } else {
                Err("Invalid address format. Use ip:port (e.g., 192.168.1.100:5001)")
            }
        })
        .interact_text()?;

    println!();
    println!("--- Video Source ---");
    println!();

    // Source type selection
    let source_options = vec!["ONVIF camera (recommended)", "Direct RTSP URL"];
    let default_source = match existing.as_ref().map(|c| &c.source) {
        Some(SourceConfig::Onvif(_)) => 0,
        Some(SourceConfig::Rtsp(_)) => 1,
        None => 0,
    };

    let source_type = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select video source type")
        .items(&source_options)
        .default(default_source)
        .interact()?;

    let source = match source_type {
        0 => configure_onvif(&existing)?,
        1 => configure_rtsp(&existing)?,
        _ => unreachable!(),
    };

    println!();
    println!("--- Local Recording ---");
    println!();

    let recording = configure_recording(&existing)?;
    let storage = configure_storage(&existing)?;

    println!();
    println!("--- Security ---");
    println!();

    let encryption_enabled = configure_encryption(&existing)?;

    // Build config
    let config = RemoteConfig {
        node_name: node_name.clone(),
        central_address: central_address.clone(),
        source,
        recording,
        storage,
        encryption_enabled,
    };

    // Show summary
    println!();
    println!("--- Summary ---");
    println!();
    print_config_summary(&config);

    // Confirm save
    println!();
    let save = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Save configuration?")
        .default(true)
        .interact()?;

    if save {
        config.save()?;
        let path = RemoteConfig::default_path()?;
        println!();
        println!("Configuration saved to {}", path.display());
    } else {
        println!("Configuration not saved.");
    }

    Ok(())
}

fn configure_onvif(existing: &Option<RemoteConfig>) -> Result<SourceConfig> {
    // Get existing ONVIF config for defaults
    let existing_onvif = existing.as_ref().and_then(|c| match &c.source {
        SourceConfig::Onvif(o) => Some(o),
        _ => None,
    });

    let ip: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Camera IP address")
        .default(existing_onvif.map(|o| o.ip.clone()).unwrap_or_default())
        .interact_text()?;

    let username: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Camera username")
        .default(existing_onvif.map(|o| o.username.clone()).unwrap_or_default())
        .interact_text()?;

    let password: String = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Camera password")
        .interact()?;

    // Test connection and enumerate profiles
    println!();
    println!("Connecting to camera at {}...", ip);

    let client = OnvifClient::new(&ip, &username, &password);

    match client.get_device_info() {
        Ok(info) => println!("Camera: {}", info),
        Err(e) => {
            println!("Warning: Could not get device info: {}", e);
        }
    }

    // Get available profiles
    let profiles = match client.get_profiles() {
        Ok(p) => p,
        Err(e) => {
            println!("Warning: Could not enumerate profiles: {}", e);
            println!("Continuing without profile selection.");
            return Ok(SourceConfig::Onvif(OnvifConfig::new(ip, username, &password)));
        }
    };

    if profiles.is_empty() {
        println!("No profiles found, using default.");
        return Ok(SourceConfig::Onvif(OnvifConfig::new(ip, username, &password)));
    }

    // Let user select profile
    println!();
    let profile_strings: Vec<String> = profiles.iter().map(|p| format!("{}", p)).collect();

    let selected = if profiles.len() == 1 {
        println!("Using profile: {}", profiles[0]);
        0
    } else {
        Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select camera profile")
            .items(&profile_strings)
            .default(0)
            .interact()?
    };

    let selected_token = profiles[selected].token.clone();
    println!("Selected profile: {}", profiles[selected]);

    // Create config with profile token
    let onvif_config = OnvifConfig::with_profile(ip, username, &password, selected_token);

    Ok(SourceConfig::Onvif(onvif_config))
}

fn configure_rtsp(existing: &Option<RemoteConfig>) -> Result<SourceConfig> {
    let existing_url = existing.as_ref().and_then(|c| match &c.source {
        SourceConfig::Rtsp(r) => r.url().ok(),
        _ => None,
    });

    let url: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("RTSP URL (with credentials if needed)")
        .default(existing_url.unwrap_or_default())
        .validate_with(|input: &String| -> Result<(), &str> {
            if input.starts_with("rtsp://") {
                Ok(())
            } else {
                Err("URL must start with rtsp://")
            }
        })
        .interact_text()?;

    Ok(SourceConfig::Rtsp(RtspConfig::new(&url)))
}

fn configure_recording(existing: &Option<RemoteConfig>) -> Result<RecordingConfig> {
    let existing_recording = existing.as_ref().map(|c| &c.recording);

    let enabled = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable local recording?")
        .default(existing_recording.map(|r| r.enabled).unwrap_or(false))
        .interact()?;

    if !enabled {
        return Ok(RecordingConfig {
            enabled: false,
            disk_reserve_percent: 90,
        });
    }

    let disk_reserve: u8 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Disk reserve % (stop recording when disk is X% full)")
        .default(existing_recording.map(|r| r.disk_reserve_percent).unwrap_or(90))
        .validate_with(|input: &u8| -> Result<(), &str> {
            if *input <= 100 {
                Ok(())
            } else {
                Err("Must be between 0 and 100")
            }
        })
        .interact_text()?;

    Ok(RecordingConfig {
        enabled: true,
        disk_reserve_percent: disk_reserve,
    })
}

fn configure_storage(existing: &Option<RemoteConfig>) -> Result<StorageConfig> {
    let existing_storage = existing.as_ref().map(|c| &c.storage);
    let default_path = existing_storage
        .map(|s| s.mountpoint.to_string_lossy().to_string())
        .unwrap_or_else(|| "/media/recordings".to_string());

    let mountpoint: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Storage mountpoint for recordings")
        .default(default_path)
        .interact_text()?;

    Ok(StorageConfig::new(
        String::new(),
        String::new(),
        PathBuf::from(mountpoint),
    ))
}

fn configure_encryption(existing: &Option<RemoteConfig>) -> Result<bool> {
    let existing_enabled = existing.as_ref().map(|c| c.encryption_enabled).unwrap_or(false);

    println!("Encryption protects recordings with a key from the central server.");
    println!("Only the central server can decrypt the footage.");
    println!();

    let enabled = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable encryption for recordings?")
        .default(existing_enabled)
        .interact()?;

    Ok(enabled)
}

fn print_config_summary(config: &RemoteConfig) {
    println!("Node name:       {}", config.node_name);
    println!("Central address: {}", config.central_address);

    match &config.source {
        SourceConfig::Rtsp(rtsp) => {
            if let Ok(url) = rtsp.url() {
                // Mask password in URL for display
                let display_url = mask_rtsp_password(&url);
                println!("Source:          RTSP - {}", display_url);
            } else {
                println!("Source:          RTSP (configured)");
            }
        }
        SourceConfig::Onvif(onvif) => {
            println!("Source:          ONVIF camera at {}", onvif.ip);
            println!("Camera user:     {}", onvif.username);
        }
    }

    println!(
        "Recording:       {}",
        if config.recording.enabled {
            format!("enabled ({}% reserve)", config.recording.disk_reserve_percent)
        } else {
            "disabled".to_string()
        }
    );
    println!("Storage:         {}", config.storage.mountpoint.display());
    println!(
        "Encryption:      {}",
        if config.encryption_enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
}

fn mask_rtsp_password(url: &str) -> String {
    // Simple password masking for rtsp://user:pass@host/path
    if let Some(at_pos) = url.find('@') {
        if let Some(colon_pos) = url[7..at_pos].find(':') {
            let prefix = &url[..7 + colon_pos + 1];
            let suffix = &url[at_pos..];
            return format!("{}********{}", prefix, suffix);
        }
    }
    url.to_string()
}
