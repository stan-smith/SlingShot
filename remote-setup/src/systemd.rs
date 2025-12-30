use anyhow::{bail, Result};
use config_manager::RemoteConfig;
use dialoguer::{theme::ColorfulTheme, Confirm, Input};
use std::fs;
use std::process::Command;

const SERVICE_NAME: &str = "slingshot-remote";
const SERVICE_FILE: &str = "/etc/systemd/system/slingshot-remote.service";
const INSTALL_PATH: &str = "/usr/local/bin/slingshot-remote";

/// Get current service status as a human-readable string
pub fn get_service_status() -> String {
    let output = Command::new("systemctl")
        .args(["is-active", SERVICE_NAME])
        .output();

    match output {
        Ok(o) => {
            let status = String::from_utf8_lossy(&o.stdout).trim().to_string();
            match status.as_str() {
                "active" => "running".to_string(),
                "inactive" => "stopped".to_string(),
                "failed" => "failed".to_string(),
                _ => {
                    // Check if service file exists
                    if std::path::Path::new(SERVICE_FILE).exists() {
                        format!("installed ({})", status)
                    } else {
                        "not installed".to_string()
                    }
                }
            }
        }
        Err(_) => "unknown (systemctl not available)".to_string(),
    }
}

/// Install the systemd service
pub fn install_service() -> Result<()> {
    // Check for config
    if !RemoteConfig::exists() {
        bail!("No configuration found. Please run configuration wizard first.");
    }

    let config = RemoteConfig::load()?;

    println!("~ Systemd Service Installation ~");
    println!();

    // Get current user info
    let current_user = users::get_current_username()
        .map(|u| u.to_string_lossy().to_string())
        .unwrap_or_else(|| "root".to_string());

    let _current_uid = users::get_current_uid();
    let home_dir = std::env::var("HOME").unwrap_or_else(|_| format!("/home/{}", current_user));

    // Ask for service user
    let service_user: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Run service as user")
        .default(current_user.clone())
        .interact_text()?;

    // Check if we need to copy the binary
    let binary_source = find_remote_binary()?;
    println!("Found remote binary at: {}", binary_source);

    let needs_copy = binary_source != INSTALL_PATH;
    if needs_copy {
        println!("Will install to: {}", INSTALL_PATH);
    }

    // Generate service file
    let service_content = generate_service_file(&config, &service_user, &home_dir);

    println!();
    println!("Service configuration:");
    println!("  User: {}", service_user);
    println!("  Binary: {}", INSTALL_PATH);
    println!("  Config: ~/.config/slingshot/remote.toml");
    println!();

    let proceed = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Install service? (requires sudo)")
        .default(true)
        .interact()?;

    if !proceed {
        println!("Installation cancelled.");
        return Ok(());
    }

    // Copy binary if needed
    if needs_copy {
        println!("Copying binary to {}...", INSTALL_PATH);
        let status = Command::new("sudo")
            .args(["cp", &binary_source, INSTALL_PATH])
            .status()?;

        if !status.success() {
            bail!("Failed to copy binary");
        }

        // Make executable
        let status = Command::new("sudo")
            .args(["chmod", "+x", INSTALL_PATH])
            .status()?;

        if !status.success() {
            bail!("Failed to set binary permissions");
        }
    }

    // Write service file
    println!("Installing service file...");

    // Write to temp file first, then sudo mv
    let temp_file = "/tmp/slingshot-remote.service";
    fs::write(temp_file, &service_content)?;

    let status = Command::new("sudo")
        .args(["mv", temp_file, SERVICE_FILE])
        .status()?;

    if !status.success() {
        bail!("Failed to install service file");
    }

    // Set permissions
    let status = Command::new("sudo")
        .args(["chmod", "644", SERVICE_FILE])
        .status()?;

    if !status.success() {
        bail!("Failed to set service file permissions");
    }

    // Reload systemd
    println!("Reloading systemd...");
    let status = Command::new("sudo")
        .args(["systemctl", "daemon-reload"])
        .status()?;

    if !status.success() {
        bail!("Failed to reload systemd");
    }

    // Ask to enable on boot
    let enable_boot = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable service to start on boot?")
        .default(true)
        .interact()?;

    if enable_boot {
        let status = Command::new("sudo")
            .args(["systemctl", "enable", SERVICE_NAME])
            .status()?;

        if !status.success() {
            eprintln!("Warning: Failed to enable service on boot");
        } else {
            println!("Service enabled for boot.");
        }
    }

    // Ask to start now
    let start_now = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Start service now?")
        .default(true)
        .interact()?;

    if start_now {
        let status = Command::new("sudo")
            .args(["systemctl", "start", SERVICE_NAME])
            .status()?;

        if !status.success() {
            eprintln!("Warning: Failed to start service");
        } else {
            println!("Service started.");
        }
    }

    println!();
    println!("Installation complete!");
    println!();
    println!("Useful commands:");
    println!("  sudo systemctl status {}   - Check status", SERVICE_NAME);
    println!("  sudo systemctl stop {}     - Stop service", SERVICE_NAME);
    println!("  sudo systemctl start {}    - Start service", SERVICE_NAME);
    println!("  sudo journalctl -u {} -f   - View logs", SERVICE_NAME);

    Ok(())
}

/// Uninstall the systemd service
pub fn uninstall_service() -> Result<()> {
    println!("~ Systemd Service Uninstall ~");
    println!();

    if !std::path::Path::new(SERVICE_FILE).exists() {
        println!("Service is not installed.");
        return Ok(());
    }

    let proceed = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Uninstall slingshot-remote service?")
        .default(false)
        .interact()?;

    if !proceed {
        println!("Uninstall cancelled.");
        return Ok(());
    }

    // Stop service if running
    println!("Stopping service...");
    let _ = Command::new("sudo")
        .args(["systemctl", "stop", SERVICE_NAME])
        .status();

    // Disable service
    println!("Disabling service...");
    let _ = Command::new("sudo")
        .args(["systemctl", "disable", SERVICE_NAME])
        .status();

    // Remove service file
    println!("Removing service file...");
    let status = Command::new("sudo")
        .args(["rm", SERVICE_FILE])
        .status()?;

    if !status.success() {
        bail!("Failed to remove service file");
    }

    // Reload systemd
    let status = Command::new("sudo")
        .args(["systemctl", "daemon-reload"])
        .status()?;

    if !status.success() {
        eprintln!("Warning: Failed to reload systemd");
    }

    // Ask about removing binary
    let remove_binary = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("Remove binary at {}?", INSTALL_PATH))
        .default(false)
        .interact()?;

    if remove_binary {
        let status = Command::new("sudo")
            .args(["rm", INSTALL_PATH])
            .status()?;

        if status.success() {
            println!("Binary removed.");
        } else {
            eprintln!("Warning: Failed to remove binary");
        }
    }

    println!();
    println!("Service uninstalled.");
    println!("Note: Configuration files in ~/.config/slingshot/ were not removed.");

    Ok(())
}

fn find_remote_binary() -> Result<String> {
    // Check common locations
    let candidates = [
        // Already installed
        INSTALL_PATH.to_string(),
        // Release build in current project
        format!(
            "{}/target/release/remote",
            std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string())
        ),
        // Relative to this binary
        {
            let exe = std::env::current_exe().ok();
            exe.and_then(|p| p.parent().map(|d| d.join("remote").to_string_lossy().to_string()))
                .unwrap_or_default()
        },
        // Common build location
        "./target/release/remote".to_string(),
        "../target/release/remote".to_string(),
        // Home directory builds
        format!(
            "{}/remote/target/release/remote",
            std::env::var("HOME").unwrap_or_default()
        ),
    ];

    for path in candidates {
        if !path.is_empty() && std::path::Path::new(&path).exists() {
            return Ok(path);
        }
    }

    bail!(
        "Could not find remote binary. Please build it first with:\n  cargo build --release -p remote"
    )
}

fn generate_service_file(config: &RemoteConfig, user: &str, home: &str) -> String {
    format!(
        r#"[Unit]
Description=Slingshot Remote Node - {node_name}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={user}
Group={user}
ExecStart={binary}
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
Environment="HOME={home}"

[Install]
WantedBy=multi-user.target
"#,
        node_name = config.node_name,
        user = user,
        binary = INSTALL_PATH,
        home = home,
    )
}
