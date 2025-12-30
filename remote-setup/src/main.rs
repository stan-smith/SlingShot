mod storage;
mod systemd;
mod wizard;

use anyhow::Result;
use clap::Parser;
use config_manager::RemoteConfig;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use fingerprint_store::FingerprintStore;
use qrcode::QrCode;

#[derive(Parser)]
#[command(name = "slingshot-remote-setup")]
#[command(about = "Interactive setup and installation tool for slingshot remote nodes")]
struct Cli {
    /// Run configuration wizard directly
    #[arg(long)]
    configure: bool,

    /// Install systemd service (requires existing config)
    #[arg(long)]
    install: bool,

    /// Uninstall systemd service
    #[arg(long)]
    uninstall: bool,

    /// Show current configuration and service status
    #[arg(long)]
    status: bool,

    /// Regenerate admin user credentials (TOTP)
    #[arg(long)]
    regenerate_admin: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle direct CLI commands
    if cli.configure {
        return wizard::run_wizard();
    }
    if cli.install {
        return systemd::install_service();
    }
    if cli.uninstall {
        return systemd::uninstall_service();
    }
    if cli.status {
        return show_status();
    }
    if cli.regenerate_admin {
        return regenerate_admin_credentials();
    }

    // No flags - show interactive menu
    run_menu()
}

fn run_menu() -> Result<()> {
    println!();
    println!("~ SLINGSHOT REMOTE NODE SETUP ~");
    println!();

    loop {
        let has_config = RemoteConfig::exists();
        let service_status = systemd::get_service_status();

        // Show current state
        if has_config {
            println!("Config: found at {}", RemoteConfig::default_path().unwrap_or_default().display());
        } else {
            println!("Config: not configured");
        }
        println!("Service: {}", service_status);
        println!();

        let options = vec![
            "Configure node settings",
            "Install/update systemd service",
            "Uninstall systemd service",
            "Show current configuration",
            "Regenerate admin credentials",
            "Exit",
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select an option")
            .items(&options)
            .default(0)
            .interact()?;

        println!();

        match selection {
            0 => {
                if let Err(e) = wizard::run_wizard() {
                    eprintln!("Configuration failed: {}", e);
                }
            }
            1 => {
                if !has_config {
                    println!("Error: No configuration found. Please configure first.");
                } else if let Err(e) = systemd::install_service() {
                    eprintln!("Installation failed: {}", e);
                }
            }
            2 => {
                if let Err(e) = systemd::uninstall_service() {
                    eprintln!("Uninstall failed: {}", e);
                }
            }
            3 => {
                if let Err(e) = show_status() {
                    eprintln!("Error: {}", e);
                }
            }
            4 => {
                if let Err(e) = regenerate_admin_credentials() {
                    eprintln!("Error: {}", e);
                }
            }
            5 => {
                println!("Goodbye!");
                break;
            }
            _ => unreachable!(),
        }

        println!();
    }

    Ok(())
}

fn show_status() -> Result<()> {
    println!("~ Current Configuration ~");
    println!();

    if !RemoteConfig::exists() {
        println!("No configuration found.");
        println!("Run 'slingshot-remote-setup --configure' to set up.");
        return Ok(());
    }

    let config = RemoteConfig::load()?;

    println!("Node name:       {}", config.node_name);
    println!("Central address: {}", config.central_address);

    match &config.source {
        config_manager::SourceConfig::Rtsp(_) => {
            println!("Source:          Direct RTSP");
        }
        config_manager::SourceConfig::Onvif(onvif) => {
            println!("Source:          ONVIF camera at {}", onvif.ip);
            println!("Camera user:     {}", onvif.username);
        }
    }

    println!("Recording:       {}", if config.recording.enabled {
        format!("enabled ({}% reserve)", config.recording.disk_reserve_percent)
    } else {
        "disabled".to_string()
    });

    if !config.storage.mountpoint.as_os_str().is_empty() {
        println!("Storage:         {}", config.storage.mountpoint.display());
    }

    println!();
    println!("~ Service Status ~");
    println!();
    println!("{}", systemd::get_service_status());

    Ok(())
}

/// Display QR code in terminal using Unicode blocks
fn display_qr_terminal(data: &str) -> Result<()> {
    let code = QrCode::new(data.as_bytes())?;
    let string = code
        .render::<char>()
        .quiet_zone(true)
        .module_dimensions(2, 1)
        .build();
    println!("{}", string);
    Ok(())
}

/// Regenerate admin user TOTP credentials
fn regenerate_admin_credentials() -> Result<()> {
    println!();
    println!("~ Regenerate Admin Credentials ~");
    println!();

    let store = match FingerprintStore::open() {
        Ok(s) => s,
        Err(e) => {
            println!("Error: Could not open fingerprint store: {}", e);
            println!("Make sure you're running this on a central node.");
            return Ok(());
        }
    };

    // List existing users
    let users = store.list_users()?;
    if users.is_empty() {
        println!("No admin users found.");
        println!("Use 'slingshot-central-setup' to create an admin user first.");
        return Ok(());
    }

    // Let user select which account to regenerate
    let user_labels: Vec<String> = users
        .iter()
        .map(|u| format!("{} ({})", u.username, u.role))
        .collect();

    let selected = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select user to regenerate credentials for")
        .items(&user_labels)
        .default(0)
        .interact()?;

    let username = &users[selected].username;

    println!();
    println!(
        "WARNING: This will invalidate the current authenticator setup for '{}'.",
        username
    );
    println!("The user will need to re-scan the QR code with their authenticator app.");
    println!();

    let confirm = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Are you sure you want to regenerate credentials?")
        .default(false)
        .interact()?;

    if !confirm {
        println!("Cancelled.");
        return Ok(());
    }

    // Regenerate TOTP
    let (totp_secret, _qr_png) = store.regenerate_totp(username)?;

    // Build otpauth URL for QR code
    let otpauth_url = format!(
        "otpauth://totp/SlingShot:{}?secret={}&issuer=SlingShot&algorithm=SHA1&digits=6&period=30",
        username, totp_secret
    );

    println!();
    println!("New credentials generated for '{}'.", username);
    println!();
    println!("Scan this QR code with your authenticator app:");
    println!("(Google Authenticator, Authy, 1Password, etc.)");
    println!();
    display_qr_terminal(&otpauth_url)?;
    println!();
    println!("Or manually enter this secret: {}", totp_secret);
    println!();

    // Verify new TOTP before completing
    loop {
        let code: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter 6-digit code from your authenticator to verify")
            .interact_text()?;

        if FingerprintStore::verify_totp_code(&totp_secret, &code)? {
            println!();
            println!("Credentials verified and updated successfully!");
            println!("All existing sessions have been invalidated.");
            break;
        } else {
            println!("Invalid code. Please try again.");
        }
    }

    Ok(())
}

