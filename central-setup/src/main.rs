mod systemd;
mod wizard;

use anyhow::Result;
use clap::Parser;
use config_manager::CentralConfig;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use fingerprint_store::FingerprintStore;
use qrcode::QrCode;

#[derive(Parser)]
#[command(name = "slingshot-central-setup")]
#[command(about = "Interactive setup and installation tool for slingshot central node")]
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
    println!("~ SLINGSHOT CENTRAL NODE SETUP ~");
    println!();

    loop {
        let has_config = CentralConfig::exists();
        let has_admin = FingerprintStore::open()
            .map(|s| s.any_users_exist().unwrap_or(false))
            .unwrap_or(false);
        let service_status = systemd::get_service_status();

        // Show current state
        if has_config {
            println!(
                "Config:  found at {}",
                CentralConfig::default_path()
                    .unwrap_or_default()
                    .display()
            );
        } else {
            println!("Config:  not configured (will use defaults)");
        }

        if has_admin {
            println!("Admin:   configured");
        } else {
            println!("Admin:   not configured");
        }
        println!("Service: {}", service_status);
        println!();

        // Different menu based on whether initial setup is needed
        if !has_config || !has_admin {
            // Initial setup needed
            let options = vec![
                "Run initial setup (network + admin account)",
                "Install/update systemd service",
                "Uninstall systemd service",
                "Show current configuration",
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
                    println!("Goodbye!");
                    break;
                }
                _ => unreachable!(),
            }
        } else {
            // Already configured - show all options
            let options = vec![
                "Reconfigure network bindings",
                "Regenerate admin credentials",
                "Install/update systemd service",
                "Uninstall systemd service",
                "Show current configuration",
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
                    if let Err(e) = regenerate_admin_credentials() {
                        eprintln!("Error: {}", e);
                    }
                }
                2 => {
                    if let Err(e) = systemd::install_service() {
                        eprintln!("Installation failed: {}", e);
                    }
                }
                3 => {
                    if let Err(e) = systemd::uninstall_service() {
                        eprintln!("Uninstall failed: {}", e);
                    }
                }
                4 => {
                    if let Err(e) = show_status() {
                        eprintln!("Error: {}", e);
                    }
                }
                5 => {
                    println!("Goodbye!");
                    break;
                }
                _ => unreachable!(),
            }
        }

        println!();
    }

    Ok(())
}

fn show_status() -> Result<()> {
    println!("~ Current Configuration ~");
    println!();

    let config = if CentralConfig::exists() {
        CentralConfig::load()?
    } else {
        println!("No configuration found, showing defaults:");
        println!();
        CentralConfig::default()
    };

    println!("Bind interfaces: {:?}", config.bind_interfaces);
    println!();
    println!("Ports:");
    println!("  Admin web: {}", config.admin_port);
    println!("  QUIC:      {}", config.quic_port);
    println!("  ONVIF:     {}", config.onvif_port);
    println!("  RTSP:      {}", config.rtsp_port);
    println!();
    println!("Service bind addresses:");
    for addr in config.admin_addrs() {
        println!("  Admin:  http://{}", addr);
    }
    for addr in config.quic_addrs() {
        println!("  QUIC:   {}", addr);
    }
    for addr in config.onvif_addrs() {
        println!("  ONVIF:  http://{}", addr);
    }
    for addr in config.rtsp_addrs() {
        println!("  RTSP:   rtsp://{}", addr);
    }

    println!();
    println!("~ Service Status ~");
    println!();
    println!("Systemd service: {}", systemd::get_service_status());

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

    let store = FingerprintStore::open()?;

    // List existing users
    let users = store.list_users()?;
    if users.is_empty() {
        println!("No admin users found.");
        println!("Run the initial setup wizard to create an admin user first.");
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
