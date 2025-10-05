mod systemd;
mod wizard;

use anyhow::Result;
use clap::Parser;
use config_manager::CentralConfig;
use dialoguer::{theme::ColorfulTheme, Select};
use fingerprint_store::FingerprintStore;

#[derive(Parser)]
#[command(name = "kaiju-central-setup")]
#[command(about = "Interactive setup and installation tool for kaiju central node")]
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

    // No flags - show interactive menu
    run_menu()
}

fn run_menu() -> Result<()> {
    println!();
    println!("~ KAIJU CENTRAL NODE SETUP ~");
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
                    if let Err(e) = systemd::install_service() {
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
