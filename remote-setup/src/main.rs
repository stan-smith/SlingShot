mod storage;
mod systemd;
mod wizard;

use anyhow::Result;
use clap::Parser;
use config_manager::RemoteConfig;
use dialoguer::{theme::ColorfulTheme, Select};

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
