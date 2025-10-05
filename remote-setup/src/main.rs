mod storage;
mod systemd;
mod wizard;

use anyhow::Result;
use clap::Parser;
use config_manager::RemoteConfig;
use dialoguer::{theme::ColorfulTheme, Select};

#[derive(Parser)]
#[command(name = "kaiju-remote-setup")]
#[command(about = "Interactive setup and installation tool for kaiju remote nodes")]
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

    /// Test connection to central node
    #[arg(long)]
    test: bool,
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
    if cli.test {
        return test_connection();
    }

    // No flags - show interactive menu
    run_menu()
}

fn run_menu() -> Result<()> {
    println!();
    println!("~ KAIJU REMOTE NODE SETUP ~");
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
            "Test connection to central",
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
                if !has_config {
                    println!("Error: No configuration found. Please configure first.");
                } else if let Err(e) = test_connection() {
                    eprintln!("Connection test failed: {}", e);
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
        println!("Run 'kaiju-remote-setup --configure' to set up.");
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

fn test_connection() -> Result<()> {
    let config = RemoteConfig::load()?;

    println!("Testing connection to central node at {}...", config.central_address);

    // For now just validate the address format
    use std::net::SocketAddr;
    match config.central_address.parse::<SocketAddr>() {
        Ok(addr) => {
            println!("Address format: valid ({})", addr);

            // Try a TCP connection to check reachability
            println!("Checking reachability...");
            match std::net::TcpStream::connect_timeout(
                &addr,
                std::time::Duration::from_secs(5),
            ) {
                Ok(_) => println!("Connection: reachable"),
                Err(e) => println!("Connection: failed ({})", e),
            }
        }
        Err(e) => {
            println!("Address format: invalid ({})", e);
        }
    }

    // Test camera connection if ONVIF
    match &config.source {
        config_manager::SourceConfig::Onvif(onvif) => {
            println!();
            println!("Testing camera connection at {}...", onvif.ip);

            let pass = onvif.password().map_err(|e| anyhow::anyhow!("Failed to decode password: {}", e))?;
            let client = onvif_client::OnvifClient::new(&onvif.ip, &onvif.username, &pass);

            match client.get_device_info() {
                Ok(info) => println!("Camera: {}", info),
                Err(e) => println!("Camera connection failed: {}", e),
            }
        }
        config_manager::SourceConfig::Rtsp(_) => {
            println!();
            println!("RTSP source - skipping camera test");
        }
    }

    Ok(())
}
