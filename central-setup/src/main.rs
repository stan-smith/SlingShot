mod wizard;

use anyhow::Result;
use clap::Parser;
use config_manager::CentralConfig;
use dialoguer::{theme::ColorfulTheme, Select};
use fingerprint_store::FingerprintStore;

#[derive(Parser)]
#[command(name = "kaiju-central-setup")]
#[command(about = "Interactive setup tool for kaiju central node")]
struct Cli {
    /// Run configuration wizard directly
    #[arg(long)]
    configure: bool,

    /// Show current configuration
    #[arg(long)]
    status: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.configure {
        return wizard::run_wizard();
    }
    if cli.status {
        return show_status();
    }

    // No flags - show interactive menu
    run_menu()
}

fn run_menu() -> Result<()> {
    println!();
    println!("==========================================");
    println!("     KAIJU CENTRAL NODE SETUP");
    println!("==========================================");
    println!();

    loop {
        let has_config = CentralConfig::exists();
        let has_admin = FingerprintStore::open()
            .map(|s| s.any_users_exist().unwrap_or(false))
            .unwrap_or(false);

        // Show current state
        if has_config {
            println!(
                "Config: {}",
                CentralConfig::default_path()
                    .unwrap_or_default()
                    .display()
            );
        } else {
            println!("Config: not configured (will use defaults)");
        }

        if has_admin {
            println!("Admin:  configured");
        } else {
            println!("Admin:  not configured");
        }
        println!();

        // Different menu based on whether initial setup is needed
        if !has_config || !has_admin {
            // Initial setup needed
            let options = vec![
                "Run initial setup (network + admin account)",
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
                    if let Err(e) = show_status() {
                        eprintln!("Error: {}", e);
                    }
                }
                2 => {
                    println!("Goodbye!");
                    break;
                }
                _ => unreachable!(),
            }
        } else {
            // Already configured - show reconfigure options
            let options = vec![
                "Reconfigure network bindings",
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
                    if let Err(e) = show_status() {
                        eprintln!("Error: {}", e);
                    }
                }
                2 => {
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
    println!("--- Current Configuration ---");
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

    Ok(())
}
