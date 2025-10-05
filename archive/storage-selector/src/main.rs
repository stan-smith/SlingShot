use clap::Parser;
use dialoguer::{theme::ColorfulTheme, Confirm};
use std::path::PathBuf;
use storage_selector::{
    filter_selectable_devices, list_devices, select_device_interactive, select_first_unmounted,
    write_config, write_config_json, SelectorError, StorageConfig,
};

#[derive(Parser, Debug)]
#[command(name = "storage-selector")]
#[command(about = "Interactive storage device selection for remote unit setup")]
#[command(version)]
struct Args {
    /// Output file path
    #[arg(short, long, default_value = "storage.toml")]
    output: PathBuf,

    /// Output JSON instead of TOML
    #[arg(short, long)]
    json: bool,

    /// Select first available unmounted disk (non-interactive)
    #[arg(long)]
    non_interactive: bool,

    /// List all devices and exit (no selection)
    #[arg(short, long)]
    list: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long)]
    yes: bool,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), SelectorError> {
    let args = Args::parse();

    if args.list {
        print_device_list()?;
        return Ok(());
    }

    let config = if args.non_interactive {
        select_first_unmounted()?
    } else {
        select_device_interactive()?
    };

    // Show selection summary and ask for confirmation
    if !args.yes {
        print_selection_summary(&config);

        let confirmed = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Use this device for recording?")
            .default(true)
            .interact()
            .map_err(|e| SelectorError::InteractiveFailed(e.to_string()))?;

        if !confirmed {
            println!("Selection cancelled.");
            return Err(SelectorError::Cancelled);
        }
    }

    if args.json {
        write_config_json(&config, &args.output)?;
    } else {
        write_config(&config, &args.output)?;
    }

    println!("\nConfig written to: {}", args.output.display());

    Ok(())
}

fn print_selection_summary(config: &StorageConfig) {
    println!("\n~ Selection Summary ~");
    println!("  Device:     {}", config.device);
    println!("  Type:       {}", config.device_type);
    println!("  Size:       {}", config.size);
    if let Some(model) = &config.model {
        println!("  Model:      {}", model);
    }
    if let Some(mp) = &config.mountpoint {
        println!("  Mountpoint: {}", mp);
    }
    if let Some(fs) = &config.fstype {
        println!("  Filesystem: {}", fs);
    }
    println!();
}

fn print_device_list() -> Result<(), SelectorError> {
    let devices = list_devices()?;
    let selectable = filter_selectable_devices(&devices);

    if selectable.is_empty() {
        println!("No devices found.");
        return Err(SelectorError::NoDevices);
    }

    println!(
        "  {:<15} {:>4}   {:>10}   {:<24} MOUNT",
        "DEVICE", "TYPE", "SIZE", "MODEL"
    );
    println!();

    for s in &selectable {
        println!("{}", s.display_line());
    }

    Ok(())
}
