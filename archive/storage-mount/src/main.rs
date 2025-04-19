use clap::{Parser, Subcommand};
use std::path::PathBuf;
use storage_mount::{
    unmount_device, SetupError, StorageEvent, StorageManager,
};

#[derive(Parser, Debug)]
#[command(name = "storage-mount")]
#[command(about = "Mount and manage storage devices for recordings")]
#[command(version)]
struct Args {
    /// Path to storage.toml config file
    #[arg(short, long, default_value = "storage.toml")]
    config: PathBuf,

    /// Mount point for recordings
    #[arg(short, long, default_value = "/media/recordings")]
    mountpoint: PathBuf,

    /// Preview operations without executing
    #[arg(long)]
    dry_run: bool,

    /// Skip confirmation prompts
    #[arg(short = 'y', long)]
    yes: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Mount device from storage.toml, format if needed, add to fstab
    Setup,

    /// Unmount the recording storage
    Unmount,

    /// Show current mount status
    Status,

    /// Monitor device availability
    Monitor {
        /// Write status to file instead of stdout
        #[arg(long)]
        status_file: Option<PathBuf>,

        /// Output to stdout
        #[arg(long)]
        stdout: bool,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), SetupError> {
    let args = Args::parse();

    let manager = StorageManager::new(&args.config, &args.mountpoint);

    match args.command {
        Commands::Setup => {
            manager.setup(args.dry_run, args.yes)?;
        }

        Commands::Unmount => {
            println!("Unmounting {}...", args.mountpoint.display());
            unmount_device(&args.mountpoint, args.dry_run)?;
            println!("Unmounted successfully.");
        }

        Commands::Status => {
            let status = manager.status()?;
            status.print();
        }

        Commands::Monitor { status_file, stdout } => {
            let rx = manager.monitor()?;
            println!("Monitoring device availability...");
            println!("Press Ctrl+C to stop.\n");

            loop {
                match rx.recv() {
                    Ok(event) => {
                        let msg = match event {
                            StorageEvent::Available => "AVAILABLE",
                            StorageEvent::Unavailable => "UNAVAILABLE",
                        };

                        if stdout || status_file.is_none() {
                            println!("{}", msg);
                        }

                        if let Some(ref path) = status_file {
                            if let Err(e) = std::fs::write(path, msg) {
                                eprintln!("Failed to write status file: {}", e);
                            }
                        }
                    }
                    Err(_) => {
                        eprintln!("Monitor channel closed");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
