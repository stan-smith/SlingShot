use anyhow::Result;
use config_manager::CentralConfig;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use fingerprint_store::FingerprintStore;
use rand::Rng;

/// Network interface info for display
struct InterfaceInfo {
    ip: String,
    display: String,
}

/// Get available network interfaces
fn get_interfaces() -> Vec<InterfaceInfo> {
    let mut interfaces = Vec::new();

    // Always offer these options first
    interfaces.push(InterfaceInfo {
        ip: "0.0.0.0".to_string(),
        display: "0.0.0.0 (all interfaces)".to_string(),
    });
    interfaces.push(InterfaceInfo {
        ip: "127.0.0.1".to_string(),
        display: "127.0.0.1 (localhost only)".to_string(),
    });

    // Enumerate actual network interfaces
    if let Ok(addrs) = if_addrs::get_if_addrs() {
        for iface in addrs {
            // Skip loopback (already covered by localhost option)
            if iface.is_loopback() {
                continue;
            }

            // Only include IPv4 for now
            if let if_addrs::IfAddr::V4(v4) = &iface.addr {
                let ip = v4.ip.to_string();
                // Skip if we already have this IP
                if interfaces.iter().any(|i| i.ip == ip) {
                    continue;
                }
                interfaces.push(InterfaceInfo {
                    ip: ip.clone(),
                    display: format!("{} ({} only)", ip, iface.name),
                });
            }
        }
    }

    interfaces
}

/// Run the full configuration wizard
pub fn run_wizard() -> Result<()> {
    println!();
    println!("--- Central Node Configuration ---");
    println!();

    // Load existing config if available for defaults
    let existing = CentralConfig::load().ok();

    // Get available interfaces
    let interfaces = get_interfaces();
    let interface_labels: Vec<&str> = interfaces.iter().map(|i| i.display.as_str()).collect();

    // Find default selection index
    let default_idx = existing
        .as_ref()
        .and_then(|c| c.bind_interfaces.first())
        .and_then(|ip| interfaces.iter().position(|i| &i.ip == ip))
        .unwrap_or(0); // Default to 0.0.0.0 (all interfaces)

    println!("Select which network interface to bind services to.");
    println!();

    let selected_idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Network interface")
        .items(&interface_labels)
        .default(default_idx)
        .interact()?;

    let bind_interface = interfaces[selected_idx].ip.clone();

    finish_wizard(existing, bind_interface)
}

fn finish_wizard(existing: Option<CentralConfig>, bind_interface: String) -> Result<()> {
    println!();
    println!("--- Port Configuration ---");
    println!();

    let defaults = existing.as_ref().cloned().unwrap_or_default();

    let admin_port: u16 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Admin web port")
        .default(defaults.admin_port)
        .interact_text()?;

    let quic_port: u16 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("QUIC server port")
        .default(defaults.quic_port)
        .interact_text()?;

    let onvif_port: u16 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("ONVIF server port")
        .default(defaults.onvif_port)
        .interact_text()?;

    let rtsp_port: u16 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("RTSP server port")
        .default(defaults.rtsp_port)
        .interact_text()?;

    // Build config with single interface
    let config = CentralConfig {
        bind_interfaces: vec![bind_interface.clone()],
        admin_port,
        quic_port,
        onvif_port,
        rtsp_port,
    };

    // Show summary
    println!();
    println!("--- Summary ---");
    println!();
    println!("Bind interface:  {}", bind_interface);
    println!("Admin web port:  {}", admin_port);
    println!("QUIC port:       {}", quic_port);
    println!("ONVIF port:      {}", onvif_port);
    println!("RTSP port:       {}", rtsp_port);
    println!();
    println!("Service endpoints:");
    println!("  Admin:  http://{}:{}", bind_interface, admin_port);
    println!("  QUIC:   {}:{}", bind_interface, quic_port);
    println!("  ONVIF:  http://{}:{}", bind_interface, onvif_port);
    println!("  RTSP:   rtsp://{}:{}", bind_interface, rtsp_port);

    // Confirm save
    println!();
    let save = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Save configuration?")
        .default(true)
        .interact()?;

    if save {
        config.save()?;
        let path = CentralConfig::default_path()?;
        println!();
        println!("Configuration saved to {}", path.display());

        // Setup admin user if not exists
        setup_admin_user()?;

        println!();
        println!("Restart the central node for changes to take effect.");
    } else {
        println!("Configuration not saved.");
    }

    Ok(())
}

/// Generate a random alphanumeric password
fn generate_alphanumeric_password(len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// Setup admin user if not already exists
fn setup_admin_user() -> Result<()> {
    let store = FingerprintStore::open()?;

    if store.admin_exists()? {
        println!();
        println!("Admin user already exists.");
        return Ok(());
    }

    println!();
    println!("=== Admin User Setup ===");
    println!();

    let password = generate_alphanumeric_password(20);
    store.create_admin_user("admin", &password)?;

    println!("Admin user created!");
    println!();
    println!("  Username: admin");
    println!("  Password: {}", password);
    println!();
    println!("  *** SAVE THIS PASSWORD - it will not be shown again! ***");

    Ok(())
}
