use anyhow::Result;
use config_manager::{generate_random_password, AuditConfig, CentralConfig, OnvifAuthConfig};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use fingerprint_store::FingerprintStore;
use qrcode::QrCode;

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
    println!("~ Central Node Configuration ~");
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
    println!("~ Port Configuration ~");
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
    println!("~ Summary ~");
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

        // Setup ONVIF credentials
        setup_onvif_credentials()?;

        // Setup audit logging
        setup_audit_logging()?;

        println!();
        println!("Restart the central node for changes to take effect.");
    } else {
        println!("Configuration not saved.");
    }

    Ok(())
}

/// Display QR code in terminal using Unicode blocks
fn display_qr_terminal(data: &str) -> Result<()> {
    let code = QrCode::new(data.as_bytes())?;
    let string = code.render::<char>()
        .quiet_zone(true)
        .module_dimensions(2, 1)
        .build();
    println!("{}", string);
    Ok(())
}

/// Setup admin user with TOTP if not already exists
fn setup_admin_user() -> Result<()> {
    let store = FingerprintStore::open()?;

    if store.any_users_exist()? {
        println!();
        println!("Admin user already exists.");
        return Ok(());
    }

    println!();
    println!("~ Admin User Setup (TOTP) ~");
    println!();

    let username: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Admin username")
        .default("admin".to_string())
        .interact_text()?;

    let description: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Description (optional)")
        .allow_empty(true)
        .interact_text()?;

    // Generate TOTP secret
    let (totp_secret, _qr_png) = FingerprintStore::generate_totp_secret(&username)?;

    // Build otpauth URL for QR code
    let otpauth_url = format!(
        "otpauth://totp/SlingShot:{}?secret={}&issuer=SlingShot&algorithm=SHA1&digits=6&period=30",
        username, totp_secret
    );

    println!();
    println!("Scan this QR code with your authenticator app:");
    println!("(Google Authenticator, Authy, 1Password, etc.)");
    println!();
    display_qr_terminal(&otpauth_url)?;
    println!();
    println!("Or manually enter this secret: {}", totp_secret);
    println!();

    // Verify TOTP before saving
    loop {
        let code: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter 6-digit code from your authenticator")
            .interact_text()?;

        // Verify code against secret directly (no database needed yet)
        if FingerprintStore::verify_totp_code(&totp_secret, &code)? {
            // Code valid - create the user
            store.create_user(&username, &totp_secret, "admin", &description)?;
            println!();
            println!("Admin account '{}' created successfully!", username);
            break;
        } else {
            println!("Invalid code. Please try again.");
        }
    }

    Ok(())
}

/// Setup ONVIF credentials for VMS authentication
fn setup_onvif_credentials() -> Result<()> {
    println!();
    println!("~ ONVIF Credentials ~");
    println!();

    if OnvifAuthConfig::exists() {
        let existing = OnvifAuthConfig::load()?;
        println!("Current ONVIF username: {}", existing.username);
        println!();

        let regenerate = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Regenerate ONVIF credentials?")
            .default(false)
            .interact()?;

        if !regenerate {
            println!("ONVIF credentials unchanged.");
            return Ok(());
        }
    }

    let username: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("ONVIF username")
        .default("onvif".to_string())
        .interact_text()?;

    let password = generate_random_password(16);

    let auth = OnvifAuthConfig::new(&username, &password);
    auth.save()?;

    println!();
    println!("ONVIF credentials saved.");
    println!();
    println!("Configure these in your VMS to access ONVIF endpoints:");
    println!("  Username: {}", username);
    println!("  Password: {}", password);
    println!();
    println!("(Keep these credentials secure)");

    Ok(())
}

/// Setup audit logging configuration
fn setup_audit_logging() -> Result<()> {
    println!();
    println!("~ Audit Logging ~");
    println!();

    let existing = AuditConfig::load().ok();
    let defaults = existing.unwrap_or_default();

    let enabled = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Enable audit logging?")
        .default(defaults.enabled)
        .interact()?;

    let retention_days: u32 = if enabled {
        Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Audit log retention (days)")
            .default(defaults.retention_days)
            .interact_text()?
    } else {
        defaults.retention_days
    };

    let config = AuditConfig {
        enabled,
        retention_days,
    };
    config.save()?;

    if enabled {
        println!();
        println!("Audit logging enabled.");
        println!("Events stored at: ~/.local/share/kaiju/audit.db");
        println!("Retention period: {} days", retention_days);
    } else {
        println!();
        println!("Audit logging disabled.");
    }

    Ok(())
}
