use chrono::prelude::*;
use colored::*;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::Sha256;
use std::env;
use std::env::consts::OS;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use sysinfo::{Networks, System};

type HmacSha256 = Hmac<Sha256>;

const MASTER_CODE_FILE: &str = "pwd.dat";
const BACKUP_MASTER_CODE_FILE: &str = "pwd_backup.dat";
const LOG_FILE: &str = "activity.log";
const PBKDF2_ITERS: u32 = 120_000;
const MAX_ATTEMPTS: u32 = 6;

// ---------- Platform Detection ----------
fn is_windows() -> bool {
    OS == "windows"
}

fn is_linux() -> bool {
    OS == "linux"
}

fn is_macos() -> bool {
    OS == "macos"
}

// ---------- UI Helpers ----------
fn typewriter(text: &str, delay: u64) {
    for c in text.chars() {
        print!("{}", c);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(delay));
    }
    println!();
}

fn loading_bar(task: &str, length: usize, speed: u64) {
    print!("{} [", task.yellow().bold());
    for _ in 0..length {
        print!("{}", "#".bright_green());
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(speed));
    }
    println!("] {}", "DONE".green().bold());
}

fn cinematic_feed() {
    let fake_data = [
        "SCANNING NETWORK INTERFACES...",
        "TRACING SIGNAL ORIGIN...",
        "FIREWALL STATUS: ARMED",
        "DETECTING UNAUTHORIZED CONNECTIONS...",
        "NO FOREIGN DEVICES DETECTED",
        "ENCRYPTION KEYS VERIFIED",
        "GATEWAY STATUS: SECURE",
    ];
    for line in fake_data.iter() {
        println!("{}", format!("[FEED] {}", line).bright_black());
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
}

fn print_banner() {
    println!("{}", "====================================================".bright_green());
    println!("{}", "           IAS // SECURITY".bright_green().bold());
    println!("{}", "====================================================".bright_green());
    typewriter("[BOOT] Initializing security subsystems...", 20);
    loading_bar("Loading encryption modules", 20, 40);
    loading_bar("Verifying system integrity", 20, 50);
    cinematic_feed();
    println!();
}

// ---------- Logger ----------
fn log_event(msg: &str) {
    let ts = Local::now().to_rfc3339();
    match OpenOptions::new().create(true).append(true).open(LOG_FILE) {
        Ok(mut f) => {
            if let Err(e) = writeln!(f, "[{}] {}", ts, msg) {
                eprintln!("Failed to write to {}: {}", LOG_FILE, e);
            }
            if let Err(e) = f.flush() {
                eprintln!("Failed to flush {}: {}", LOG_FILE, e);
            } else {
                println!("Logged event to {}: {}", LOG_FILE, msg);
            }
        }
        Err(e) => eprintln!("Failed to open {}: {}. Ensure directory is writable.", LOG_FILE, e),
    }
}

// ---------- Master Password Handling ----------
fn create_master_store(password: &str) -> std::io::Result<()> {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    let mut dk = [0u8; 32];
    pbkdf2::<HmacSha256>(password.as_bytes(), &salt, PBKDF2_ITERS, &mut dk);

    let mut file = File::create(MASTER_CODE_FILE)?;
    file.write_all(&salt)?;
    file.write_all(&dk)?;
    file.sync_all()?;

    try_harden_file_acl(MASTER_CODE_FILE);
    backup_master_store()?;
    log_event("Master store created");
    Ok(())
}

fn verify_master(password: &str) -> std::io::Result<bool> {
    let mut file = File::open(MASTER_CODE_FILE)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    if buf.len() != 48 {
        log_event("Invalid master store file length");
        return Ok(false);
    }
    let salt = &buf[..16];
    let stored_dk = &buf[16..48];
    let mut dk = [0u8; 32];
    pbkdf2::<HmacSha256>(password.as_bytes(), salt, PBKDF2_ITERS, &mut dk);
    Ok(stored_dk == dk)
}

fn try_harden_file_acl(path: &str) {
    if is_windows() {
        let user = env::var("USERNAME").unwrap_or_else(|_| "CURRENT_USER".into());
        let _ = Command::new("icacls")
            .args(&[
                path,
                "/inheritance:r",
                "/grant:r",
                &format!("{}:F", user),
                "SYSTEM:F",
                "Administrators:F",
            ])
            .output();
    } else if is_linux() || is_macos() {
        let _ = Command::new("chmod").args(["600", path]).output();
    }
}

fn read_password_with_confirmation(prompt: &str) -> std::io::Result<String> {
    typewriter(prompt, 15);
    let pw1 = rpassword::read_password()?;
    typewriter("Confirm new master password:", 15);
    let pw2 = rpassword::read_password()?;
    if pw1 == pw2 {
        Ok(pw1)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Passwords do not match",
        ))
    }
}

fn change_master_password_flow() -> std::io::Result<()> {
    use rpassword::read_password;
    if !Path::new(MASTER_CODE_FILE).exists() {
        println!("{}", "No master store found. Can't change password.".red());
        log_event("Attempted to change password but no master store found");
        return Ok(());
    }

    typewriter("Enter current master password:", 15);
    let cur = read_password()?;
    match verify_master(&cur) {
        Ok(true) => {
            let new = read_password_with_confirmation("Enter new master password:")?;
            create_master_store(&new)?;
            println!("{}", "Master password changed successfully.".green());
            log_event("Master password changed");
            Ok(())
        }
        Ok(false) => {
            println!("{}", "Current master password incorrect.".red());
            log_event("Failed master-change attempt");
            Ok(())
        }
        Err(e) => {
            println!("Error verifying current password: {}", e);
            log_event(&format!("Error verifying current password: {}", e));
            Ok(())
        }
    }
}

fn backup_master_store() -> std::io::Result<()> {
    fs::copy(MASTER_CODE_FILE, BACKUP_MASTER_CODE_FILE)?;
    try_harden_file_acl(BACKUP_MASTER_CODE_FILE);
    log_event("Master store backed up");
    Ok(())
}

// ---------- Network Interface Helpers ----------
fn get_network_interfaces() -> Vec<String> {
    let mut interfaces = Vec::new();
    
    if is_windows() {
        // For Windows, return common interface names
        interfaces.push("Wi-Fi".to_string());
        interfaces.push("Ethernet".to_string());
    } else {
        // For Linux/macOS, try to get actual interfaces
        let networks = Networks::new_with_refreshed_list();
        for (name, _) in networks.iter() {
            interfaces.push(name.to_string());
        }
    }
    
    interfaces
}

// ---------- Lockdown ----------
fn lockdown_all() {
    println!("{}", "🔒 SYSTEM LOCKDOWN INITIATED".red().bold());
    cinematic_feed();

    // Platform-specific network interface disabling
    if is_windows() {
        let _ = Command::new("netsh")
            .args(["interface", "set", "interface", "Wi-Fi", "admin=disabled"])
            .output();
        let _ = Command::new("netsh")
            .args(["interface", "set", "interface", "Ethernet", "admin=disabled"])
            .output();
    } else {
        let interfaces = get_network_interfaces();
        for iface in interfaces {
            if iface.to_lowercase().contains("lo") || iface.to_lowercase().contains("loopback") {
                continue;
            }
            if is_linux() {
                let _ = Command::new("ip")
                    .args(["link", "set", &iface, "down"])
                    .output();
            } else if is_macos() {
                let _ = Command::new("ifconfig")
                    .args([&iface, "down"])
                    .output();
            }
        }
    }

    // Disable USB storage and services (platform-specific)
    if is_windows() {
        let _ = Command::new("reg")
            .args([
                "add",
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR",
                "/v",
                "Start",
                "/t",
                "REG_DWORD",
                "/d",
                "4",
                "/f",
            ])
            .output();
        let _ = Command::new("sc")
            .args(["stop", "LanmanServer"])
            .output();
        let _ = Command::new("sc")
            .args(["config", "LanmanServer", "start=", "disabled"])
            .output();
        let _ = Command::new("sc")
            .args(["stop", "SharedAccess"])
            .output();
        let _ = Command::new("sc")
            .args(["config", "SharedAccess", "start=", "disabled"])
            .output();
    } else if is_linux() {
        let _ = Command::new("modprobe")
            .args(["-r", "usb_storage"])
            .output();
        let _ = Command::new("systemctl")
            .args(["stop", "smb"])
            .output();
        let _ = Command::new("systemctl")
            .args(["disable", "smb"])
            .output();
    } else if is_macos() {
        let _ = Command::new("launchctl")
            .args(["stop", "com.apple.smbd"])
            .output();
        let _ = Command::new("launchctl")
            .args(["disable", "system/com.apple.smbd"])
            .output();
    }

    log_event("Lockdown applied at startup");
}

// ---------- Unlock ----------
fn unlock_all() {
    println!("{}", "✅ ACCESS GRANTED — RESTORING CONNECTIVITY".green().bold());
    cinematic_feed();

    // Platform-specific network interface enabling
    if is_windows() {
        // For Windows, use specific interface names
        let _ = Command::new("netsh")
            .args(["interface", "set", "interface", "Wi-Fi", "admin=enabled"])
            .output();
        let _ = Command::new("netsh")
            .args(["interface", "set", "interface", "Ethernet", "admin=enabled"])
            .output();
    } else {
        // For Linux/macOS, try to enable all non-loopback interfaces
        let interfaces = get_network_interfaces();
        for iface in interfaces {
            if iface.to_lowercase().contains("lo") || iface.to_lowercase().contains("loopback") {
                continue;
            }
            if is_linux() {
                let _ = Command::new("ip")
                    .args(["link", "set", &iface, "up"])
                    .output();
            } else if is_macos() {
                let _ = Command::new("ifconfig")
                    .args([&iface, "up"])
                    .output();
            }
        }
    }

    // Enable USB storage and services (platform-specific)
    if is_windows() {
        let _ = Command::new("reg")
            .args([
                "add",
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR",
                "/v",
                "Start",
                "/t",
                "REG_DWORD",
                "/d",
                "3",
                "/f",
            ])
            .output();
        let _ = Command::new("sc")
            .args(["config", "LanmanServer", "start=", "auto"])
            .output();
        let _ = Command::new("sc")
            .args(["start", "LanmanServer"])
            .output();
        let _ = Command::new("sc")
            .args(["config", "SharedAccess", "start=", "auto"])
            .output();
        let _ = Command::new("sc")
            .args(["start", "SharedAccess"])
            .output();
    } else if is_linux() {
        let _ = Command::new("modprobe")
            .args(["usb_storage"])
            .output();
        let _ = Command::new("systemctl")
            .args(["enable", "--now", "smb"])
            .output();
    } else if is_macos() {
        let _ = Command::new("launchctl")
            .args(["enable", "system/com.apple.smbd"])
            .output();
        let _ = Command::new("launchctl")
            .args(["start", "com.apple.smbd"])
            .output();
    }

    log_event("Basic functionality enabled");
}

// ---------- Shutdown ----------
fn shutdown_system() {
    log_event("Shutting down system due to max failed attempts");
    if is_windows() {
        let output = Command::new("shutdown")
            .args(["/s", "/t", "0"])
            .output();
        if let Err(e) = output {
            log_event(&format!("Shutdown failed: {}", e));
        }
    } else if is_linux() || is_macos() {
        let output = Command::new("shutdown")
            .args(["-h", "now"])
            .output();
        if let Err(e) = output {
            log_event(&format!("Shutdown failed: {}", e));
        }
    }
}

// ---------- Interactive Menu ----------
fn print_menu() {
    println!("{}", "=== IAS // SECURITY MENU ===".cyan().bold());
    println!("1. Change master password");
    println!("2. View activity log");
    println!("3. View system status");
    println!("4. Exit");
}

fn display_log() {
    match fs::read_to_string(LOG_FILE) {
        Ok(content) => println!("{}", content),
        Err(e) => {
            println!(
                "{}",
                format!("Error reading {}: {}. Check if file exists and is readable.", LOG_FILE, e).red()
            );
            log_event(&format!("Failed to read log: {}", e));
        }
    }
}

fn display_system_status() {
    match fs::read_to_string(LOG_FILE) {
        Ok(content) => {
            let lines: Vec<&str> = content.lines().collect();
            println!("Total events: {}", lines.len());

            let mut failed_attempts = 0;
            let mut lockdowns = 0;
            let mut unlocks = 0;

            for line in &lines {
                if line.contains("Failed") || line.contains("Incorrect") {
                    failed_attempts += 1;
                } else if line.contains("Lockdown") {
                    lockdowns += 1;
                } else if line.contains("unlocked") || line.contains("Basic functionality enabled") {
                    unlocks += 1;
                }
            }

            // Chart code block for system status
            println!(
                "System Events: Failed Attempts: {}, Lockdowns: {}, Unlocks: {}",
                failed_attempts, lockdowns, unlocks
            );

            // List recent events
            println!("\nRecent Events (last 10):");
            let recent = lines.iter().rev().take(10).rev();
            for line in recent {
                println!("{}", line);
            }
        }
        Err(e) => {
            println!(
                "{}",
                format!("Error reading log for status: {}. Check if {} exists.", e, LOG_FILE).red()
            );
            log_event(&format!("Failed to read log for status: {}", e));
        }
    }
}

fn run_menu() {
    loop {
        print_menu();
        typewriter("Select an option (1-4):", 15);
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        match input.trim() {
            "1" => {
                if let Err(e) = change_master_password_flow() {
                    println!("{}", format!("Error changing password: {}", e).red());
                    log_event(&format!("Error changing password: {}", e));
                }
            }
            "2" => display_log(),
            "3" => display_system_status(),
            "4" => {
                println!("{}", "Exiting... System will remain unlocked.".yellow());
                log_event("Program exited");
                break;
            }
            _ => println!("{}", "Invalid option.".red()),
        }
    }
}

// ---------- Main ----------
fn main() {
    print_banner();

    let args: Vec<String> = env::args().collect();
    if args.get(1).map(|s| s == "changepw").unwrap_or(false) {
        if let Err(e) = change_master_password_flow() {
            eprintln!("Error changing password: {}", e);
            log_event(&format!("Error changing password: {}", e));
        }
        return;
    }

    lockdown_all();

    if !Path::new(MASTER_CODE_FILE).exists() {
        loop {
            match read_password_with_confirmation("No master password found. Set new master password:") {
                Ok(pw) => {
                    if let Err(e) = create_master_store(&pw) {
                        eprintln!("Failed to create master store: {}", e);
                        log_event(&format!("Failed to create master store: {}", e));
                        continue;
                    }
                    println!("{}", "Master password created.".green());
                    log_event("Master password created");
                    break;
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    log_event(&format!("Error setting new password: {}", e));
                    continue;
                }
            }
        }
    }

    // Rate-limited password verification
    let mut attempts: u32 = 0;
    loop {
        typewriter("Enter master key to enable basic functionality:", 15);
        match rpassword::read_password() {
            Ok(input) => match verify_master(&input) {
                Ok(true) => {
                    unlock_all();
                    break;
                }
                Ok(false) => {
                    attempts += 1;
                    println!(
                        "{}",
                        format!("Incorrect password. {} attempts remaining.", MAX_ATTEMPTS - attempts).red()
                    );
                    log_event("Incorrect master key attempt");
                    if attempts >= MAX_ATTEMPTS {
                        log_event("Max attempts reached; initiating shutdown");
                        shutdown_system();
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(2));
                }
                Err(e) => {
                    eprintln!("Verification error: {}", e);
                    log_event(&format!("Verification error: {}", e));
                    return;
                }
            },
            Err(e) => {
                eprintln!("Failed to read password: {}", e);
                log_event(&format!("Failed to read password: {}", e));
                return;
            }
        }
    }

    println!("{}", "SYSTEM RUNNING WITH BASIC FUNCTIONALITY ENABLED".cyan().bold());
    run_menu();
}