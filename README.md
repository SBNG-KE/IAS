IAS // SECURITY

IAS Security is a cross-platform defensive system control tool written in Rust designed to enforce system lockdown until a verified master key is provided.

The application protects system access by:

enforcing cryptographically secured authentication

applying network and peripheral lockdown

logging all security-related events

enforcing rate-limited authentication attempts

automatically shutting down the system after repeated failures

It functions as a local defensive security gate for sensitive environments where unauthorized system access must be prevented.

Core Concept

IAS Security temporarily restricts system functionality until a verified master key unlocks the system.

During lockdown it:

disables network interfaces

disables external storage access

disables sharing services

logs security events

prevents brute-force attempts

Only a verified password can restore normal system operation.

System Architecture
             IAS SECURITY SYSTEM
      -----------------------------------

              User Authentication
                      │
                      ▼
           Master Key Verification
              (PBKDF2 + SHA256)
                      │
          ┌───────────┴───────────┐
          │                       │
          ▼                       ▼
     Access Denied           Access Granted
          │                       │
          ▼                       ▼
   System Lockdown        Restore Functionality
          │                       │
          ▼                       ▼
   Network Disabled       Network Enabled
   USB Disabled           Services Enabled
   Services Stopped       System Operational
Key Security Features
Master Password Protection

IAS uses PBKDF2 password hashing with HMAC-SHA256.

Configuration:

PBKDF2 iterations: 120,000
Salt length: 16 bytes
Derived key length: 32 bytes

Password storage format:

[salt (16 bytes)] + [derived key (32 bytes)]

The password file is stored as:

pwd.dat

A backup copy is automatically created:

pwd_backup.dat

File permissions are hardened using OS-specific ACL controls.

Authentication Security

The program prevents brute force attacks by enforcing:

maximum login attempts

cooldown delays

automatic system shutdown

Configuration:

MAX_ATTEMPTS = 6

If authentication fails repeatedly:

System shutdown is triggered
Lockdown Mode

When IAS starts, it automatically enters lockdown mode.

Lockdown applies multiple defensive actions.

Network Lockdown

Network interfaces are disabled.

Platform specific commands:

Windows

netsh interface set interface Wi-Fi admin=disabled
netsh interface set interface Ethernet admin=disabled

Linux

ip link set <interface> down

macOS

ifconfig <interface> down
USB Storage Lockdown

External storage is disabled.

Windows

USBSTOR registry service disabled

Linux

modprobe -r usb_storage
Service Restrictions

Network sharing services are disabled.

Windows

LanmanServer
SharedAccess

Linux

smb service

macOS

com.apple.smbd
Unlock Mode

Once the correct master key is entered:

network interfaces are restored

USB storage access is restored

disabled services are restarted

system returns to normal operation

Security Logging

IAS records all security activity in:

activity.log

Events recorded include:

password creation

login attempts

failed authentication

system lockdown

unlock events

shutdown triggers

Example log entry:

[2026-03-08T21:10:34Z] Incorrect master key attempt
Interactive Security Console

After authentication the user gains access to the IAS management console.

Menu:

=== IAS SECURITY MENU ===

1. Change master password
2. View activity log
3. View system status
4. Exit
System Status Reporting

IAS analyzes log events to produce security metrics:

Example output:

Total events: 54
Failed Attempts: 3
Lockdowns: 2
Unlocks: 4

It also displays the most recent activity events.

Platform Support

IAS Security supports:

Platform	Support
Windows	Supported
Linux	Supported
macOS	Supported

Platform-specific commands are executed using Rust's Command interface.

Dependencies

Rust crates used:

chrono
colored
hmac
pbkdf2
rand
sha2
sysinfo
rpassword

These provide:

cryptography

terminal UI

system inspection

password input protection

Project Structure
ias-security
│
├── src
│   └── main.rs
│
├── pwd.dat
├── pwd_backup.dat
├── activity.log
│
└── README.md
Building the Application

Requirements:

Rust 1.70+

Cargo

Build:

cargo build --release

Run:

cargo run

Executable:

target/release/ias-security
Security Design Goals

IAS was designed with the following objectives:

Prevent unauthorized local access

Enforce strong password security

Provide defensive system lockdown

Record forensic activity logs

Maintain cross-platform compatibility

Resist brute-force authentication attempts

Intended Use Cases

IAS Security can be used for:

research on defensive system controls

local machine hardening

secure workstation environments

security engineering experiments

cybersecurity training labs

Disclaimer

This tool modifies system network interfaces and services.

Use only:

on systems you own

in controlled environments

with administrator privileges

Improper usage may disrupt system connectivity.
