# 🔒 Debian/Ubuntu Security Hardening Script

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Bash-5.0+-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu-blue.svg)](https://www.debian.org/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/Z-A-P-P-I-T/Debian-Ubuntu-Security-Hardening-Script/graphs/commit-activity)

A comprehensive, production-ready hardening script for Debian/Ubuntu systems. It applies security best practices, creates a secure admin user, and configures monitoring and auditing tools. Runs interactively or in fully automated mode.

---

## 📋 Table of Contents

- [Features](#-features)
- [What Gets Hardened](#-what-gets-hardened)
- [Prerequisites](#-prerequisites)
- [Quick Start](#-quick-start)
- [Usage Modes](#-usage-modes)
- [Command-Line Flags](#-command-line-flags)
- [What the Script Does](#-what-the-script-does)
- [Safety Features](#-safety-features)
- [After Running the Script](#-after-running-the-script)
- [Logs and Reports](#-logs-and-reports)
- [Verification](#-verification)
- [Troubleshooting](#-troubleshooting)
- [FAQ](#-faq)
- [Contributing](#-contributing)
- [License](#-license)
- [Disclaimer](#-disclaimer)

---

## ✨ Features

- 🚀 **Fully automated** (optional)
- 🔐 **Auto user creation** with a random admin username
- 🛡️ **Comprehensive hardening** across SSH, kernel, users, and services
- 🔍 **Security scanning** with Lynis, RKHunter, and AIDE
- 📊 **Detailed logging** of every action
- ♻️ **Safe to re-run**
- 🎯 **VPS-safe** (tests new admin access before disabling root)
- 🔄 **Rollback** on SSH config errors
- 📦 **Minimal dependencies** (uses system packages)
- 🌐 **Works offline** after packages are installed

---

## 🎯 What Gets Hardened

### System Security
- SSH hardening (disable root login, key-only auth, port restrictions)
- Firewall configuration (Fail2Ban)
- Kernel parameters (sysctl hardening)
- File permissions for sensitive files
- User account policies (password aging, quality requirements)
- Disable unnecessary services and network protocols
- Compiler access restrictions
- Core dump prevention

### Monitoring & Detection
- File integrity monitoring (AIDE)
- Rootkit detection (RKHunter)
- System auditing (auditd rules)
- Security scanning (Lynis)
- Process accounting
- Log monitoring and rotation

### Access Control
- PAM configuration (password quality, history)
- Sudo restrictions
- `su` restrictions (wheel group)
- Session timeouts
- Legal banners

### Network Security
- TCP SYN cookies
- IP forwarding disabled
- ICMP redirect disabled
- Source routing disabled
- Reverse path filtering
- IPv6 hardening

---

## 📋 Prerequisites

### Required
- **OS**: Debian 10+ or Ubuntu 18.04+
- **User**: Root access (`sudo`)
- **Disk**: ~500MB free for logs and packages

### Remote Servers (VPS)
- Root should have SSH keys configured
- Keep the current SSH session open while testing

### Local VMs / Workstations
- Use `--local-vm` to skip SSH key checks

---

## 🚀 Quick Start

### 1) Clone or Download

```bash
# Clone the repository
git clone https://github.com/Z-A-P-P-I-T/Debian-Ubuntu-Security-Hardening-Script.git
cd Debian-Ubuntu-Security-Hardening-Script

# Or download the script directly
curl -L -o debian-ubuntu-hardening-script.sh \
  https://raw.githubusercontent.com/Z-A-P-P-I-T/Debian-Ubuntu-Security-Hardening-Script/main/debian-ubuntu-hardening-script.sh

chmod +x debian-ubuntu-hardening-script.sh
```

### 2) Run (Interactive Mode)

```bash
sudo bash debian-ubuntu-hardening-script.sh
```

### 3) Save Credentials

The script creates a secure admin user and prints credentials:

```
Username: sec_a3f9c2b1
Password: xK8#mP2$vR9@wL4!qT7y
```

⚠️ Save these immediately.

---

## 🎮 Usage Modes

### Interactive (Default)
Best for first-time users and production servers.

```bash
sudo bash debian-ubuntu-hardening-script.sh
```

### Fully Automated
Good for CI/CD and large deployments.

```bash
sudo bash debian-ubuntu-hardening-script.sh --disable-root-login
```

### Safety Mode
Keeps root SSH enabled for cautious admins.

```bash
sudo bash debian-ubuntu-hardening-script.sh --keep-root-login
```

### Local VM / Testing Mode
Skips SSH key checks and keeps password auth enabled.

```bash
sudo bash debian-ubuntu-hardening-script.sh --local-vm
```

---

## 🚩 Command-Line Flags

| Flag | Description | Use Case |
|------|-------------|----------|
| `--disable-root-login` | Disable root SSH login automatically | Automation / CI |
| `--keep-root-login` | Keep root SSH login enabled | Cautious admins |
| `--local-vm` | Skip SSH key checks | Local VM testing |
| `--skip-user-creation` | Don’t create a new admin | Existing admin setup |
| `--enable-pam-lockout` | Enable PAM lockout | High-security environments |

Example:

```bash
sudo bash debian-ubuntu-hardening-script.sh --local-vm --keep-root-login
```

---

## 🔧 What the Script Does

**Phase 1: Pre-Hardening**
- System checks and root validation
- SSH key checks (unless `--local-vm`)
- Create secure admin user
- Verify sudo access

**Phase 2: Packages**
- Update packages
- Install security tools (Lynis, AIDE, RKHunter, Fail2Ban, auditd)

**Phase 3: Baseline Scan**
- Run initial Lynis audit

**Phase 4: Security Configuration**
- Fail2Ban, auditd, sysctl hardening
- Password policies, AIDE initialization
- SSH hardening
- Banner setup and access restrictions

**Phase 5: Auto-Remediation**
- File permissions fixes
- Disable unused modules
- Apply network hardening
- Apply Lynis recommendations

**Phase 6: Verification**
- Re-run Lynis
- Integrity checks (debsums)
- RKHunter scan

---

## 🛡️ Safety Features

- Verifies new admin login before disabling root
- Automatic rollback on SSH misconfiguration
- Safe to re-run

---

## ✅ After Running the Script

- Test the new admin account
- Verify SSH login
- Review logs and reports

---

## 📄 Logs and Reports

Logs are stored under `/var/log/` and within the script’s output directory. Check:
- Lynis reports
- AIDE database and scan logs
- RKHunter logs

---

## 🔍 Verification

Recommended:

```bash
sudo lynis audit system
sudo rkhunter --check
```

---

## 🧯 Troubleshooting

- Keep SSH session open until you confirm new login works.
- Use `--local-vm` for VM testing.
- If SSH breaks, restore from the backup the script creates.

---

## ❓ FAQ

**Q: Does this work on Ubuntu/Debian servers?**
A: Yes — Debian 10+ and Ubuntu 18.04+.

**Q: Can I run it multiple times?**
A: Yes — it is designed to be idempotent.

---

## 🤝 Contributing

Issues and PRs are welcome.

---

## 📜 License

MIT License.

---

## ⚠️ Disclaimer

This script makes significant security changes. Review the code before use and test in a non‑production environment first.

## 👤 Author

Created by Kimi Autto (github.com/Z-A-P-P-I-T)
