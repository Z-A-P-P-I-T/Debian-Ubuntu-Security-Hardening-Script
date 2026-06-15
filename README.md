# Debian/Ubuntu Security Hardening Script

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Bash-5.0+-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu-blue.svg)](https://www.debian.org/)
[![Tested on Ubuntu 24.04](https://img.shields.io/badge/Tested-Ubuntu%2024.04%20LTS-brightgreen.svg)](https://ubuntu.com/)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/Z-A-P-P-I-T/Debian-Ubuntu-Security-Hardening-Script/graphs/commit-activity)

A comprehensive, production-ready security hardening script for Debian and Ubuntu systems. Applies security best practices aligned with CIS benchmarks and Lynis recommendations — covering SSH, kernel parameters, PAM, auditd, AppArmor, UFW firewall, automatic security updates, filesystem mount hardening, sudo I/O logging, and more. Runs interactively or in fully automated mode.

---

## Table of Contents

- [Features](#features)
- [What Gets Hardened](#what-gets-hardened)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Usage Modes](#usage-modes)
- [Command-Line Flags](#command-line-flags)
- [What the Script Does](#what-the-script-does)
- [Kernel Parameters Applied](#kernel-parameters-applied)
- [Disabled Kernel Modules](#disabled-kernel-modules)
- [Disabled Services](#disabled-services)
- [Auditd Rules](#auditd-rules)
- [File Permissions Hardened](#file-permissions-hardened)
- [Safety Features](#safety-features)
- [After Running the Script](#after-running-the-script)
- [Re-enabling USB Storage](#re-enabling-usb-storage)
- [Logs and Reports](#logs-and-reports)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)
- [Changelog](#changelog)

---

## Features

- **Fully automated** — runs unattended with a single flag, suitable for CI/CD and large deployments
- **Auto user creation** — generates a secure admin user with a randomized username and strong password
- **UFW firewall** — deny-by-default stateful firewall, SSH auto-allowed, `--skip-ufw` flag available
- **Automatic security updates** — `unattended-upgrades` configured for daily security patches, no auto-reboot
- **SSH hardening** — disables root login, enforces key-only auth, restricts forwarding, sets timeouts
- **Kernel hardening** — applies 25+ sysctl parameters covering network, TCP, memory, and process security
- **PAM hardening** — enforces password complexity, history, aging, and optional account lockout
- **Sudo hardening** — full I/O session logging, 15-min credential cache, bad-password alerts
- **Secure mount options** — `/tmp` and `/dev/shm` mounted with `noexec,nosuid,nodev`
- **AppArmor** — enables and enforces profiles for system daemons
- **Auditd** — deploys comprehensive audit rules for user, group, login, and network change monitoring
- **Service reduction** — stops and disables unnecessary network-facing daemons
- **Module blocking** — prevents loading of unused/dangerous kernel modules and filesystems
- **USB storage disabled** — blocks USB mass storage via modprobe (re-enable with one command)
- **Umask hardening** — sets `027` across profile, bashrc, login.defs, and init scripts
- **Session timeout** — enforces a 15-minute idle shell timeout via `/etc/profile.d/`
- **Compiler restrictions** — limits gcc/cc execution to the `compilers` group
- **File integrity monitoring** — AIDE with daily automated checks via cron
- **Rootkit detection** — RKHunter with daily automated scans via cron
- **Security auditing** — Lynis audit run before and after hardening
- **Detailed logging** — every action is logged under `/var/log/`
- **Safe to re-run** — idempotent design; checks before applying each change
- **VPS-safe** — verifies new admin SSH access before disabling root login
- **Rollback on failure** — automatic SSH config restore if misconfiguration detected

---

## What Gets Hardened

### SSH
- Root login disabled (configurable)
- Password authentication disabled — SSH keys required
- Empty passwords forbidden
- X11 forwarding disabled
- Agent forwarding disabled
- Protocol 2 enforced
- MaxAuthTries set to 3
- Client alive timeout set to 10 minutes
- Legal banner added to SSH
- SSH private key permissions set to 600, public to 644
- `/run/sshd` privilege separation directory created

### Kernel (sysctl)
- TCP SYN cookies enabled
- IP forwarding disabled
- ICMP redirects disabled (send and accept)
- Source routing disabled
- Reverse path filtering enabled
- Martian packet logging enabled
- ICMP broadcast echo disabled
- Bogus ICMP error response disabled
- IPv6 router advertisement disabled
- dmesg access restricted to root
- Kernel pointer leaks restricted
- ptrace scope restricted (Yama LSM)
- Core dumps disabled (`fs.suid_dumpable = 0`, `kernel.core_pattern = /dev/null`)
- `kexec_load_disabled = 1` (prevents live kernel replacement)
- `unprivileged_bpf_disabled = 1`
- BPF JIT hardening enabled (`net.core.bpf_jit_harden = 2`)

### PAM & Password Policy
- Password minimum length: 14 characters
- Requires uppercase, lowercase, digits, and special characters
- Password history: 5 previous passwords remembered
- Password hashing algorithm: SHA512
- Maximum password age configured via `/etc/login.defs`
- Optional account lockout after 10 failed login attempts (`--enable-pam-lockout`)

### AppArmor
- Service enabled and started
- Profiles enforced for selected system daemons (tcpdump, man)

### Auditd
- Rules for login/logout monitoring
- Rules for user and group modification commands
- Rules for password and shell change commands
- Rules for network configuration changes
- Rules for host file changes
- See [Auditd Rules](#auditd-rules) for full list

### Filesystem & Permissions
- `/etc/passwd` — 644
- `/etc/shadow` — 640
- `/etc/group` — 644
- `/etc/gshadow` — 640
- `/etc/crontab` — 600
- `/etc/cron.*` directories — 700
- SSH private keys — 600
- `/var/log/wtmp`, `btmp`, `lastlog` — 640

### User & Session Security
- Umask set to `027` in `/etc/profile`, `/etc/bash.bashrc`, `/etc/login.defs`, `/etc/init.d/rc`
- Shell idle timeout: 15 minutes (`TMOUT=900` in `/etc/profile.d/`)
- `su` command restricted to the `wheel` group
- Compiler tools (gcc, cc) restricted to the `compilers` group
- Process accounting enabled (acct)
- System statistics enabled (sysstat)

### Services Disabled
- avahi-daemon
- cups
- isc-dhcp-server / isc-dhcp-server6
- nfs-server
- rpcbind
- rsync
- snmpd

### Kernel Modules Blocked
See [Disabled Kernel Modules](#disabled-kernel-modules) for the full list.

### USB Storage
- USB mass storage disabled via `/etc/modprobe.d/disable-usb-storage.conf`
- See [Re-enabling USB Storage](#re-enabling-usb-storage) to temporarily or permanently restore access

### Monitoring & Integrity
- AIDE database initialized; daily check via `/etc/cron.daily/aide-check`
- RKHunter installed, configured, and run daily via cron
- Lynis audit run before and after hardening
- debsums package integrity verification
- Log rotation compression enabled
- Log file permissions tightened

### UFW Firewall
- Default policy: deny all incoming, allow all outgoing
- SSH port auto-detected from `sshd_config` and allowed
- UFW enabled with `--force` (non-interactive)
- Skip with `--skip-ufw` if you manage your own firewall

### Automatic Security Updates
- `unattended-upgrades` installed and enabled
- Configured to apply security patches daily
- Auto-reboot disabled — patches apply without surprise reboots
- Root receives email reports on changes
- Stale package lists cleaned weekly

### Secure Mount Options
- `/tmp` — mounted with `noexec,nosuid,nodev` (prevents executing binaries from temp space)
- `/dev/shm` — mounted with `noexec,nosuid,nodev` (prevents shared memory abuse)
- Both are remounted immediately; `/etc/fstab` updated for persistence across reboots

### Sudo Hardening
- Credential cache timeout: 15 minutes (`timestamp_timeout=15`)
- Max password attempts: 3 (`passwd_tries=3`)
- Full session I/O logging to `/var/log/sudo-io/`
- Audit log written to `/var/log/sudo.log`
- Bad-password attempts trigger mail alert to root (`mail_badpass`)
- Password prompt never echoes (`!visiblepw`)
- Configuration written to `/etc/sudoers.d/hardening`, validated with `visudo -c`

### Network Security
- Fail2Ban installed and configured with custom jail rules
- IPv6 support in Fail2Ban configured
- Legal banners set in `/etc/issue` and `/etc/issue.net`
- TCP timestamps disabled (prevents uptime fingerprinting)
- TCP RFC1337 enabled (TIME-WAIT assassination protection)

---

## Prerequisites

### Required
- **OS**: Debian 10+ or Ubuntu 18.04+
- **Access**: Root or sudo
- **Disk**: ~500 MB free for logs and packages

### Remote Servers (VPS)
- Root should have SSH keys configured before running
- Keep your current SSH session open while the script tests the new admin login

### Local VMs / Workstations
- Use `--local-vm` to skip SSH key checks and keep password auth enabled

---

## Quick Start

### 1. Clone or download

```bash
git clone https://github.com/Z-A-P-P-I-T/Debian-Ubuntu-Security-Hardening-Script.git
cd Debian-Ubuntu-Security-Hardening-Script
chmod +x debian-ubuntu-hardening-script.sh
```

Or download directly:

```bash
curl -L -o debian-ubuntu-hardening-script.sh \
  https://raw.githubusercontent.com/Z-A-P-P-I-T/Debian-Ubuntu-Security-Hardening-Script/main/debian-ubuntu-hardening-script.sh
chmod +x debian-ubuntu-hardening-script.sh
```

### 2. Run

```bash
sudo bash debian-ubuntu-hardening-script.sh
```

### 3. Save the generated credentials

The script creates a secure admin user and prints the credentials once:

```
Username: sec_a3f9c2b1
Password: xK8#mP2$vR9@wL4!qT7y
```

> **Save these immediately** — they are not stored anywhere on the system.

---

## Usage Modes

### Interactive (default)
Prompts before key decisions. Recommended for first-time use and production servers.

```bash
sudo bash debian-ubuntu-hardening-script.sh
```

### Fully automated
No prompts. Good for CI/CD pipelines and scripted deployments.

```bash
sudo bash debian-ubuntu-hardening-script.sh --disable-root-login
```

### Safety mode
Keeps root SSH login enabled. Use when you want a cautious first pass.

```bash
sudo bash debian-ubuntu-hardening-script.sh --keep-root-login
```

### Local VM / workstation mode
Skips SSH key checks and keeps password authentication active.

```bash
sudo bash debian-ubuntu-hardening-script.sh --local-vm
```

---

## Command-Line Flags

| Flag | Description | Use case |
|------|-------------|----------|
| `--disable-root-login` | Disable root SSH login automatically | Automation / CI |
| `--keep-root-login` | Keep root SSH login enabled | Cautious/staged rollout |
| `--local-vm` | Skip SSH key checks, keep password auth | Local VM or workstation |
| `--skip-user-creation` | Do not create a new admin user | Existing admin already configured |
| `--enable-pam-lockout` | Enable PAM account lockout (10 failed attempts) | High-security environments |
| `--skip-ufw` | Skip UFW firewall configuration | Systems with an existing firewall |

Example combining flags:

```bash
sudo bash debian-ubuntu-hardening-script.sh --local-vm --keep-root-login
```

---

## What the Script Does

### Phase 1 — Pre-Hardening Checks
- Verifies root/sudo access
- Checks for Debian/Ubuntu OS
- Verifies required commands are available
- Checks root SSH key configuration (unless `--local-vm`)
- Creates a secure randomized admin user and tests sudo access
- Sets up the logging directory structure

### Phase 2 — Package Installation
- Updates all system packages
- Installs core security tools: Lynis, AIDE, RKHunter, Fail2Ban, auditd, libpam-pwquality, libpam-tmpdir, needrestart, acct, sysstat, debsums, apt-show-versions, bsd-mailx
- Installs Lynis-recommended extras: apparmor, apparmor-utils, debsecan, debian-goodies
- Enables process accounting (acct) and system statistics (sysstat) services

### Phase 3 — Baseline Security Scan
- Runs a full Lynis audit and saves the report

### Phase 4 — Security Configuration
- Deploys Fail2Ban with custom jail configuration and IPv6 support
- Deploys auditd rules (`/etc/audit/rules.d/hardening.rules`)
- Applies kernel sysctl hardening (`/etc/sysctl.d/99-hardening.conf`)
- Configures password aging in `/etc/login.defs`
- Installs and configures libpam-pwquality (complexity, length, history)
- Initializes AIDE file integrity database
- Sets legal banners in `/etc/issue` and `/etc/issue.net`
- Restricts compiler access to the `compilers` group

### Phase 5 — Auto-Remediation
Runs a suite of auto-fix functions:

**SSH hardening** — applies all SSH configuration changes listed above

**File permissions** — corrects permissions on passwd, shadow, group, gshadow, crontab, cron directories, and SSH keys

**Kernel module blocking** — writes `/etc/modprobe.d/hardening.conf` and attempts to unload already-loaded modules

**Umask hardening** — sets `027` in all relevant locations

**Additional network parameters** — appends extra sysctl values for redirect, RA, dmesg, ptrace, and core dump hardening

**Lynis recommendations** — enables AppArmor, disables core dumps, tightens log permissions, disables unnecessary services, sets up AIDE cron, disables USB storage, adds SHA512 password hashing, configures optional PAM lockout, restricts su to wheel group, sets 15-minute session timeout, enables log rotation compression, adds extended auditd rules, applies BPF/kexec kernel hardening

**UFW firewall** — installs ufw, sets default deny incoming / allow outgoing, auto-detects SSH port and allows it, enables firewall (skipped if `--skip-ufw`)

**Automatic security updates** — installs and configures `unattended-upgrades` for daily security patches with mail reporting

**Secure mount options** — adds `noexec,nosuid,nodev` to `/tmp` and `/dev/shm` in `/etc/fstab` and remounts immediately

**Sudo hardening** — writes `/etc/sudoers.d/hardening` with I/O logging, credential timeout, and bad-password alerts; validated with `visudo -c` before applying

### Phase 6 — Verification
- Runs a second Lynis audit to measure improvement
- Runs debsums to verify package integrity
- Runs a full RKHunter scan
- Sets up daily RKHunter cron job
- Verifies AIDE database
- Verifies Fail2Ban is active
- Prints a final summary report

---

## Kernel Parameters Applied

All parameters are written to `/etc/sysctl.d/99-hardening.conf`.

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `net.ipv4.tcp_syncookies` | `1` | SYN flood protection |
| `net.ipv4.ip_forward` | `0` | Disable IP forwarding |
| `net.ipv4.conf.all.accept_redirects` | `0` | Reject ICMP redirects |
| `net.ipv4.conf.default.accept_redirects` | `0` | Reject ICMP redirects |
| `net.ipv4.conf.all.send_redirects` | `0` | Do not send redirects |
| `net.ipv4.conf.default.send_redirects` | `0` | Do not send redirects |
| `net.ipv4.conf.all.secure_redirects` | `0` | Reject secure ICMP redirects |
| `net.ipv4.conf.all.accept_source_route` | `0` | Disable source routing |
| `net.ipv4.conf.all.rp_filter` | `1` | Reverse path filtering |
| `net.ipv4.conf.all.log_martians` | `1` | Log martian packets |
| `net.ipv4.icmp_echo_ignore_broadcasts` | `1` | Ignore broadcast pings |
| `net.ipv4.icmp_ignore_bogus_error_responses` | `1` | Ignore bogus ICMP errors |
| `net.ipv6.conf.all.accept_ra` | `0` | Disable IPv6 router advertisements |
| `net.ipv6.conf.default.accept_ra` | `0` | Disable IPv6 router advertisements |
| `kernel.dmesg_restrict` | `1` | Restrict dmesg to root |
| `kernel.kptr_restrict` | `2` | Hide kernel pointers |
| `kernel.yama.ptrace_scope` | `1` | Restrict ptrace to parent processes |
| `kernel.core_uses_pid` | `1` | Append PID to core dump filenames |
| `kernel.core_pattern` | `/dev/null` | Discard core dumps |
| `fs.suid_dumpable` | `0` | Disable core dumps for setuid processes |
| `kernel.kexec_load_disabled` | `1` | Prevent live kernel replacement |
| `kernel.unprivileged_bpf_disabled` | `1` | Restrict BPF to root |
| `net.core.bpf_jit_harden` | `2` | Harden BPF JIT compiler |
| `net.ipv4.tcp_timestamps` | `0` | Disable TCP timestamps (prevents uptime fingerprinting) |
| `net.ipv4.tcp_rfc1337` | `1` | Protect against TCP TIME-WAIT assassination attacks |

---

## Disabled Kernel Modules

Written to `/etc/modprobe.d/hardening.conf`. The script also attempts to unload modules that are already loaded.

**Uncommon network protocols:**
- `dccp` — Datagram Congestion Control Protocol
- `sctp` — Stream Control Transmission Protocol
- `rds` — Reliable Datagram Sockets
- `tipc` — Transparent Inter-Process Communication

**Uncommon filesystems:**
- `cramfs`
- `freevxfs`
- `jffs2`
- `hfs`
- `hfsplus`
- `udf`

**Other:**
- `firewire-core` — FireWire bus support
- `usb-storage` — USB mass storage (written to `/etc/modprobe.d/disable-usb-storage.conf`)

---

## Disabled Services

The following services are stopped and disabled if present:

| Service | Reason |
|---------|--------|
| `avahi-daemon` | mDNS/DNS-SD — unnecessary network exposure |
| `cups` | Printing service — not needed on servers |
| `isc-dhcp-server` / `isc-dhcp-server6` | DHCP server — rarely needed |
| `nfs-server` | Network file sharing — significant attack surface |
| `rpcbind` | RPC port mapper — dependency of NFS |
| `rsync` | Remote sync daemon — unnecessary if not in use |
| `snmpd` | SNMP daemon — often misconfigured, high exposure |

---

## Auditd Rules

Written to `/etc/audit/rules.d/hardening.rules` and loaded with `augenrules`.

| Watch target | Permissions | Key |
|---|---|---|
| `/var/log/lastlog` | write, attribute | `logins` |
| `/var/run/faillock/` | write, attribute | `logins` |
| `/etc/hosts` | write, attribute | `network_modifications` |
| `/etc/network/` | write, attribute | `network_modifications` |
| `/usr/bin/passwd` | execute | `passwd_modification` |
| `/usr/bin/chsh` | execute | `shell_modification` |
| `/usr/sbin/groupadd` | execute | `group_modification` |
| `/usr/sbin/groupmod` | execute | `group_modification` |
| `/usr/sbin/addgroup` | execute | `group_modification` |
| `/usr/sbin/useradd` | execute | `user_modification` |
| `/usr/sbin/usermod` | execute | `user_modification` |
| `/usr/sbin/adduser` | execute | `user_modification` |

---

## File Permissions Hardened

| File / Directory | Permission |
|---|---|
| `/etc/passwd` | 644 |
| `/etc/shadow` | 640 |
| `/etc/group` | 644 |
| `/etc/gshadow` | 640 |
| `/etc/crontab` | 600 |
| `/etc/cron.hourly`, `daily`, `weekly`, `monthly`, `cron.d` | 700 |
| SSH private keys | 600 |
| SSH public keys | 644 |
| `/var/log/wtmp` | 640 |
| `/var/log/btmp` | 640 |
| `/var/log/lastlog` | 640 |

---

## Safety Features

- **Pre-flight checks** — validates OS, root access, and required tools before making any changes
- **SSH session protection** — prompts you to test the new admin login in a separate terminal before disabling root
- **Automatic rollback** — restores the SSH config backup if the test connection fails
- **Config backups** — every modified config file is backed up before changes are applied
- **Idempotent** — safe to re-run; each step checks current state before applying
- **Step-by-step logging** — every action is logged with timestamps for audit trails

---

## After Running the Script

1. Open a **new terminal** and log in as the generated admin user to verify access
2. Confirm sudo works: `sudo whoami`
3. Review the Lynis before/after reports in `/var/log/`
4. Check the AIDE database was initialized: `sudo aide --check`
5. Verify Fail2Ban is active: `sudo fail2ban-client status`
6. Store the generated credentials securely (password manager)

---

## Re-enabling USB Storage

USB mass storage is disabled by default. To re-enable it temporarily (until next reboot):

```bash
sudo modprobe --ignore-install usb_storage
```

To make it permanent again, remove the blocking file:

```bash
sudo rm /etc/modprobe.d/disable-usb-storage.conf
sudo modprobe usb_storage
```

---

## Logs and Reports

All logs are written under `/var/log/` in a timestamped directory created by the script.

| Log | Contents |
|-----|----------|
| `tools/rkhunter.log` | RKHunter scan results |
| `tools/aide.log` | AIDE initialization and check output |
| `tools/fail2ban.log` | Fail2Ban configuration log |
| `tools/auditd.log` | Auditd setup log |
| Lynis reports | Before and after audit reports |

---

## Verification

Run these after the script completes to confirm the hardening is in effect:

```bash
# Security audit score
sudo lynis audit system

# Rootkit scan
sudo rkhunter --check

# File integrity check
sudo aide --check

# Fail2Ban status
sudo fail2ban-client status

# UFW firewall status
sudo ufw status verbose

# Check applied sysctl values
sudo sysctl -a | grep -E 'syncookies|dmesg_restrict|kptr_restrict|bpf|tcp_timestamps|tcp_rfc1337'

# Confirm USB storage is blocked
lsmod | grep usb_storage   # should return nothing

# Verify secure mount options
mount | grep -E '/tmp|/dev/shm'

# Check automatic updates are active
systemctl status unattended-upgrades

# Confirm sudo logging is active
sudo cat /var/log/sudo.log
```

---

## Troubleshooting

**SSH locked out**
Keep your original SSH session open until you have confirmed the new admin account can log in. If the script detects a failure it will restore the SSH config backup automatically.

**USB drive not detected**
Run `sudo modprobe --ignore-install usb_storage` — see [Re-enabling USB Storage](#re-enabling-usb-storage).

**AppArmor profile errors**
The script enforces profiles selectively for stability. If a specific daemon is being denied, check `sudo aa-status` and adjust the profile with `sudo aa-complain <profile>`.

**AIDE shows unexpected changes**
This is normal after running the script since it modifies many system files. Re-initialize the database after hardening: `sudo aideinit && sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db`.

**Service fails to start after hardening**
Check if the service was disabled by the script (`systemctl status <service>`). Services in the [Disabled Services](#disabled-services) list are stopped intentionally. Re-enable with `sudo systemctl enable --now <service>` if needed.

**UFW blocking a port I need**
List current rules with `sudo ufw status numbered`. Add a rule with `sudo ufw allow <port>/<protocol>`. If you want to skip UFW entirely, re-run the script with `--skip-ufw`.

**Cannot write to /tmp or /dev/shm**
The noexec/nosuid/nodev mount options prevent binary execution from those locations but do not prevent writing. If a specific application requires execute permissions from `/tmp`, you may need to remount it without `noexec`: `sudo mount -o remount,exec /tmp`.

**Sudo sessions expiring too fast**
The default is 15 minutes. To adjust: edit `/etc/sudoers.d/hardening` and change `timestamp_timeout=15` to your preferred value. Use `sudo visudo -f /etc/sudoers.d/hardening` to edit safely.

---

## FAQ

**Does this work on Ubuntu and Debian servers?**
Yes — tested on Debian 10+ and Ubuntu 18.04+.

**Can I run it more than once?**
Yes — the script is idempotent. It checks the current state before applying each change, so re-running it is safe.

**Will this break my running services?**
The script disables a specific list of services (see [Disabled Services](#disabled-services)) that are commonly unused on servers. It does not stop web servers, databases, or application daemons. Review the list and re-enable any service you need.

**What happens to the GRUB bootloader?**
The script detects if GRUB is present and logs a recommendation to set a GRUB password manually, but does not modify GRUB configuration automatically to avoid breaking boot.

**What does `--enable-pam-lockout` do exactly?**
It configures PAM to lock an account for a period after 10 consecutive failed login attempts, using either `pam_faillock` (newer systems) or `pam_tally2` (older systems) depending on what is available.

---

## Contributing

Issues and pull requests are welcome. Please test changes against both Debian and Ubuntu before submitting.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

This script makes significant and wide-ranging security changes to your system. Review the code before running it, and always test in a non-production environment first. The author is not responsible for service disruptions or lockouts resulting from use of this script.

---

## Tested On

All functions have been manually verified on live systems. The table below tracks confirmed working environments.

| OS | Version | Kernel | Date | Scope |
|---|---|---|---|---|
| Ubuntu | 24.04.4 LTS (Noble) | 6.17.0-29-generic | 2026-06 | Full script + all new functions (UFW, unattended-upgrades, mount hardening, sudo hardening) verified individually on live system |

If you have tested on Debian or an older Ubuntu release, contributions to this table are welcome.

---

## Changelog

### Latest
- Added UFW firewall with deny-by-default policy and auto-detected SSH port (`--skip-ufw` flag to opt out)
- Added `unattended-upgrades` for daily automatic security patch application
- Added secure mount options for `/tmp` and `/dev/shm` (`noexec,nosuid,nodev`)
- Added sudo hardening with full I/O session logging and credential timeout
- Added TCP timestamp disabling and RFC1337 protection to sysctl hardening
- Documented all previously undocumented hardening steps in README (auditd rules, kernel params, disabled services/modules, file permissions, PAM, AppArmor, umask, session timeout)
- Fixed git remote misconfiguration

---

## Author

Created by Kimi Autto — [github.com/Z-A-P-P-I-T](https://github.com/Z-A-P-P-I-T)
