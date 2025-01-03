#!/bin/bash

# Ensure the script is run with root privileges
if [[ "$EUID" -ne 0 ]]; then
    echo "This script must be run as root. Please use 'sudo' or log in as root."
    exit 1
fi

# Enable strict error handling
set -euo pipefail
trap 'echo "Error on line $LINENO"; exit 1' ERR

# Log file
LOGFILE="/var/log/hardening_script.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "Starting comprehensive server hardening script..."

# Function to check and install a package
install_if_missing() {
    local package="$1"
    if ! dpkg -l | grep -q "^ii  $package"; then
        echo "$package is not installed. Installing..."
        apt install -y "$package"
    else
        echo "$package is already installed. Skipping..."
    fi
}

# Update and upgrade system
echo "Updating and upgrading system..."
apt update && apt full-upgrade -y

# Install essential tools
ESSENTIAL_TOOLS=("perl" "wget" "curl" "lynx" "lynis" "libpam-tmpdir" "apt-listchanges" "needrestart" "bsd-mailx" "apt-show-versions" "debsums" "ufw" "rkhunter" "fail2ban" "auditd")
echo "Checking and installing essential tools..."
for tool in "${ESSENTIAL_TOOLS[@]}"; do
    install_if_missing "$tool"
done

# Ensure required tools are available
REQUIRED_TOOLS=("perl" "wget" "curl" "lynx" "stat" "strings" "systemctl")
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" >/dev/null; then
        echo "Error: $tool is required but not installed. Installing..."
        install_if_missing "$tool"
    fi
done

# Configure Postfix
echo "Checking Postfix..."
if dpkg -l | grep -q "^ii  postfix"; then
    echo "Postfix is already installed."
else
    echo "Installing Postfix in 'No configuration' mode..."
    debconf-set-selections <<< "postfix postfix/main_mailer_type select No configuration"
    debconf-set-selections <<< "postfix postfix/mailname string localhost"
    DEBIAN_FRONTEND=noninteractive apt install -y postfix
    systemctl restart postfix
fi

# Check and update Fail2Ban
echo "Checking Fail2Ban..."
install_if_missing "fail2ban"

# Validate Fail2Ban configuration
if [ -f /etc/fail2ban/jail.local ]; then
    echo "Validating existing Fail2Ban configuration..."
    if ! sudo fail2ban-client -t; then
        echo "Fail2Ban configuration is invalid. Backing up and recreating jail.local..."
        sudo mv /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
    fi
else
    echo "Creating a new Fail2Ban configuration file..."
    cat <<EOF | sudo tee /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
EOF
fi
sudo systemctl enable fail2ban
sudo systemctl restart fail2ban

# Configure and update RKHunter dynamically
echo "Checking RKHunter..."
install_if_missing "rkhunter"

# Fetch the latest version of RKHunter
BASE_URL="https://sourceforge.net/projects/rkhunter/files/rkhunter"
LATEST_VERSION=$(curl -s https://sourceforge.net/projects/rkhunter/files/ | grep -oP 'rkhunter/\K[\d.]+(?=/)' | sort -V | tail -n 1)

if [ -z "$LATEST_VERSION" ]; then
    echo "Failed to fetch the latest RKHunter version. Using fallback version 1.4.6."
    LATEST_VERSION="1.4.6"
fi

echo "Latest RKHunter version: $LATEST_VERSION"

FILE_LIST=("mirrors.dat" "programs_bad.dat" "backdoorports.dat" "i18n.versions")
for file in "${FILE_LIST[@]}"; do
    URL="https://sourceforge.net/projects/rkhunter/files/rkhunter/${LATEST_VERSION}/files/${file}"
    echo "Downloading $file from $URL"
    wget -O "/var/lib/rkhunter/db/${file}" "$URL" || echo "Failed to download $file."
done

mkdir -p /var/lib/rkhunter/db/i18n
if [ ! -f /var/lib/rkhunter/db/i18n/en ]; then
    echo "Creating placeholder English language file..."
    echo "English language file placeholder" > /var/lib/rkhunter/db/i18n/en
fi

rkhunter --propupd

# Configure and enable auditd
echo "Setting up AuditD for logging..."
install_if_missing "auditd"
auditctl -e 1
cat <<EOF | sudo tee /etc/audit/rules.d/hardening.rules
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
EOF
sudo augenrules --load
sudo systemctl enable auditd
sudo systemctl restart auditd

# Enable and configure UFW
echo "Configuring UFW (firewall)..."
install_if_missing "ufw"
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw enable

# Apply sysctl hardening
echo "Applying sysctl hardening..."
tee /etc/sysctl.d/99-hardening.conf > /dev/null <<EOF
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
kernel.randomize_va_space = 2
kernel.sysrq = 0
EOF
sysctl --system

# Final message
echo "Comprehensive server hardening script completed successfully. Please review logs for details."
