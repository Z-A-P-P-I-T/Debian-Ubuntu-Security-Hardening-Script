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

echo "Starting server hardening script with version checks..."

# Function to prompt for user confirmation
ask_user() {
    local message="$1"
    read -p "$message [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        return 0
    else
        return 1
    fi
}

# Update and upgrade system
echo "Updating and upgrading system..."
apt update && apt full-upgrade -y

# Install essential tools
ESSENTIAL_TOOLS=("perl" "wget" "curl" "lynis" "libpam-tmpdir" "apt-listchanges" "needrestart" "bsd-mailx" "apt-show-versions" "debsums" "ufw")
echo "Checking and installing essential tools..."
for tool in "${ESSENTIAL_TOOLS[@]}"; do
    if ! dpkg -l | grep -q "^ii  $tool"; then
        echo "$tool is not installed. Installing..."
        apt install -y "$tool"
    else
        echo "$tool is already installed. Skipping..."
    fi
done

# Ensure required tools are available
REQUIRED_TOOLS=("perl" "wget" "curl" "lynx" "stat" "strings" "systemctl")
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" >/dev/null; then
        echo "Error: $tool is required but not installed. Please install it manually."
        exit 1
    fi
done

# Configure Postfix
echo "Checking Postfix..."
if dpkg -l | grep -q "^ii  postfix"; then
    echo "Postfix is already installed."
else
    if ask_user "Postfix is not installed. Do you want to install Postfix?"; then
        debconf-set-selections <<< "postfix postfix/main_mailer_type select No configuration"
        debconf-set-selections <<< "postfix postfix/mailname string localhost"
        DEBIAN_FRONTEND=noninteractive apt install -y postfix
        systemctl restart postfix
    else
        echo "Skipping Postfix installation."
    fi
fi

# Check and update Fail2Ban
echo "Checking Fail2Ban..."
if dpkg -l | grep -q "^ii  fail2ban"; then
    echo "Fail2Ban is already installed."
else
    if ask_user "Fail2Ban is not installed. Do you want to install Fail2Ban?"; then
        apt install -y fail2ban
    else
        echo "Skipping Fail2Ban installation."
    fi
fi

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
if dpkg -l | grep -q "^ii  rkhunter"; then
    echo "RKHunter is already installed."
else
    if ask_user "RKHunter is not installed. Do you want to install RKHunter?"; then
        apt install -y rkhunter
    else
        echo "Skipping RKHunter installation."
    fi
fi

# Fetch the latest version of RKHunter
BASE_URL="https://sourceforge.net/projects/rkhunter/files/rkhunter"
LATEST_VERSION=$(curl -s https://sourceforge.net/projects/rkhunter/files/ | grep -oP 'rkhunter/\K[\d.]+(?=/)' | sort -V | tail -n 1)

if [ -z "$LATEST_VERSION" ]; then
    echo "Failed to fetch the latest RKHunter version. Using fallback version 1.4.6."
    LATEST_VERSION="1.4.6"
fi

echo "Latest RKHunter version: $LATEST_VERSION"
if ask_user "Do you want to update RKHunter to version $LATEST_VERSION?"; then
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
fi

# Enable and configure UFW
echo "Configuring UFW (firewall)..."
if ask_user "Do you want to configure and enable UFW?"; then
    apt install -y ufw
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
fi

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
echo "Security hardening script completed with version checks. Please review logs for details."
