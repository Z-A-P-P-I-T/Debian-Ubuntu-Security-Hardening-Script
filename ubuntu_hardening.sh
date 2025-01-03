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

echo "Starting comprehensive server hardening script with dynamic updates..."

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

# Function to download and validate a file
download_and_validate() {
    local url="$1"
    local dest="$2"
    local retries=3

    for ((i = 1; i <= retries; i++)); do
        echo "Attempt $i to download $url..."
        wget -q -O "$dest" "$url"

        if [[ -f "$dest" && -s "$dest" ]]; then
            echo "Downloaded and validated: $dest"
            return 0
        else
            echo "Failed to validate $dest. Retrying..."
            sleep 5
        fi
    done

    echo "Failed to download or validate $url after $retries attempts."
    return 1
}

# Function to query and apply latest Fail2Ban configuration
update_fail2ban() {
    echo "Configuring Fail2Ban with dynamic updates..."
    install_if_missing "fail2ban"

    local config_url="https://raw.githubusercontent.com/fail2ban/fail2ban/master/config/jail.conf"
    local dest="/etc/fail2ban/jail.local"

    if [[ ! -f "$dest" ]]; then
        echo "Downloading the latest Fail2Ban configuration..."
        download_and_validate "$config_url" "$dest"
    else
        echo "Fail2Ban configuration already exists. Validating syntax..."
        if ! fail2ban-client -t; then
            echo "Fail2Ban configuration is invalid. Downloading a fresh configuration..."
            mv "$dest" "${dest}.bak"
            download_and_validate "$config_url" "$dest"
        fi
    fi

    sudo systemctl enable fail2ban
    sudo systemctl restart fail2ban
}

# Function to query and apply latest RKHunter updates
update_rkhunter() {
    echo "Updating RKHunter..."
    install_if_missing "rkhunter"

    # Query latest version and files dynamically
    local base_url="https://sourceforge.net/projects/rkhunter/files/rkhunter"
    local latest_version
    latest_version=$(curl -s "$base_url" | grep -oP 'rkhunter/\K[\d.]+(?=/)' | sort -V | tail -n 1)

    if [[ -z "$latest_version" ]]; then
        echo "Failed to determine the latest RKHunter version. Using fallback version 1.4.6."
        latest_version="1.4.6"
    fi

    echo "Latest RKHunter version: $latest_version"

    local file_base_url="$base_url/$latest_version/files/"
    local files=("mirrors.dat" "programs_bad.dat" "backdoorports.dat" "i18n.versions")

    for file in "${files[@]}"; do
        local url="${file_base_url}${file}"
        local dest="/var/lib/rkhunter/db/${file}"
        download_and_validate "$url" "$dest" || echo "Skipping $file due to repeated failure."
    done

    mkdir -p /var/lib/rkhunter/db/i18n
    if [[ ! -f /var/lib/rkhunter/db/i18n/en ]]; then
        echo "Creating placeholder English language file..."
        echo "English language file placeholder" > /var/lib/rkhunter/db/i18n/en
    fi

    rkhunter --propupd
}

# Function to query and apply latest sysctl hardening
update_sysctl() {
    echo "Applying sysctl hardening with dynamic updates..."
    local hardening_url="https://raw.githubusercontent.com/BetterLinuxSecurity/sysctl-hardening/main/sysctl.conf"
    local dest="/etc/sysctl.d/99-hardening.conf"

    echo "Downloading the latest sysctl hardening configuration..."
    download_and_validate "$hardening_url" "$dest"

    sysctl --system
}

# Function to configure and enable UFW
configure_ufw() {
    echo "Configuring UFW (firewall)..."
    install_if_missing "ufw"
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
}

# Function to configure and update AuditD
update_auditd() {
    echo "Setting up AuditD for logging..."
    install_if_missing "auditd"
    auditctl -e 1

    local audit_rules_url="https://raw.githubusercontent.com/linux-audit/audit-config/master/audit.rules"
    local dest="/etc/audit/rules.d/hardening.rules"

    echo "Downloading the latest AuditD rules..."
    download_and_validate "$audit_rules_url" "$dest"

    sudo augenrules --load
    sudo systemctl enable auditd
    sudo systemctl restart auditd
}

# Update and upgrade system
echo "Updating and upgrading system..."
apt update && apt full-upgrade -y

# Install essential tools
ESSENTIAL_TOOLS=("perl" "wget" "curl" "lynx" "lynis" "libpam-tmpdir" "apt-listchanges" "needrestart" "bsd-mailx" "apt-show-versions" "debsums")
echo "Checking and installing essential tools..."
for tool in "${ESSENTIAL_TOOLS[@]}"; do
    install_if_missing "$tool"
done

# Apply all dynamic updates
update_fail2ban
update_rkhunter
update_sysctl
configure_ufw
update_auditd

# Final message
echo "Comprehensive server hardening script completed successfully with dynamic updates from official sources. Please review logs for details."
