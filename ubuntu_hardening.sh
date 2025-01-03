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
        echo "$package is already installed."
    fi
}

# Function to run Lynis audit
run_lynis_audit() {
    echo "Running Lynis system audit..."
    install_if_missing "lynis"

    lynis audit system --quiet --logfile /var/log/lynis.log --report-file /var/log/lynis-report.dat || {
        echo "Lynis audit failed. Check /var/log/lynis.log for details."
        return 1
    }
    echo "Lynis audit completed."
}

# Function to configure Fail2Ban
update_fail2ban() {
    echo "Updating Fail2Ban..."
    install_if_missing "fail2ban"

    local config_url="https://raw.githubusercontent.com/fail2ban/fail2ban/master/config/jail.conf"
    if curl -f -s "$config_url" -o /etc/fail2ban/jail.local; then
        echo "Downloaded latest Fail2Ban configuration."
    else
        echo "Failed to download Fail2Ban configuration. Using default."
        cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    fi

    systemctl enable fail2ban
    systemctl restart fail2ban
}

# Function to update RKHunter
update_rkhunter() {
    echo "Updating RKHunter..."
    install_if_missing "rkhunter"

    # Query for the latest RKHunter version dynamically
    local base_url="https://sourceforge.net/projects/rkhunter/files/rkhunter"
    local latest_version
    latest_version=$(curl -s "$base_url" | grep -oP 'rkhunter/\K[\d.]+(?=/)' | sort -V | tail -n 1)

    if [[ -z "$latest_version" ]]; then
        echo "Failed to determine the latest RKHunter version. Using fallback version 1.4.6."
        latest_version="1.4.6"
    fi

    echo "Latest RKHunter version: $latest_version"

    # Download required files
    local file_base_url="$base_url/$latest_version/files/"
    local files=("mirrors.dat" "programs_bad.dat" "backdoorports.dat" "i18n.versions")
    for file in "${files[@]}"; do
        local url="${file_base_url}${file}"
        local dest="/var/lib/rkhunter/db/${file}"
        if curl -f -s "$url" -o "$dest"; then
            echo "Downloaded $file."
        else
            echo "Failed to download $file. Skipping."
        fi
    done

    rkhunter --propupd
}

# Function to apply sysctl hardening
update_sysctl() {
    echo "Applying sysctl hardening..."
    local hardening_url="https://raw.githubusercontent.com/BetterLinuxSecurity/sysctl-hardening/main/sysctl.conf"
    if curl -f -s "$hardening_url" -o /etc/sysctl.d/99-hardening.conf; then
        echo "Downloaded latest sysctl hardening rules."
    else
        echo "Failed to download sysctl hardening rules."
        return 1
    fi
    sysctl --system
}

# Function to configure UFW
configure_ufw() {
    echo "Configuring UFW (firewall)..."
    install_if_missing "ufw"
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
}

# Function to update AuditD
update_auditd() {
    echo "Setting up AuditD for logging..."
    install_if_missing "auditd"

    local audit_rules_url="https://raw.githubusercontent.com/linux-audit/audit-config/master/audit.rules"
    if curl -f -s "$audit_rules_url" -o /etc/audit/rules.d/hardening.rules; then
        echo "Downloaded latest AuditD rules."
    else
        echo "Failed to download AuditD rules."
        return 1
    fi

    sudo augenrules --load
    sudo systemctl enable auditd
    sudo systemctl restart auditd
}

# Function to harden password policies
harden_password_policy() {
    echo "Configuring password policies..."
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^UMASK.*/UMASK   027/' /etc/login.defs
}

# Function to disable unnecessary protocols
disable_unnecessary_protocols() {
    echo "Disabling unnecessary protocols..."
    for protocol in dccp sctp rds tipc; do
        echo "blacklist $protocol" >> /etc/modprobe.d/blacklist.conf
    done
}

# Function to disable core dumps
disable_core_dumps() {
    echo "Disabling core dumps..."
    echo '* hard core 0' >> /etc/security/limits.conf
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

# Apply all hardening steps
update_fail2ban
update_rkhunter
update_sysctl
configure_ufw
update_auditd
harden_password_policy
disable_unnecessary_protocols
disable_core_dumps
run_lynis_audit

# Final message
echo "Comprehensive server hardening script completed successfully. Please review logs for details."
