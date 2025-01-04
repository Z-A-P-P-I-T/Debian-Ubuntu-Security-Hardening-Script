#!/bin/bash

# Ensure the script is run with root privileges
if [[ "$EUID" -ne 0 ]]; then
    echo "This script must be run as root. Please use 'sudo'."
    exit 1
fi

# Log file
LOGFILE="/var/log/server_hardening.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "Starting server hardening script at $(date)..."

# Error handling
set -euo pipefail
trap 'echo "Error on line $LINENO. Check $LOGFILE for details." | tee -a $LOGFILE; exit 1' ERR

# Function to log success
log_success() {
    local step="$1"
    echo "✔ [$step] completed successfully at $(date)." | tee -a $LOGFILE
}

# Function to log failure
log_failure() {
    local step="$1"
    echo "✖ [$step] failed at $(date). Check $LOGFILE for details." | tee -a $LOGFILE
    exit 1
}

# Function to install a package
install_package() {
    local package="$1"
    echo "Checking if $package is installed..." | tee -a $LOGFILE
    if ! dpkg -l | grep -q "^ii  $package"; then
        echo "Installing $package..." | tee -a $LOGFILE
        apt-get install -y "$package" || log_failure "Installing $package"
    else
        echo "$package is already installed." | tee -a $LOGFILE
    fi
}

# Update and upgrade system
echo "Updating and upgrading system..." | tee -a $LOGFILE
apt-get update && apt-get full-upgrade -y || log_failure "System update and upgrade"
log_success "System update and upgrade"

# Install essential packages
echo "Installing essential packages..." | tee -a $LOGFILE
ESSENTIAL_PACKAGES=("perl" "wget" "curl" "lynx" "lynis" "fail2ban" "ufw" "auditd" "rkhunter" "apt-listchanges" "debsums" "bsd-mailx")
for package in "${ESSENTIAL_PACKAGES[@]}"; do
    install_package "$package"
done
log_success "Essential packages installation"

# Run Lynis audit
echo "Running Lynis audit..." | tee -a $LOGFILE
lynis audit system --quiet --logfile /var/log/lynis.log --report-file /var/log/lynis-report.dat || log_failure "Lynis audit"
log_success "Lynis audit"

# Configure Fail2Ban
echo "Configuring Fail2Ban..." | tee -a $LOGFILE
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sed -i '/\[DEFAULT\]/a ignoreip = 127.0.0.1/8' /etc/fail2ban/jail.local
sed -i '/\[DEFAULT\]/a bantime = 3600' /etc/fail2ban/jail.local
systemctl enable fail2ban
systemctl restart fail2ban || log_failure "Fail2Ban configuration"
log_success "Fail2Ban configuration"

# Configure UFW
echo "Configuring UFW..." | tee -a $LOGFILE
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw enable || log_failure "UFW configuration"
log_success "UFW configuration"

# Update RKHunter dynamically with online validation
update_rkhunter() {
    echo "Updating RKHunter..." | tee -a $LOGFILE

    # Ensure the RKHunter config is correct
    sed -i 's|WEB_CMD="/bin/true"|WEB_CMD=""|' /etc/rkhunter.conf

    # Try updating RKHunter automatically
    if rkhunter --update; then
        echo "RKHunter database updated successfully." | tee -a $LOGFILE
    else
        echo "RKHunter database update failed. Validating paths and performing manual update..." | tee -a $LOGFILE

        # Define base URL
        local base_url="https://sourceforge.net/projects/rkhunter/files"
        local files=("mirrors.dat" "programs_bad.dat" "backdoorports.dat" "i18n.versions")

        # Validate and download each file
        mkdir -p /var/lib/rkhunter/db
        for file in "${files[@]}"; do
            # Construct the file URL dynamically
            local file_url="$base_url/latest/download/$file"
            
            # Check if the file exists online
            if curl -Ifs "$file_url"; then
                echo "Verified $file_url exists. Downloading..." | tee -a $LOGFILE
                if curl -f -s -o "/var/lib/rkhunter/db/$file" "$file_url"; then
                    echo "$file downloaded successfully." | tee -a $LOGFILE
                else
                    echo "Failed to download $file from $file_url." | tee -a $LOGFILE
                fi
            else
                echo "File $file not found at $file_url. Skipping." | tee -a $LOGFILE
            fi
        done

        # Update file properties
        if rkhunter --propupd; then
            echo "RKHunter property update completed successfully." | tee -a $LOGFILE
        else
            echo "RKHunter property update failed. Check logs for details." | tee -a $LOGFILE
        fi
    fi
}
update_rkhunter

# Apply sysctl hardening
echo "Applying sysctl hardening..." | tee -a $LOGFILE
cat <<EOF >/etc/sysctl.d/99-hardening.conf
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
EOF
sysctl --system || log_failure "Sysctl hardening"
log_success "Sysctl hardening"

# Harden password policies
echo "Configuring password policies..." | tee -a $LOGFILE
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^UMASK.*/UMASK   027/' /etc/login.defs || log_failure "Password policy hardening"
log_success "Password policy hardening"

# Disable unnecessary protocols
echo "Disabling unnecessary protocols..." | tee -a $LOGFILE
for protocol in dccp sctp rds tipc; do
    echo "blacklist $protocol" >> /etc/modprobe.d/blacklist.conf
done || log_failure "Disabling unnecessary protocols"
log_success "Disabling unnecessary protocols"

# Disable core dumps
echo "Disabling core dumps..." | tee -a $LOGFILE
echo '* hard core 0' >> /etc/security/limits.conf || log_failure "Disabling core dumps"
log_success "Disabling core dumps"

# Configure AuditD
echo "Setting up AuditD..." | tee -a $LOGFILE
cat <<EOF >/etc/audit/rules.d/hardening.rules
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
EOF
augenrules --load
systemctl enable auditd
systemctl restart auditd || log_failure "AuditD configuration"
log_success "AuditD configuration"

# Finalize
echo "Server hardening script completed successfully at $(date)." | tee -a $LOGFILE
