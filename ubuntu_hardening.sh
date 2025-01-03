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

echo "Starting server hardening script..."

# Update and upgrade system
echo "Updating and upgrading system..."
apt update && apt upgrade -y

# Pre-configure Postfix to avoid prompts
echo "Pre-configuring Postfix for 'No configuration' mode..."
debconf-set-selections <<< "postfix postfix/main_mailer_type select No configuration"
debconf-set-selections <<< "postfix postfix/mailname string localhost"

# Install Postfix in non-interactive mode
echo "Installing Postfix in 'No configuration' mode..."
DEBIAN_FRONTEND=noninteractive apt install -y postfix
systemctl restart postfix

# Install essential packages
ESSENTIAL_PACKAGES="lynis libpam-tmpdir apt-listchanges needrestart rkhunter bsd-mailx apt-show-versions debsums"
echo "Installing essential packages: $ESSENTIAL_PACKAGES"
apt install -y $ESSENTIAL_PACKAGES

# Run Lynis scan
echo "Running Lynis scan..."
lynis audit system --quiet --logfile /var/log/lynis.log --report-file /var/log/lynis-report.dat > /tmp/lynis-output.txt

# Set up fail2ban
echo "Setting up fail2ban..."
if apt install -y fail2ban; then
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

    # Check if IPv6 is enabled
    if [ -n "$(ip -6 addr show scope global)" ]; then
        echo "IPv6 is enabled. Keeping IPv6 support in Fail2ban."
    else
        echo "IPv6 is not in use. Disabling IPv6 support in Fail2ban."
        sed -i '/\[DEFAULT\]/a allowipv6 = no' /etc/fail2ban/jail.local
    fi

    systemctl enable fail2ban
    systemctl start fail2ban
else
    echo "Fail2ban installation failed. Skipping..."
fi

# Enable sysstat for accounting
echo "Enabling sysstat..."
apt install -y sysstat
systemctl enable sysstat
systemctl start sysstat

# Set up auditd
echo "Setting up auditd..."
if apt install -y auditd; then
    echo "-w /etc/passwd -p wa -k passwd_changes" | tee /etc/audit/rules.d/passwd_changes.rules
    echo "-w /etc/group -p wa -k group_changes" | tee /etc/audit/rules.d/group_changes.rules
    echo "-w /etc/shadow -p wa -k shadow_changes" | tee /etc/audit/rules.d/shadow_changes.rules
    echo "-w /var/log/ -p wa -k log_changes" | tee /etc/audit/rules.d/log_changes.rules
    augenrules --load
    systemctl enable auditd
    systemctl start auditd
else
    echo "Auditd installation failed. Skipping..."
fi

# Install and configure rkhunter
echo "Installing and configuring rkhunter..."
apt install -y rkhunter
sed -i 's|^WEB_CMD=.*|WEB_CMD=""|' /etc/rkhunter.conf

echo "Updating rkhunter data files..."
if ! rkhunter --update; then
    echo "RKHunter update failed. Attempting manual update..."
    # Create necessary directories
    mkdir -p /var/lib/rkhunter/db/i18n
    echo "English language file placeholder" > /var/lib/rkhunter/db/i18n/en

    # Download updated files
    wget -O /var/lib/rkhunter/db/mirrors.dat https://downloads.sourceforge.net/project/rkhunter/rkhunter/1.4.6/files/mirrors.dat || echo "Failed to download mirrors.dat."
    wget -O /var/lib/rkhunter/db/programs_bad.dat https://downloads.sourceforge.net/project/rkhunter/rkhunter/1.4.6/files/programs_bad.dat || echo "Failed to download programs_bad.dat."
    wget -O /var/lib/rkhunter/db/backdoorports.dat https://downloads.sourceforge.net/project/rkhunter/rkhunter/1.4.6/files/backdoorports.dat || echo "Failed to download backdoorports.dat."
    wget -O /var/lib/rkhunter/db/i18n.versions https://downloads.sourceforge.net/project/rkhunter/rkhunter/1.4.6/files/i18n.versions || echo "Failed to download i18n.versions."
    
    chmod 644 /var/lib/rkhunter/db/*
fi
rkhunter --propupd

# Configure SSH banner only if OpenSSH is installed
if [ -f /etc/ssh/sshd_config ]; then
    echo "Configuring SSH legal banner..."
    sed -i 's|#Banner none|Banner /etc/issue.net|' /etc/ssh/sshd_config
    systemctl restart sshd
else
    echo "OpenSSH is not installed. Skipping SSH configuration."
fi

# Configure legal banners
echo "Configuring legal banners..."
echo "Authorized access only. Unauthorized access is prohibited." | tee /etc/issue
echo "Authorized access only. Unauthorized access is prohibited." | tee /etc/issue.net

# Configure password settings
echo "Configuring password settings..."
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^UMASK.*/UMASK   027/' /etc/login.defs

# Disable core dumps
echo "Disabling core dumps..."
echo '* hard core 0' | tee -a /etc/security/limits.conf

# Recommend partitioning
echo "Consider adding separate partitions for /home, /tmp, and /var. This requires manual intervention."

# Disable unnecessary protocols
echo "Disabling unnecessary protocols..."
for protocol in dccp sctp rds tipc; do
    echo "blacklist $protocol" | tee -a /etc/modprobe.d/blacklist.conf
done

# Enable process accounting
echo "Enabling process accounting..."
apt install -y acct
systemctl enable acct
systemctl start acct

# Install AIDE for file integrity monitoring
echo "Installing AIDE..."
apt install -y aide
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

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

# Restrict compiler access
echo "Restricting compiler access..."
if [ -f /usr/bin/gcc ]; then
    chmod o-rx /usr/bin/gcc
else
    echo "GCC is not installed. Skipping GCC restrictions."
fi

if [ -f /usr/bin/cc ]; then
    chmod o-rx /usr/bin/cc
else
    echo "CC is not installed. Skipping CC restrictions."
fi

# Check and restart services after library updates
if command -v needrestart >/dev/null; then
    echo "Checking and restarting services after updates..."
    needrestart -r a
else
    echo "Needrestart is not installed. Skipping..."
fi

# Set up UFW (firewall)
echo "Setting up UFW..."
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw enable

# Final message
echo "Security hardening script completed. Review manual steps and verify changes."
