#!/bin/bash

# Enable strict error handling
set -euo pipefail
trap 'echo "Error on line $LINENO"; exit 1' ERR

# Log file
LOGFILE="/var/log/hardening_script.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "Starting server hardening script..."

# Update and upgrade system
echo "Updating and upgrading system..."
sudo apt update && sudo apt upgrade -y

# Install essential packages
ESSENTIAL_PACKAGES="lynis libpam-tmpdir apt-listchanges needrestart rkhunter bsd-mailx apt-show-versions debsums"
echo "Installing essential packages: $ESSENTIAL_PACKAGES"
sudo apt install -y $ESSENTIAL_PACKAGES

# Run Lynis scan
echo "Running Lynis scan..."
sudo lynis audit system --quiet --logfile /var/log/lynis.log --report-file /var/log/lynis-report.dat > /tmp/lynis-output.txt

# Set up fail2ban
echo "Setting up fail2ban..."
if sudo apt install -y fail2ban; then
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    
    # Check if IPv6 is enabled
    if [ -n "$(ip -6 addr show scope global)" ]; then
        echo "IPv6 is enabled. Keeping IPv6 support in Fail2ban."
    else
        echo "IPv6 is not in use. Disabling IPv6 support in Fail2ban."
        sudo sed -i '/\[DEFAULT\]/a allowipv6 = no' /etc/fail2ban/jail.local
    fi

    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban
else
    echo "Fail2ban installation failed. Skipping..."
fi

# Enable sysstat for accounting
echo "Enabling sysstat..."
sudo apt install -y sysstat
sudo systemctl enable sysstat
sudo systemctl start sysstat

# Set up auditd
echo "Setting up auditd..."
if sudo apt install -y auditd; then
    echo "-w /etc/passwd -p wa -k passwd_changes" | sudo tee /etc/audit/rules.d/passwd_changes.rules
    echo "-w /etc/group -p wa -k group_changes" | sudo tee /etc/audit/rules.d/group_changes.rules
    echo "-w /etc/shadow -p wa -k shadow_changes" | sudo tee /etc/audit/rules.d/shadow_changes.rules
    echo "-w /var/log/ -p wa -k log_changes" | sudo tee /etc/audit/rules.d/log_changes.rules
    sudo augenrules --load
    sudo systemctl enable auditd
    sudo systemctl start auditd
else
    echo "Auditd installation failed. Skipping..."
fi

# Install and configure rkhunter
echo "Installing rkhunter..."
sudo apt install -y rkhunter
sudo sed -i 's|WEB_CMD="/bin/true"|WEB_CMD=""|' /etc/rkhunter.conf
echo "Updating rkhunter data files..."
sudo rkhunter --update || echo "RKHunter update failed. Check /var/log/rkhunter.log."
sudo rkhunter --propupd

# Configure legal banners
echo "Configuring legal banners..."
echo "Authorized access only. Unauthorized access is prohibited." | sudo tee /etc/issue
echo "Authorized access only. Unauthorized access is prohibited." | sudo tee /etc/issue.net
sudo sed -i 's|#Banner none|Banner /etc/issue.net|' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Configure password settings
echo "Configuring password settings..."
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sudo sed -i 's/^UMASK.*/UMASK   027/' /etc/login.defs

# Disable core dumps
echo "Disabling core dumps..."
echo '* hard core 0' | sudo tee -a /etc/security/limits.conf

# Recommend partitioning
echo "Consider adding separate partitions for /home, /tmp, and /var. This requires manual intervention."

# Disable unnecessary protocols
echo "Disabling unnecessary protocols..."
for protocol in dccp sctp rds tipc; do
    echo "blacklist $protocol" | sudo tee -a /etc/modprobe.d/blacklist.conf
done

# Enable process accounting
echo "Enabling process accounting..."
sudo apt install -y acct
sudo systemctl enable acct
sudo systemctl start acct

# Install AIDE for file integrity monitoring
echo "Installing AIDE..."
sudo apt install -y aide
sudo aideinit
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Apply sysctl hardening
echo "Applying sysctl hardening..."
sudo tee /etc/sysctl.d/99-hardening.conf > /dev/null <<EOF
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
sudo sysctl --system

# Restrict compiler access
echo "Restricting compiler access..."
sudo chmod o-rx /usr/bin/gcc /usr/bin/cc

# Check and restart services after library updates
if command -v needrestart >/dev/null; then
    echo "Checking and restarting services after updates..."
    sudo needrestart -r a
else
    echo "Needrestart is not installed. Skipping..."
fi

# Set up UFW (firewall)
echo "Setting up UFW..."
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw enable

# Final message
echo "Security hardening script completed. Review manual steps and verify changes."
