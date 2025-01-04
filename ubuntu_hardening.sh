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
if apt-get update && apt-get full-upgrade -y; then
    log_success "System update and upgrade"
else
    log_failure "System update and upgrade"
fi

# Install essential packages
echo "Installing essential packages..." | tee -a $LOGFILE
ESSENTIAL_PACKAGES=("perl" "wget" "curl" "lynx" "lynis" "fail2ban" "ufw" "auditd" "rkhunter" "apt-listchanges" "debsums" "bsd-mailx" "sysstat" "acct" "aide")
for package in "${ESSENTIAL_PACKAGES[@]}"; do
    install_package "$package"
done
log_success "Essential packages installation"

# Run Lynis audit
echo "Running Lynis audit..." | tee -a $LOGFILE
if lynis audit system --quiet --logfile /var/log/lynis.log --report-file /var/log/lynis-report.dat; then
    log_success "Lynis audit"
else
    log_failure "Lynis audit"
fi

# Configure Fail2Ban
echo "Configuring Fail2Ban..." | tee -a $LOGFILE
if [ -f /etc/fail2ban/jail.local ]; then
    mv /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
    echo "Backed up existing Fail2Ban configuration to jail.local.bak." | tee -a $LOGFILE
fi

cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = 127.0.0.1/8
bantime  = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
EOF

if systemctl enable fail2ban && systemctl restart fail2ban; then
    log_success "Fail2Ban configuration"
else
    log_failure "Fail2Ban configuration"
fi

# Configure UFW
echo "Configuring UFW..." | tee -a $LOGFILE
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
if ufw enable; then
    log_success "UFW configuration"
else
    log_failure "UFW configuration"
fi

# Configure AuditD
echo "Configuring AuditD..." | tee -a $LOGFILE

# Backup existing rules
if [ -f /etc/audit/audit.rules ]; then
    cp /etc/audit/audit.rules /etc/audit/audit.rules.bak
    echo "Backed up existing AuditD rules to audit.rules.bak." | tee -a $LOGFILE
fi

# Clear existing rules
> /etc/audit/audit.rules
> /etc/audit/rules.d/hardening.rules

# Add minimal rules
cat <<EOF > /etc/audit/rules.d/hardening.rules
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
EOF

# Validate and reload rules
if augenrules --load; then
    systemctl restart auditd || log_failure "Restarting AuditD"
    log_success "AuditD configuration and rule loading"
else
    echo "AuditD rule loading failed. Attempting to reinstall AuditD..." | tee -a $LOGFILE
    apt-get install --reinstall -y auditd || log_failure "Reinstalling AuditD"
    if augenrules --load; then
        systemctl restart auditd || log_failure "Restarting AuditD after reinstall"
        log_success "AuditD configuration and rule loading after reinstall"
    else
        log_failure "AuditD configuration failed after reinstall"
    fi
fi

# Update RKHunter
echo "Updating RKHunter..." | tee -a $LOGFILE
if rkhunter --update && rkhunter --propupd; then
    log_success "RKHunter update and configuration"
else
    log_failure "RKHunter update"
fi

# Configure Legal Banners
echo "Configuring legal banners..." | tee -a $LOGFILE
if echo "Authorized access only. Unauthorized access is prohibited." > /etc/issue &&
   echo "Authorized access only. Unauthorized access is prohibited." > /etc/issue.net; then
    log_success "Legal banners configuration"
else
    log_failure "Legal banners configuration"
fi

# Configure Password Policies
echo "Configuring password policies..." | tee -a $LOGFILE
if sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs &&
   sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs &&
   sed -i 's/^UMASK.*/UMASK   027/' /etc/login.defs; then
    log_success "Password policy configuration"
else
    log_failure "Password policy configuration"
fi

# Disable Core Dumps
echo "Disabling core dumps..." | tee -a $LOGFILE
if echo '* hard core 0' >> /etc/security/limits.conf; then
    log_success "Core dumps disabling"
else
    log_failure "Core dumps disabling"
fi

# Disable Unnecessary Protocols
echo "Disabling unnecessary protocols..." | tee -a $LOGFILE
for protocol in dccp sctp rds tipc; do
    if echo "blacklist $protocol" >> /etc/modprobe.d/blacklist.conf; then
        echo "$protocol protocol disabled." | tee -a $LOGFILE
    else
        log_failure "Disabling $protocol protocol"
    fi
done
log_success "Unnecessary protocols disabling"

# Apply Sysctl Hardening
echo "Applying sysctl hardening..." | tee -a $LOGFILE
cat <<EOF > /etc/sysctl.d/99-hardening.conf
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
if sysctl --system; then
    log_success "Sysctl hardening"
else
    log_failure "Sysctl hardening"
fi

# Initialize AIDE
echo "Initializing AIDE..." | tee -a $LOGFILE
if aideinit; then
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db || log_failure "AIDE database move"
    log_success "AIDE initialization"
else
    log_failure "AIDE initialization"
fi

# Restart Services
echo "Restarting necessary services..." | tee -a $LOGFILE
if needrestart -r a; then
    log_success "Service restarts"
else
    log_failure "Service restarts"
fi

# Final Message
echo "Server hardening script completed successfully at $(date)." | tee -a $LOGFILE
