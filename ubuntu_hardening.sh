#!/bin/bash

LOGFILE="/var/log/server_hardening.log"
echo "Starting server hardening process at $(date)" | tee -a $LOGFILE

log_success() {
    echo "[SUCCESS] $1 completed successfully at $(date)" | tee -a $LOGFILE
}

log_failure() {
    echo "[FAILURE] $1 failed at $(date). Check $LOGFILE for details." | tee -a $LOGFILE
}

# Ensure script is running with root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root." | tee -a $LOGFILE
    exit 1
fi

# System updates
echo "Updating and upgrading system..." | tee -a $LOGFILE
apt update && apt upgrade -y && apt autoremove -y
if [ $? -eq 0 ]; then
    log_success "System update and upgrade"
else
    log_failure "System update and upgrade"
    exit 1
fi

# Install Lynis and run security audit
echo "Installing and running Lynis..." | tee -a $LOGFILE
apt install -y lynis
if lynis audit system --quiet --logfile /var/log/lynis.log --report-file /var/log/lynis-report.dat; then
    log_success "Lynis audit"
else
    log_failure "Lynis audit"
fi

# Install recommended packages
RECOMMENDED_PACKAGES=("libpam-tmpdir" "apt-listchanges" "needrestart" "rkhunter" "bsd-mailx" "apt-show-versions" "debsums" "ufw")
for pkg in "${RECOMMENDED_PACKAGES[@]}"; do
    echo "Checking if $pkg is installed..." | tee -a $LOGFILE
    if ! dpkg -l | grep -qw "$pkg"; then
        echo "$pkg is not installed. Installing..." | tee -a $LOGFILE
        apt install -y "$pkg"
        if [ $? -eq 0 ]; then
            log_success "$pkg installation"
        else
            log_failure "$pkg installation"
        fi
    else
        echo "$pkg is already installed." | tee -a $LOGFILE
    fi
done

# Configure Fail2ban
echo "Configuring Fail2ban..." | tee -a $LOGFILE
apt install -y fail2ban
if [ $? -eq 0 ]; then
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    if [ -n "$(ip -6 addr show scope global)" ]; then
        echo "IPv6 is enabled. Keeping IPv6 support in Fail2ban." | tee -a $LOGFILE
    else
        sed -i '/\[DEFAULT\]/a allowipv6 = no' /etc/fail2ban/jail.local
        echo "Disabled IPv6 in Fail2ban." | tee -a $LOGFILE
    fi
    systemctl enable fail2ban && systemctl restart fail2ban
    log_success "Fail2ban configuration"
else
    log_failure "Fail2ban installation and configuration"
fi

# Install and configure sysstat
echo "Installing and configuring sysstat..." | tee -a $LOGFILE
apt install -y sysstat
systemctl enable sysstat && systemctl restart sysstat
if [ $? -eq 0 ]; then
    log_success "Sysstat installation and configuration"
else
    log_failure "Sysstat installation and configuration"
fi

# Configure AuditD
echo "Configuring AuditD..." | tee -a $LOGFILE
apt install -y auditd
if [ $? -eq 0 ]; then
    echo "-w /etc/passwd -p wa -k passwd_changes" > /etc/audit/rules.d/passwd_changes.rules
    echo "-w /etc/group -p wa -k group_changes" > /etc/audit/rules.d/group_changes.rules
    echo "-w /etc/shadow -p wa -k shadow_changes" > /etc/audit/rules.d/shadow_changes.rules
    augenrules --load && systemctl restart auditd
    if [ $? -eq 0 ]; then
        log_success "AuditD configuration"
    else
        echo "Failed to load audit rules. Attempting to troubleshoot..." | tee -a $LOGFILE
        augenrules --load
        log_failure "AuditD configuration"
    fi
else
    log_failure "AuditD installation"
fi

# Install and configure RKHunter
echo "Installing and configuring RKHunter..." | tee -a $LOGFILE
apt install -y rkhunter
if [ $? -eq 0 ]; then
    sed -i 's|WEB_CMD="/bin/true"|WEB_CMD=""|' /etc/rkhunter.conf
    rkhunter --update
    rkhunter --propupd
    log_success "RKHunter installation and configuration"
else
    log_failure "RKHunter installation"
fi

# Configure legal banners
echo "Configuring legal banners..." | tee -a $LOGFILE
echo "Authorized access only. Unauthorized access is prohibited." > /etc/issue
cp /etc/issue /etc/issue.net
log_success "Legal banners configuration"

# Configure password policy
echo "Configuring password policies..." | tee -a $LOGFILE
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^UMASK.*/UMASK   027/' /etc/login.defs
log_success "Password policies configuration"

# Disable core dumps
echo "Disabling core dumps..." | tee -a $LOGFILE
echo '* hard core 0' >> /etc/security/limits.conf
log_success "Core dump disabling"

# Disable unnecessary protocols
echo "Disabling unnecessary protocols..." | tee -a $LOGFILE
for proto in dccp sctp rds tipc; do
    echo "blacklist $proto" >> /etc/modprobe.d/blacklist.conf
done
log_success "Protocol disabling"

# Configure UFW (Firewall)
echo "Configuring UFW firewall..." | tee -a $LOGFILE
ufw default deny incoming
ufw default allow outgoing
ufw enable
if [ $? -eq 0 ]; then
    log_success "UFW firewall configuration"
else
    log_failure "UFW firewall configuration"
fi

# Install AIDE and initialize database
echo "Installing and configuring AIDE..." | tee -a $LOGFILE
apt install -y aide
if [ $? -eq 0 ]; then
    aideinit
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    log_success "AIDE installation and initialization"
else
    log_failure "AIDE installation"
fi

# Apply sysctl hardening
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
sysctl --system
log_success "Sysctl hardening"

# Restrict compiler access
echo "Restricting compiler access..." | tee -a $LOGFILE
chmod o-rx /usr/bin/gcc /usr/bin/cc
if [ $? -eq 0 ]; then
    log_success "Compiler access restriction"
else
    log_failure "Compiler access restriction"
fi

echo "Server hardening process completed at $(date)" | tee -a $LOGFILE
exit 0
