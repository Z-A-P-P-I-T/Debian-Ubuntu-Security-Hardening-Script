#!/bin/bash

LOGFILE="/var/log/server_hardening.log"
exec > >(tee -a $LOGFILE) 2>&1

log_success() {
    echo "[SUCCESS] $1"
}

log_failure() {
    echo "[FAILURE] $1"
}

retry_command() {
    local CMD="$1"
    local RETRIES=3
    local WAIT=5

    for ((i=1; i<=RETRIES; i++)); do
        eval "$CMD"
        if [ $? -eq 0 ]; then
            return 0
        fi
        echo "Attempt $i failed. Retrying in $WAIT seconds..."
        sleep $WAIT
    done

    return 1
}

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root. Exiting."
    exit 1
fi

# Update the system
log_success "Updating and upgrading system..."
retry_command "apt update && apt upgrade -y"

# Install Lynis
log_success "Installing Lynis..."
retry_command "apt install -y lynis"

# Run Lynis scan
log_success "Running Lynis scan..."
retry_command "lynis audit system --logfile /var/log/lynis.log --report-file /var/log/lynis-report.dat"

# Install recommended packages
log_success "Installing recommended packages..."
retry_command "apt install -y libpam-tmpdir apt-listchanges needrestart rkhunter bsd-mailx apt-show-versions debsums"

# Configure Fail2Ban
log_success "Configuring Fail2Ban..."
retry_command "apt install -y fail2ban"
if [ $? -eq 0 ]; then
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sed -i '/\[DEFAULT\]/a allowipv6 = no' /etc/fail2ban/jail.local
    systemctl enable fail2ban
    systemctl start fail2ban
else
    log_failure "Fail2Ban configuration failed."
fi

# Install and configure sysstat
log_success "Configuring sysstat..."
retry_command "apt install -y sysstat"
retry_command "systemctl enable sysstat && systemctl start sysstat"

# Install and configure auditd
log_success "Configuring auditd..."
retry_command "apt install -y auditd"
if [ $? -eq 0 ]; then
    echo "-w /etc/passwd -p wa -k passwd_changes" > /etc/audit/rules.d/passwd_changes.rules
    echo "-w /etc/group -p wa -k group_changes" > /etc/audit/rules.d/group_changes.rules
    echo "-w /etc/shadow -p wa -k shadow_changes" > /etc/audit/rules.d/shadow_changes.rules
    augenrules --load
    systemctl enable auditd
    systemctl start auditd
else
    log_failure "Auditd configuration failed."
fi

# Install and configure RKHunter
log_success "Configuring RKHunter..."
retry_command "apt install -y rkhunter"
if [ $? -eq 0 ]; then
    sed -i 's|^WEB_CMD=.*|WEB_CMD=""|' /etc/rkhunter.conf
    retry_command "rkhunter --update"
    retry_command "rkhunter --propupd"
else
    log_failure "RKHunter configuration failed."
fi

# Configure legal banners
log_success "Configuring legal banners..."
echo "Authorized access only. Unauthorized access is prohibited." > /etc/issue
cp /etc/issue /etc/issue.net

# Configure password policies
log_success "Configuring password policies..."
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^UMASK.*/UMASK   027/' /etc/login.defs

# Disable core dumps
log_success "Disabling core dumps..."
echo '* hard core 0' >> /etc/security/limits.conf

# Disable unnecessary protocols
log_success "Disabling unnecessary protocols..."
for protocol in dccp sctp rds tipc; do
    echo "blacklist $protocol" >> /etc/modprobe.d/blacklist.conf
done

# Configure UFW
log_success "Configuring UFW..."
retry_command "apt install -y ufw"
ufw default deny incoming
ufw default allow outgoing
ufw enable

# Install and configure AIDE
log_success "Configuring AIDE..."
retry_command "apt install -y aide"
retry_command "aideinit"
retry_command "mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"

# Apply sysctl settings
log_success "Applying sysctl settings..."
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

# Restrict compiler access
log_success "Restricting compiler access..."
if [ -f /usr/bin/gcc ] || [ -f /usr/bin/cc ]; then
    chmod o-rx /usr/bin/gcc /usr/bin/cc
    log_success "Compiler access restricted successfully."
else
    log_success "Compilers not found. Skipping compiler restriction step."
fi

log_success "Security hardening completed successfully."
echo "Check $LOGFILE for full details."
