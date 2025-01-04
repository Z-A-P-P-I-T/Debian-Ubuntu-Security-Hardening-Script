#!/bin/bash

# Log file for the script
LOG_FILE="/var/log/server_hardening.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Helper functions
log_success() {
    echo -e "\e[32m[SUCCESS]\e[0m $1"
}

log_failure() {
    echo -e "\e[31m[FAILURE]\e[0m $1"
}

retry_command() {
    local cmd="$1"
    local retries=3
    local count=0
    until [ $count -ge $retries ]; do
        eval "$cmd" && break
        count=$((count + 1))
        log_failure "Command failed: $cmd. Retrying ($count/$retries)..."
        sleep 2
    done
    if [ $count -eq $retries ]; then
        log_failure "Command failed after $retries attempts: $cmd"
        return 1
    fi
    return 0
}

# Update system
log_success "Updating and upgrading system..."
retry_command "apt update && apt upgrade -y"

# Install essential packages
ESSENTIAL_PACKAGES=(
    lynis libpam-tmpdir apt-listchanges needrestart rkhunter bsd-mailx
    apt-show-versions debsums aide sysstat auditd fail2ban ufw
)
log_success "Installing essential packages..."
for pkg in "${ESSENTIAL_PACKAGES[@]}"; do
    retry_command "apt install -y $pkg"
done

# Lynis audit
log_success "Running Lynis audit..."
retry_command "lynis audit system"

# Configure Fail2Ban
log_success "Configuring Fail2Ban..."
if [ -f /etc/fail2ban/jail.local ]; then
    mv /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
fi
cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 10m
findtime = 10m
maxretry = 3
EOF
retry_command "systemctl enable fail2ban && systemctl restart fail2ban"

# Configure UFW
log_success "Configuring UFW..."
retry_command "ufw default deny incoming"
retry_command "ufw default allow outgoing"
retry_command "ufw enable"

# Configure auditd
log_success "Configuring Auditd..."
AUDIT_RULES="/etc/audit/audit.rules"
if [ -f "$AUDIT_RULES" ]; then
    cp "$AUDIT_RULES" "${AUDIT_RULES}.bak"
fi
cat <<EOF > $AUDIT_RULES
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
EOF
retry_command "systemctl enable auditd && systemctl restart auditd"

# Configure AIDE
log_success "Configuring AIDE..."
retry_command "aideinit"
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Configure RKHunter
log_success "Installing and configuring RKHunter..."
retry_command "apt install -y rkhunter"
if [ $? -eq 0 ]; then
    sed -i 's|^WEB_CMD=.*|WEB_CMD=""|' /etc/rkhunter.conf
    log_success "Updating RKHunter data files..."
    retry_command "rkhunter --update"
    if [ $? -ne 0 ]; then
        log_failure "RKHunter data update failed. Attempting manual update..."
        MIRROR_URL="https://sourceforge.net/projects/rkhunter/files/latest/download"
        wget -O /tmp/rkhunter.tar.gz "$MIRROR_URL"
        if [ -f /tmp/rkhunter.tar.gz ]; then
            tar -xzf /tmp/rkhunter.tar.gz -C /tmp/
            cp -r /tmp/rkhunter*/* /var/lib/rkhunter/
            log_success "RKHunter manual update completed."
        else
            log_failure "Failed to download manual RKHunter updates."
        fi
    fi
    log_success "Running RKHunter property update..."
    retry_command "rkhunter --propupd"
    if [ $? -ne 0 ]; then
        log_failure "RKHunter property update failed. Check /var/log/rkhunter.log for details."
    else
        log_success "RKHunter configuration completed successfully."
    fi
else
    log_failure "RKHunter installation failed."
fi

# Apply sysctl settings
log_success "Applying sysctl hardening..."
cat <<EOF > /etc/sysctl.d/99-hardening.conf
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
EOF
retry_command "sysctl --system"

# Restrict compilers
log_success "Restricting compiler access..."
if [ -f /usr/bin/gcc ]; then
    chmod o-rx /usr/bin/gcc
else
    log_success "GCC not found. Skipping compiler restriction step."
fi

log_success "Security hardening completed successfully."
log_success "Check $LOG_FILE for full details."
