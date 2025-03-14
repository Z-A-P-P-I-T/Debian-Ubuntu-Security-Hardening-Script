#!/bin/bash

export safe_date=`date +%s`;
export LOG_FILE="/var/log/server_hardening`date +%s`.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[INFO] Starting security hardening at $safe_date"


## probably check_for_likely_pm () which does some whiching -a on uh yum apt aptitude apt-get dnf etc etc etc

# Function to check if a package is installed, install if not, and handle errors
install_package() {
    local package=$1
    echo "[INFO] Checking if $package is installed..."
    if ! dpkg -l | grep -qw "$package"; then
        echo "[INFO] $package is not installed. Installing..."
        if ! apt-get install -y "$package"; then
            echo "[ERROR] Failed to install $package. Exiting..."
            exit 1
        fi
    else
        echo "[INFO] $package is already installed."
    fi
}

# Function to ensure RKHunter updates and installs correctly
install_rkhunter() {
    echo "[INFO] Checking if RKHunter is installed..."
    if ! command -v rkhunter &> /dev/null; then
        echo "[INFO] RKHunter is not installed. Installing..."
        if ! apt-get install -y rkhunter; then
            echo "[ERROR] Failed to install RKHunter. Exiting..."
            exit 1
        fi
    fi

    echo "[INFO] Updating RKHunter database..."
    for attempt in {1..3}; do
        if rkhunter --update; then
            echo "[INFO] RKHunter database updated successfully."
            break
        else
            echo "[WARNING] RKHunter update failed. Retrying ($attempt/3)..."
            sleep 5
        fi
    done

    if ! rkhunter --propupd; then
        echo "[ERROR] Failed to update RKHunter file properties database. Exiting..."
        exit 1
    fi

    echo "[INFO] RKHunter installation and configuration completed successfully."
}

# Update system and install essential packages
echo "[INFO] Updating system packages..."
apt-get update && apt-get upgrade -y

PACKAGES=(
    "lynis"
    "libpam-tmpdir"
    "apt-listchanges"
    "needrestart"
    "bsd-mailx"
    "apt-show-versions"
    "debsums"
    "auditd"
    "acct"
    "sysstat"
)

for package in "${PACKAGES[@]}"; do
    install_package "$package"
done

# Run Lynis security audit
echo "[INFO] Running Lynis scan..."
lynis audit system || echo "[WARNING] Lynis encountered issues. Check Lynis logs for details."

# Configure Fail2Ban
echo "[INFO] Installing and configuring Fail2Ban..."
install_package "fail2ban"
builtin cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
if grep -q "::" /proc/net/if_inet6; then
    sed -i 's/#banaction_allports = iptables-multiport/banaction_allports = ip6tables-multiport/' /etc/fail2ban/jail.local
fi
systemctl enable fail2ban && systemctl start fail2ban

# Configure auditd
echo "[INFO] Configuring Auditd..."
cat << EOF > /etc/audit/rules.d/hardening.rules
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
EOF
augenrules --load || echo "[ERROR] Failed to load Auditd rules."

# Configure sysctl hardening
echo "[INFO] Applying sysctl settings..."
cat << EOF > /etc/sysctl.d/99-hardening.conf
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
EOF
sysctl --system

# Configure password policies
echo "[INFO] Configuring password policies..."
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

# Configure AIDE
echo "[INFO] Installing and initializing AIDE..."
install_package "aide"
aideinit && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Apply security banner
echo "[INFO] Setting up legal banners..."
echo "Authorized access only. Unauthorized access is prohibited." > /etc/issue
echo "Authorized access only. Unauthorized access is prohibited." > /etc/issue.net

# Restrict compiler access
echo "[INFO] Restricting compiler access..."
chmod 700 /usr/bin/gcc /usr/bin/cc || echo "[WARNING] GCC not found. Skipping compiler restriction step."

# Run RKHunter installation and updates
install_rkhunter

echo "[INFO] Security hardening completed successfully at $(date)."
echo "Check $LOG_FILE for full details."
