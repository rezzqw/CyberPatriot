#!/bin/bash
# cyberpatrol_auto.sh
# Automates non-manual security steps from both checklists for Ubuntu/Mint.
# *** CRITICAL: MANY STEPS REQUIRE MANUAL INTERVENTION. RUN THIS SCRIPT WITH CAUTION AND REVIEW CHECKLISTS FOR MANUAL STEPS! ***

# Stop on any error
set -e

echo "Starting automated security hardening script..."

# --- Secure Root and SSH Configuration ---
echo "1. Securing root access and SSH..."
# Set PermitRootLogin no in /etc/ssh/sshd_config [cite: 12, 13, 93]
if grep -q "PermitRootLogin yes" /etc/ssh/sshd_config; then
    sudo sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
elif ! grep -q "PermitRootLogin no" /etc/ssh/sshd_config; then
    echo "PermitRootLogin no" | sudo tee -a /etc/ssh/sshd_config > /dev/null
fi
# Restart SSH to apply changes (may disconnect your session if you're using SSH)
sudo systemctl restart ssh || echo "SSH service restart failed. Check service status."

# --- Disable Guest User ---
echo "2. Disabling the guest user..."
# Go to /etc/lightdm/lightdm.conf and add 'allow-guest=false' [cite: 15, 16, 17, 93]
LIGHTDM_CONF="/etc/lightdm/lightdm.conf"
if [ ! -f "$LIGHTDM_CONF" ]; then
    echo -e "[Seat:*]\nallow-guest=false" | sudo tee -a "$LIGHTDM_CONF" > /dev/null
elif ! grep -q "allow-guest=false" "$LIGHTM_CONF"; then
    # Add to the end of the file or an appropriate section
    echo "allow-guest=false" | sudo tee -a "$LIGHTDM_CONF" > /dev/null
fi
echo "Guest user disabled. NOTE: Session must be restarted manually (sudo restart lightdm) to fully apply. This will log you out." [cite: 18]

# --- Enforce Password Requirements (Expiration and Length) ---
echo "3. Enforcing password requirements (Expiration and Length)..."
# Add or change password expiration requirements to /etc/login.defs [cite: 32, 33, 34, 35, 36, 93]
sudo sed -i 's/^\(PASS_MIN_DAYS\).*/\1 7/' /etc/login.defs
sudo sed -i 's/^\(PASS_MAX_DAYS\).*/\1 90/' /etc/login.defs
sudo sed -i 's/^\(PASS_WARN_AGE\).*/\1 14/' /etc/login.defs

# Add minimum password length minlen=8 to /etc/pam.d/common-password [cite: 37, 38, 39, 93]
sudo sed -i '/pam_unix.so/ s/$/ minlen=8/' /etc/pam.d/common-password

# --- Implement Account Lockout Policy ---
echo "4. Implementing account lockout policy..."
# Add deny=5 unlock_time=1800 to the line with pam_tally2.so in /etc/pam.d/common-auth [cite: 40, 41, 42, 93]
# Using pam_tally2 is common, but newer systems like Ubuntu 22 may use pam_faillock.so
# This script uses pam_tally2 as specified in the checklist, but you should verify on your system.
# Note: Ubuntu 22/Mint 21 often uses pam_faillock.so. You may need to adapt this line.
if grep -q "pam_tally2.so" /etc/pam.d/common-auth; then
    sudo sed -i '/pam_tally2.so/ s/$/ deny=5 unlock_time=1800/' /etc/pam.d/common-auth
else
    echo "WARNING: pam_tally2.so not found in common-auth. Consider manually adding pam_faillock.so or pam_tally2.so rules."
fi
echo "NOTE: All passwords must be changed manually (e.g., using chpasswd) to satisfy these new requirements." 

# --- Enable Automatic Updates (GUI setting, using apt to approximate) ---
echo "5. Enabling automatic updates..."
# The checklist specifies a GUI setting: Update Manager->Settings->Updates->Check for updates:->Daily[cite: 45, 46, 93].
# This is hard to script, but we can ensure unattended-upgrades is installed and configured.
sudo apt update
sudo apt install -y unattended-upgrades
# Enable unattended-upgrades and set check interval
sudo dpkg-reconfigure -plow unattended-upgrades

# --- Secure Network: Firewall and Syn Cookie Protection ---
echo "6. Securing network (Firewall and Syn Cookies)..."
# Enable the firewall [cite: 59, 60, 61, 88, 93]
echo "Enabling UFW (Firewall)..."
sudo ufw enable
sudo ufw status verbose

# Enable syn cookie protection [cite: 62, 63, 93]
echo "Enabling SYN cookie protection..."
# Check current value
CURRENT_SYNCOOKIES=$(sysctl -n net.ipv4.tcp_syncookies)
if [ "$CURRENT_SYNCOOKIES" -ne 1 ]; then
    echo "net.ipv4.tcp_syncookies=1" | sudo tee -a /etc/sysctl.conf > /dev/null
    sudo sysctl -p
fi

# --- System Updates (General) ---
echo "7. Installing general system updates..."
# Do general updates [cite: 64, 66, 67, 68, 93]
sudo apt-get update
sudo apt-get upgrade -y

# --- Configuration: Monitor Processes and Logs (Manual Steps) ---
echo "8. Post-script: Reviewing processes, services, and logs..."
echo "REMINDER: Manual steps required for configuration and cleanup:"
echo "* Review the status of all services with 'service --status-all' and ensure they are legitimate (check for hacking tools)[cite: 76, 77, 78, 93]."
echo "* Monitor processes using 'ps aux' or 'top' or System Monitor[cite: 93]."
echo "* Check user directories for media, tools, and prohibited files[cite: 28, 31, 90, 93]."
echo "* Empty the recycle bin[cite: 87]."
echo "* Install and update anti-virus (e.g., ClamTK)[cite: 89, 93]."

echo "Automated script complete. Please proceed with all manual steps in the checklists!"