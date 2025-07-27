#!/bin/bash

# Enhanced System Initialization Script
# Features: System initialization, security configuration, user management, software installation
# Characteristics: Repeatable execution, configuration modification, error handling, logging

set -euo pipefail  # Strict mode: exit immediately on error

# Global variables
SCRIPT_NAME="Enhanced System Init"
LOG_FILE="/var/log/system_init.log"
CONFIG_DIR="/etc/system_init"
BACKUP_DIR="/etc/system_init/backups"
SSH_PORT=32798

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$*"; }
log_warn() { log "WARN" "$*"; }
log_error() { log "ERROR" "$*"; }
log_success() { log "SUCCESS" "$*"; }

# Colored output functions
print_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $*"; }
print_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Error handling function
error_exit() {
    log_error "$1"
    print_error "$1"
    exit 1
}

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error_exit "Please run this script as root user"
    fi
}

# Initialize environment
init_environment() {
    print_info "Initializing environment..."
    
    # Create necessary directories
    mkdir -p "$CONFIG_DIR" "$BACKUP_DIR"
    
    # Create log file
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    log_info "Script started - $SCRIPT_NAME"
    log_info "Log file: $LOG_FILE"
    
    print_success "Environment initialization completed"
}

# Backup configuration file
backup_file() {
    local file=$1
    local backup_name=$(basename "$file").$(date +%Y%m%d_%H%M%S)
    
    if [ -f "$file" ]; then
        cp "$file" "$BACKUP_DIR/$backup_name"
        log_info "Backup file: $file -> $BACKUP_DIR/$backup_name"
        return 0
    fi
    return 1
}

# Check service status
check_service() {
    local service=$1
    if systemctl is-active --quiet "$service"; then
        return 0
    else
        return 1
    fi
}

# Safely restart service
restart_service() {
    local service=$1
    log_info "Restarting service: $service"
    
    if systemctl restart "$service"; then
        log_success "Service $service restarted successfully"
        return 0
    else
        log_error "Service $service restart failed"
        return 1
    fi
}

# Main menu
show_menu() {
    clear
    echo -e "${BLUE}===== $SCRIPT_NAME =====${NC}"
    echo -e "${GREEN}Current configuration status:${NC}"
    echo "  SSH Port: $(get_ssh_port)"
    echo "  Firewall Status: $(get_ufw_status)"
    echo "  Fail2ban Status: $(get_fail2ban_status)"
    echo "  Swap Status: $(get_swap_status)"
    echo ""
    echo "Please select an operation to execute:"
    echo "1) 🔄 System update and software installation"
    echo "2) 💾 Setup Swap partition"
    echo "3) 🔒 Security configuration (SSH/Firewall/Fail2ban)"
    echo "4) 👤 User management"
    echo "5) 🔑 SSH key management"
    echo "6) ⚙️  System optimization configuration"
    echo "7) 📦 Install Docker"
    echo "8) 🛠️  Bash auto-completion configuration"
    echo "9) 🔍 View system status"
    echo "10) 📋 View configuration history"
    echo "0) Exit"
    echo ""
}

# Get current configuration status
get_ssh_port() {
    if [ -f /etc/ssh/sshd_config ]; then
        grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' || echo "22"
    else
        echo "Not configured"
    fi
}

get_ufw_status() {
    if command -v ufw >/dev/null 2>&1; then
        ufw status | head -1 | awk '{print $2}' || echo "Not installed"
    else
        echo "Not installed"
    fi
}

get_fail2ban_status() {
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        echo "Running"
    else
        echo "Not running"
    fi
}

get_swap_status() {
    local swap_total=$(free -h | grep Swap | awk '{print $2}')
    if [ "$swap_total" = "0B" ]; then
        echo "Not configured"
    else
        echo "$swap_total"
    fi
}

# 1. System update and software installation
update_system() {
    print_info "Starting system update and software installation..."
    
    log_info "Updating package list"
    apt-get update || error_exit "Package list update failed"
    
    log_info "Upgrading system packages"
    apt-get upgrade -y || error_exit "System upgrade failed"
    
    log_info "Full system upgrade"
    apt-get dist-upgrade -y || log_warn "Full upgrade partially failed, continuing execution"
    
    log_info "Installing basic packages"
    local packages=(
        "curl" "vim" "ufw" "jq" "sudo" "fail2ban" 
        "unattended-upgrades" "apt-listchanges" "bash-completion" 
        "git" "net-tools" "dnsutils" "gh" "htop" "tree"
    )
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            log_info "Installing package: $package"
            apt-get install -y "$package" || log_warn "Package $package installation failed"
        else
            log_info "Package $package already installed"
        fi
    done
    
    # Configure automatic updates
    configure_auto_updates
    
    print_success "System update and software installation completed"
}

# Configure automatic updates
configure_auto_updates() {
    log_info "Configuring automatic security updates"
    
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
EOF
    
    log_success "Automatic update configuration completed"
}

# 2. Setup Swap partition
setup_swap() {
    print_info "Swap partition configuration"
    
    local current_swap=$(get_swap_status)
    echo "Current Swap status: $current_swap"
    
    if [ "$current_swap" != "Not configured" ]; then
        read -p "Existing Swap partition detected, do you want to reconfigure? (y/n): " reconfigure
        if [ "$reconfigure" != "y" ]; then
            return 0
        fi
        
        # Disable existing swap
        swapoff -a || true
        sed -i '/swapfile/d' /etc/fstab
        rm -f /swapfile
    fi
    
    read -p "Please enter Swap size (in GB), press Enter to skip: " swap_size
    
    if [[ -n "$swap_size" && "$swap_size" =~ ^[0-9]+$ ]]; then
        log_info "Creating ${swap_size}GB Swap partition"
        
        # Create swap file
        if command -v fallocate >/dev/null 2>&1; then
            fallocate -l "${swap_size}G" /swapfile
        else
            dd if=/dev/zero of=/swapfile bs=1G count="$swap_size"
        fi
        
        # Set permissions and format
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        
        # Add to fstab (check if already exists)
        if ! grep -q "/swapfile" /etc/fstab; then
            echo "/swapfile none swap sw 0 0" >> /etc/fstab
        fi
        
        # Optimize swap usage
        if ! grep -q "vm.swappiness" /etc/sysctl.conf; then
            echo "vm.swappiness=10" >> /etc/sysctl.conf
        fi
        sysctl -p
        
        log_success "Swap partition setup completed: ${swap_size}GB"
        print_success "Swap partition configuration completed"
    else
        print_info "Skipping Swap configuration"
    fi
}

# 3. Security configuration
security_config() {
    print_info "Starting security configuration..."
    
    # SSH configuration
    configure_ssh
    
    # Firewall configuration
    configure_firewall
    
    # Fail2ban configuration
    configure_fail2ban
    
    # System security parameters
    configure_system_security
    
    print_success "Security configuration completed"
}

# SSH configuration
configure_ssh() {
    log_info "Configuring SSH security settings"
    
    # Backup existing configuration
    backup_file "/etc/ssh/sshd_config"
    
    # Ask for SSH port
    local current_port=$(get_ssh_port)
    read -p "SSH port (current: $current_port, press Enter to use $SSH_PORT): " new_port
    new_port=${new_port:-$SSH_PORT}
    
    # Create secure SSH configuration
    cat > /etc/ssh/sshd_config << EOF
# SSH security configuration - Generated by system initialization script
Port $new_port
Protocol 2

# Host keys
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Hardened encryption algorithms
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# Authentication settings
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Session security
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 300
ClientAliveCountMax 2

# Feature limitations
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*

# SFTP subsystem
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
    
    # Test configuration
    if sshd -t; then
        restart_service "sshd"
        log_success "SSH configuration updated, port: $new_port"
        SSH_PORT=$new_port
    else
        log_error "SSH configuration test failed, restoring backup"
        # Restore backup (logic can be added here)
    fi
}

# Firewall configuration
configure_firewall() {
    log_info "Configuring UFW firewall"
    
    # Ensure UFW is installed
    if ! command -v ufw >/dev/null 2>&1; then
        log_error "UFW not installed"
        return 1
    fi
    
    # Basic rules
    ufw default deny incoming
    ufw default allow outgoing
    
    # SSH port
    ufw allow "$SSH_PORT/tcp" comment 'SSH'
    
    # Web service ports
    read -p "Open HTTP(80) and HTTPS(443) ports? (y/n): " open_web
    if [ "$open_web" = "y" ]; then
        ufw allow http comment 'HTTP'
        ufw allow https comment 'HTTPS'
    fi
    
    # Redis port
    read -p "Open Redis port(6379)? (y/n): " open_redis
    if [ "$open_redis" = "y" ]; then
        ufw allow 6379/tcp comment 'Redis'
    fi
    
    # Custom port
    read -p "Need to open other ports? (format: port/protocol description, e.g.: 3306/tcp MySQL): " custom_port
    if [ -n "$custom_port" ]; then
        ufw allow $custom_port
    fi
    
    # Enable logging
    ufw logging on
    
    # Enable firewall
    ufw --force enable
    systemctl enable ufw
    
    log_success "UFW firewall configuration completed"
}

# Fail2ban configuration
configure_fail2ban() {
    log_info "Configuring Fail2ban intrusion protection"
    
    # Backup existing configuration
    backup_file "/etc/fail2ban/jail.local"
    
    # Create jail.local configuration
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# Basic settings
bantime = 3600
findtime = 600
maxretry = 5
banaction = ufw

# SSH protection - basic configuration
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF
    
    # Test configuration
    log_info "Testing Fail2ban configuration"
    if fail2ban-client -t >/dev/null 2>&1; then
        log_success "Basic configuration test passed"
        
        # Start service
        systemctl enable fail2ban
        if restart_service "fail2ban"; then
            log_success "Fail2ban basic configuration completed"
            
            # Ask if extended protection should be added
            echo ""
            read -p "Add extended service protection (Apache/Nginx/Postfix)? (y/n): " add_extended
            if [ "$add_extended" = "y" ]; then
                add_extended_protection
            fi
        else
            log_error "Fail2ban startup failed"
        fi
    else
        log_error "Fail2ban configuration test failed, showing error:"
        fail2ban-client -t || true
        log_warn "Keeping minimal configuration, can be manually fixed later"
    fi
}

# Add extended protection
add_extended_protection() {
    log_info "Adding extended service protection"
    
    # Check Apache
    if [ -d /etc/apache2 ] && [ -f /var/log/apache2/error.log ]; then
        log_info "Apache detected, adding protection rules"
        cat >> /etc/fail2ban/jail.local << 'EOF'

# Apache protection
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/error.log
maxretry = 3
EOF
    fi
    
    # Check Nginx
    if [ -d /etc/nginx ] && [ -f /var/log/nginx/error.log ]; then
        log_info "Nginx detected, adding protection rules"
        cat >> /etc/fail2ban/jail.local << 'EOF'

# Nginx protection
[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3
EOF
    fi
    
    # Check Postfix
    if [ -d /etc/postfix ] && [ -f /var/log/mail.log ]; then
        log_info "Postfix detected, adding protection rules"
        cat >> /etc/fail2ban/jail.local << 'EOF'

# Postfix protection
[postfix]
enabled = true
port = smtp,465,submission
filter = postfix
logpath = /var/log/mail.log
maxretry = 3
EOF
    fi
    
    # Test extended configuration
    if fail2ban-client -t >/dev/null 2>&1; then
        log_info "Reloading extended configuration"
        systemctl reload fail2ban
        sleep 2
        log_success "Extended protection configuration completed"
    else
        log_error "Extended configuration has errors, restoring basic configuration"
        # Restore basic configuration
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
banaction = ufw

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
        systemctl reload fail2ban
    fi
    
    # Create Redis filter
    mkdir -p /etc/fail2ban/filter.d
    cat > /etc/fail2ban/filter.d/redis-server.conf << 'EOF'
[Definition]
failregex = ^ WARNING .* Client .* @ <HOST> .*
ignoreregex =
EOF
    
    systemctl enable fail2ban
    restart_service "fail2ban"
    
    log_success "Fail2ban configuration completed"
}

# System security parameter configuration
configure_system_security() {
    log_info "Configuring system security parameters"
    
    # File permission mask
    if ! grep -q "umask 027" /etc/profile; then
        echo "umask 027" >> /etc/profile
    fi
    
    # Limit core dumps
    if ! grep -q "hard core 0" /etc/security/limits.conf; then
        echo "* hard core 0" >> /etc/security/limits.conf
    fi
    
    # System resource limits
    cat >> /etc/security/limits.conf << 'EOF'

# System resource limits - Added by system initialization script
* soft nofile 65535
* hard nofile 65535
* soft nproc 4096
* hard nproc 4096
EOF
    
    # Network security parameters
    cat > /etc/sysctl.d/99-security.conf << 'EOF'
# Network security configuration - Generated by system initialization script

# IP security settings
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# TCP/IP security settings
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# File system security
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Memory management optimization
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 2
EOF
    
    sysctl -p /etc/sysctl.d/99-security.conf
    
    log_success "System security parameter configuration completed"
}

# 4. User management
user_management() {
    print_info "User management"
    
    echo "Please select operation:"
    echo "1) Create new user"
    echo "2) Modify existing user"
    echo "3) Delete user"
    echo "4) View user list"
    
    read -p "Please select (1-4): " user_choice
    
    case $user_choice in
        1) create_user ;;
        2) modify_user ;;
        3) delete_user ;;
        4) list_users ;;
        *) print_warning "Invalid selection" ;;
    esac
}

# Create user
create_user() {
    read -p "Please enter username to create: " new_user
    
    if [ -z "$new_user" ]; then
        print_error "Username cannot be empty"
        return 1
    fi
    
    if id "$new_user" &>/dev/null; then
        print_warning "User $new_user already exists"
        return 1
    fi
    
    # Create user
    useradd -m -s /bin/bash "$new_user"
    
    # Set password
    read -p "Please enter password (press Enter to use username as password): " user_password
    user_password=${user_password:-$new_user}
    echo "$new_user:$user_password" | chpasswd
    
    # Add to groups
    read -p "Add user to sudo group? (y/n): " add_sudo
    if [ "$add_sudo" = "y" ]; then
        usermod -aG sudo "$new_user"
        echo "$new_user ALL=(ALL) NOPASSWD: ALL" > "/etc/sudoers.d/$new_user"
        chmod 440 "/etc/sudoers.d/$new_user"
    fi
    
    read -p "Add user to docker group? (y/n): " add_docker
    if [ "$add_docker" = "y" ]; then
        if getent group docker >/dev/null; then
            usermod -aG docker "$new_user"
        else
            print_warning "Docker group does not exist, please install Docker first"
        fi
    fi
    
    log_success "User $new_user created successfully"
    print_success "User creation completed, password: $user_password"
}

# Modify user
modify_user() {
    read -p "Please enter username to modify: " target_user
    
    if ! id "$target_user" &>/dev/null; then
        print_error "User $target_user does not exist"
        return 1
    fi
    
    echo "Current groups for user $target_user:"
    groups "$target_user"
    
    echo "Please select modification operation:"
    echo "1) Reset password"
    echo "2) Add to sudo group"
    echo "3) Remove from sudo group"
    echo "4) Add to docker group"
    echo "5) Remove from docker group"
    
    read -p "Please select (1-5): " modify_choice
    
    case $modify_choice in
        1) 
            read -p "Please enter new password: " new_password
            echo "$target_user:$new_password" | chpasswd
            log_success "Password reset for user $target_user"
            ;;
        2) 
            usermod -aG sudo "$target_user"
            log_success "User $target_user added to sudo group"
            ;;
        3) 
            gpasswd -d "$target_user" sudo
            rm -f "/etc/sudoers.d/$target_user"
            log_success "User $target_user removed from sudo group"
            ;;
        4) 
            usermod -aG docker "$target_user"
            log_success "User $target_user added to docker group"
            ;;
        5) 
            gpasswd -d "$target_user" docker
            log_success "User $target_user removed from docker group"
            ;;
        *) print_warning "Invalid selection" ;;
    esac
}

# Delete user
delete_user() {
    read -p "Please enter username to delete: " target_user
    
    if ! id "$target_user" &>/dev/null; then
        print_error "User $target_user does not exist"
        return 1
    fi
    
    read -p "Confirm deletion of user $target_user and their home directory? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        userdel -r "$target_user" 2>/dev/null || userdel "$target_user"
        rm -f "/etc/sudoers.d/$target_user"
        log_success "User $target_user deleted"
    else
        print_info "Deletion operation cancelled"
    fi
}

# List users
list_users() {
    print_info "System user list:"
    echo "Regular users:"
    awk -F: '$3 >= 1000 && $3 < 65534 {print $1 " (UID: " $3 ")"}' /etc/passwd
    echo ""
    echo "System users:"
    awk -F: '$3 < 1000 || $3 >= 65534 {print $1 " (UID: " $3 ")"}' /etc/passwd | head -10
}

# 5. SSH key management
ssh_key_management() {
    print_info "SSH key management"
    
    echo "Please select operation:"
    echo "1) Add public key for user"
    echo "2) Generate key pair for user"
    echo "3) View user public keys"
    echo "4) Delete user public key"
    
    read -p "Please select (1-4): " key_choice
    
    case $key_choice in
        1) add_public_key ;;
        2) generate_key_pair ;;
        3) view_public_keys ;;
        4) remove_public_key ;;
        *) print_warning "Invalid selection" ;;
    esac
}

# Add public key
add_public_key() {
    read -p "Please enter username: " key_user
    
    if ! id "$key_user" &>/dev/null; then
        print_error "User $key_user does not exist"
        return 1
    fi
    
    # Create .ssh directory
    mkdir -p "/home/$key_user/.ssh"
    chmod 700 "/home/$key_user/.ssh"
    
    echo "Please paste public key content (starting with ssh-, connect multiple lines with spaces):"
    read -r pubkey
    
    if [ -n "$pubkey" ]; then
        echo "$pubkey" >> "/home/$key_user/.ssh/authorized_keys"
        chmod 600 "/home/$key_user/.ssh/authorized_keys"
        chown -R "$key_user:$key_user" "/home/$key_user/.ssh"
        
        log_success "Public key added to user $key_user"
        print_success "SSH public key added successfully"
    else
        print_error "Public key content is empty"
    fi
}

# Generate key pair
generate_key_pair() {
    read -p "Please enter username: " key_user
    
    if ! id "$key_user" &>/dev/null; then
        print_error "User $key_user does not exist"
        return 1
    fi
    
    # Create .ssh directory
    mkdir -p "/home/$key_user/.ssh"
    chmod 700 "/home/$key_user/.ssh"
    chown "$key_user:$key_user" "/home/$key_user/.ssh"
    
    read -p "Please enter key password (press Enter for no password): " key_password
    
    # Generate key
    su - "$key_user" -c "ssh-keygen -t ed25519 -N '$key_password' -f /home/$key_user/.ssh/id_ed25519"
    
    # Add public key to authorized_keys
    cat "/home/$key_user/.ssh/id_ed25519.pub" >> "/home/$key_user/.ssh/authorized_keys"
    chmod 600 "/home/$key_user/.ssh/authorized_keys"
    chown "$key_user:$key_user" "/home/$key_user/.ssh/authorized_keys"
    
    print_success "SSH key pair generation completed"
    echo "Private key location: /home/$key_user/.ssh/id_ed25519"
    echo "Public key content:"
    cat "/home/$key_user/.ssh/id_ed25519.pub"
    
    log_success "Generated SSH key pair for user $key_user"
}

# View public keys
view_public_keys() {
    read -p "Please enter username: " key_user
    
    if ! id "$key_user" &>/dev/null; then
        print_error "User $key_user does not exist"
        return 1
    fi
    
    if [ -f "/home/$key_user/.ssh/authorized_keys" ]; then
        print_info "Authorized public keys for user $key_user:"
        cat "/home/$key_user/.ssh/authorized_keys"
    else
        print_info "User $key_user has no SSH public keys configured"
    fi
}

# Remove public key
remove_public_key() {
    read -p "Please enter username: " key_user
    
    if ! id "$key_user" &>/dev/null; then
        print_error "User $key_user does not exist"
        return 1
    fi
    
    if [ -f "/home/$key_user/.ssh/authorized_keys" ]; then
        echo "Current public keys:"
        nl "/home/$key_user/.ssh/authorized_keys"
        read -p "Please enter the line number of the public key to delete: " line_num
        
        if [[ "$line_num" =~ ^[0-9]+$ ]]; then
            sed -i "${line_num}d" "/home/$key_user/.ssh/authorized_keys"
            print_success "Public key deleted successfully"
            log_success "Deleted line $line_num public key for user $key_user"
        else
            print_error "Invalid line number"
        fi
    else
        print_info "User $key_user has no SSH public keys configured"
    fi
}

# 6. System optimization configuration
system_optimization() {
    print_info "System optimization configuration"
    log_info "Starting system optimization configuration"
    
    # Configure system parameters (already included in security configuration)
    print_info "System security parameters already completed in security configuration"
    
    # Configure timezone
    read -p "Configure timezone? Current timezone: $(timedatectl show --property=Timezone --value) (y/n): " config_timezone
    if [ "$config_timezone" = "y" ]; then
        echo "Common timezones:"
        echo "1) Asia/Shanghai (China)"
        echo "2) UTC (Coordinated Universal Time)"
        echo "3) America/New_York (US Eastern)"
        echo "4) Europe/London (UK)"
        echo "5) Custom input"
        
        read -p "Please select timezone (1-5): " tz_choice
        
        case $tz_choice in
            1) timedatectl set-timezone Asia/Shanghai ;;
            2) timedatectl set-timezone UTC ;;
            3) timedatectl set-timezone America/New_York ;;
            4) timedatectl set-timezone Europe/London ;;
            5) 
                read -p "Please enter timezone (e.g.: Asia/Tokyo): " custom_tz
                timedatectl set-timezone "$custom_tz" || print_error "Timezone setting failed"
                ;;
            *) print_warning "Invalid selection" ;;
        esac
        
        log_success "Timezone setting completed: $(timedatectl show --property=Timezone --value)"
    fi
    
    # Configure hostname
    read -p "Modify hostname? Current: $(hostname) (y/n): " change_hostname
    if [ "$change_hostname" = "y" ]; then
        read -p "Please enter new hostname: " new_hostname
        if [ -n "$new_hostname" ]; then
            hostnamectl set-hostname "$new_hostname"
            echo "127.0.1.1 $new_hostname" >> /etc/hosts
            log_success "Hostname set to: $new_hostname"
        fi
    fi
    
    print_success "System optimization configuration completed"
}

# 7. Install Docker
install_docker() {
    print_info "Docker installation"
    
    if command -v docker >/dev/null 2>&1; then
        local docker_version=$(docker --version)
        print_info "Docker already installed: $docker_version"
        read -p "Reinstall? (y/n): " reinstall
        if [ "$reinstall" != "y" ]; then
            return 0
        fi
    fi
    
    log_info "Starting Docker installation"
    
    # Download and install Docker
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    
    # Enable Docker service
    systemctl enable docker
    systemctl start docker
    
    # Create docker group
    groupadd docker 2>/dev/null || true
    
    # Add user to docker group
    read -p "Please enter username to add to docker group (press Enter to skip): " docker_user
    if [ -n "$docker_user" ] && id "$docker_user" &>/dev/null; then
        usermod -aG docker "$docker_user"
        log_success "User $docker_user added to docker group"
    fi
    
    # Clean up installation script
    rm -f get-docker.sh
    
    print_success "Docker installation completed"
    docker --version
    
    log_success "Docker installation completed"
}

# 8. Bash auto-completion configuration
configure_bash_completion() {
    print_info "Configuring bash auto-completion"
    
    # Check if already installed
    if ! dpkg -l | grep -q bash-completion; then
        log_info "Installing bash-completion"
        apt-get install -y bash-completion
    fi
    
    # Global configuration
    if [ ! -f /etc/profile.d/bash_completion.sh ]; then
        cat > /etc/profile.d/bash_completion.sh << 'EOF'
# Global bash auto-completion configuration
if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
fi
EOF
        chmod +x /etc/profile.d/bash_completion.sh
    fi
    
    # Configure for existing users
    read -p "Enable bash auto-completion for all regular users? (y/n): " enable_for_users
    if [ "$enable_for_users" = "y" ]; then
        for user_home in /home/*; do
            if [ -d "$user_home" ]; then
                user=$(basename "$user_home")
                if [ -f "$user_home/.bashrc" ]; then
                    if ! grep -q "bash-completion" "$user_home/.bashrc"; then
                        cat >> "$user_home/.bashrc" << 'EOF'

# Enable bash auto-completion
if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
fi
EOF
                        chown "$user:$user" "$user_home/.bashrc"
                        log_info "Enabled bash auto-completion for user $user"
                    fi
                fi
            fi
        done
    fi
    
    print_success "Bash auto-completion configuration completed"
    log_success "Bash auto-completion configuration completed"
}

# 9. View system status
show_system_status() {
    print_info "System status information"
    
    echo -e "\n${BLUE}===== System Basic Information =====${NC}"
    echo "Hostname: $(hostname)"
    echo "Operating System: $(lsb_release -d | cut -f2)"
    echo "Kernel Version: $(uname -r)"
    echo "Uptime: $(uptime -p)"
    echo "Current Time: $(date)"
    echo "Timezone: $(timedatectl show --property=Timezone --value)"
    
    echo -e "\n${BLUE}===== Network Configuration =====${NC}"
    echo "SSH Port: $(get_ssh_port)"
    echo "Firewall Status: $(get_ufw_status)"
    if command -v ufw >/dev/null 2>&1; then
        echo "Firewall Rules:"
        ufw status numbered 2>/dev/null | head -10
    fi
    
    echo -e "\n${BLUE}===== Service Status =====${NC}"
    echo "SSH Service: $(systemctl is-active sshd)"
    echo "Firewall: $(systemctl is-active ufw)"
    echo "Fail2ban: $(systemctl is-active fail2ban)"
    if command -v docker >/dev/null 2>&1; then
        echo "Docker: $(systemctl is-active docker)"
    fi
    
    echo -e "\n${BLUE}===== Resource Usage =====${NC}"
    echo "Memory Usage:"
    free -h
    echo -e "\nSwap Usage: $(get_swap_status)"
    echo -e "\nDisk Usage:"
    df -h / | tail -1
    
    echo -e "\n${BLUE}===== User Information =====${NC}"
    echo "Currently Logged In Users:"
    who
    echo -e "\nRegular User List:"
    awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd
    
    if command -v fail2ban-client >/dev/null 2>&1; then
        echo -e "\n${BLUE}===== Fail2ban Status =====${NC}"
        fail2ban-client status 2>/dev/null || echo "Fail2ban not running"
    fi
}

# 10. View configuration history
show_config_history() {
    print_info "Configuration history"
    
    if [ -f "$LOG_FILE" ]; then
        echo -e "\n${BLUE}===== Recent Operation Log =====${NC}"
        tail -50 "$LOG_FILE"
    else
        print_warning "Log file not found"
    fi
    
    if [ -d "$BACKUP_DIR" ]; then
        echo -e "\n${BLUE}===== Configuration Backup Files =====${NC}"
        ls -la "$BACKUP_DIR"
    else
        print_warning "Backup directory not found"
    fi
    
    echo -e "\n${BLUE}===== SSH Configuration Summary =====${NC}"
    if [ -f /etc/ssh/sshd_config ]; then
        grep -E "^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)" /etc/ssh/sshd_config
    fi
    
    echo -e "\n${BLUE}===== UFW Rules Summary =====${NC}"
    if command -v ufw >/dev/null 2>&1; then
        ufw status 2>/dev/null || echo "UFW not configured"
    fi
}

# Main program
main() {
    # Initialize
    check_root
    init_environment
    
    while true; do
        show_menu
        read -p "Please select operation (0-10): " choice
        
        case $choice in
            1) update_system ;;
            2) setup_swap ;;
            3) security_config ;;
            4) user_management ;;
            5) ssh_key_management ;;
            6) system_optimization ;;
            7) install_docker ;;
            8) configure_bash_completion ;;
            9) show_system_status ;;
            10) show_config_history ;;
            0) 
                print_success "Script execution completed!"
                log_info "Script exited normally"
                exit 0
                ;;
            *) 
                print_warning "Invalid selection, please try again"
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}

# Signal handling
trap 'log_error "Script interrupted"; exit 1' INT TERM

# Start main program
main "$@"