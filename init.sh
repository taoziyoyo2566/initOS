#!/bin/bash

# Enhanced System Initialization Script
# 功能：系统初始化、安全配置、用户管理、软件安装
# 特点：可重复执行、配置修改、错误处理、日志记录

set -euo pipefail  # 严格模式：遇到错误立即退出

# 全局变量
SCRIPT_NAME="Enhanced System Init"
LOG_FILE="/var/log/system_init.log"
CONFIG_DIR="/etc/system_init"
BACKUP_DIR="/etc/system_init/backups"
SSH_PORT=32798

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志记录函数
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

# 彩色输出函数
print_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $*"; }
print_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# 错误处理函数
error_exit() {
    log_error "$1"
    print_error "$1"
    exit 1
}

# 检查是否为root用户
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error_exit "请以root用户运行此脚本"
    fi
}

# 初始化环境
init_environment() {
    print_info "初始化环境..."
    
    # 创建必要目录
    mkdir -p "$CONFIG_DIR" "$BACKUP_DIR"
    
    # 创建日志文件
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    
    log_info "脚本启动 - $SCRIPT_NAME"
    log_info "日志文件: $LOG_FILE"
    
    print_success "环境初始化完成"
}

# 备份配置文件
backup_file() {
    local file=$1
    local backup_name=$(basename "$file").$(date +%Y%m%d_%H%M%S)
    
    if [ -f "$file" ]; then
        cp "$file" "$BACKUP_DIR/$backup_name"
        log_info "备份文件: $file -> $BACKUP_DIR/$backup_name"
        return 0
    fi
    return 1
}

# 检查服务状态
check_service() {
    local service=$1
    if systemctl is-active --quiet "$service"; then
        return 0
    else
        return 1
    fi
}

# 安全地重启服务
restart_service() {
    local service=$1
    log_info "重启服务: $service"
    
    if systemctl restart "$service"; then
        log_success "服务 $service 重启成功"
        return 0
    else
        log_error "服务 $service 重启失败"
        return 1
    fi
}

# 主菜单
show_menu() {
    clear
    echo -e "${BLUE}===== $SCRIPT_NAME =====${NC}"
    echo -e "${GREEN}当前配置状态:${NC}"
    echo "  SSH端口: $(get_ssh_port)"
    echo "  防火墙状态: $(get_ufw_status)"
    echo "  Fail2ban状态: $(get_fail2ban_status)"
    echo "  Swap状态: $(get_swap_status)"
    echo ""
    echo "请选择要执行的操作:"
    echo "1) 🔄 系统更新和软件安装"
    echo "2) 💾 设置Swap分区"
    echo "3) 🔒 安全配置 (SSH/防火墙/Fail2ban)"
    echo "4) 👤 用户管理"
    echo "5) 🔑 SSH密钥管理"
    echo "6) ⚙️  系统优化配置"
    echo "7) 📦 安装Docker"
    echo "8) 🛠️  bash自动补全配置"
    echo "9) 🔍 查看系统状态"
    echo "10) 📋 查看配置历史"
    echo "0) 退出"
    echo ""
}

# 获取当前配置状态
get_ssh_port() {
    if [ -f /etc/ssh/sshd_config ]; then
        grep "^Port" /etc/ssh/sshd_config | awk '{print $2}' || echo "22"
    else
        echo "未配置"
    fi
}

get_ufw_status() {
    if command -v ufw >/dev/null 2>&1; then
        ufw status | head -1 | awk '{print $2}' || echo "未安装"
    else
        echo "未安装"
    fi
}

get_fail2ban_status() {
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        echo "运行中"
    else
        echo "未运行"
    fi
}

get_swap_status() {
    local swap_total=$(free -h | grep Swap | awk '{print $2}')
    if [ "$swap_total" = "0B" ]; then
        echo "未配置"
    else
        echo "$swap_total"
    fi
}

# 1. 系统更新和软件安装
update_system() {
    print_info "开始系统更新和软件安装..."
    
    log_info "更新软件包列表"
    apt-get update || error_exit "软件包列表更新失败"
    
    log_info "升级系统软件包"
    apt-get upgrade -y || error_exit "系统升级失败"
    
    log_info "完整系统升级"
    apt-get dist-upgrade -y || log_warn "完整升级部分失败，继续执行"
    
    log_info "安装基础软件包"
    local packages=(
        "curl" "vim" "ufw" "jq" "sudo" "fail2ban" 
        "unattended-upgrades" "apt-listchanges" "bash-completion" 
        "git" "net-tools" "dnsutils" "gh" "htop" "tree"
    )
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            log_info "安装软件包: $package"
            apt-get install -y "$package" || log_warn "软件包 $package 安装失败"
        else
            log_info "软件包 $package 已安装"
        fi
    done
    
    # 配置自动更新
    configure_auto_updates
    
    print_success "系统更新和软件安装完成"
}

# 配置自动更新
configure_auto_updates() {
    log_info "配置自动安全更新"
    
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
EOF
    
    log_success "自动更新配置完成"
}

# 2. 设置Swap分区
setup_swap() {
    print_info "Swap分区配置"
    
    local current_swap=$(get_swap_status)
    echo "当前Swap状态: $current_swap"
    
    if [ "$current_swap" != "未配置" ]; then
        read -p "检测到已有Swap分区，是否重新配置？(y/n): " reconfigure
        if [ "$reconfigure" != "y" ]; then
            return 0
        fi
        
        # 禁用现有swap
        swapoff -a || true
        sed -i '/swapfile/d' /etc/fstab
        rm -f /swapfile
    fi
    
    read -p "请输入Swap大小（单位：G），直接回车跳过: " swap_size
    
    if [[ -n "$swap_size" && "$swap_size" =~ ^[0-9]+$ ]]; then
        log_info "创建 ${swap_size}G 的Swap分区"
        
        # 创建swap文件
        if command -v fallocate >/dev/null 2>&1; then
            fallocate -l "${swap_size}G" /swapfile
        else
            dd if=/dev/zero of=/swapfile bs=1G count="$swap_size"
        fi
        
        # 设置权限和格式化
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        
        # 添加到fstab（检查是否已存在）
        if ! grep -q "/swapfile" /etc/fstab; then
            echo "/swapfile none swap sw 0 0" >> /etc/fstab
        fi
        
        # 优化swap使用
        if ! grep -q "vm.swappiness" /etc/sysctl.conf; then
            echo "vm.swappiness=10" >> /etc/sysctl.conf
        fi
        sysctl -p
        
        log_success "Swap分区设置完成: ${swap_size}G"
        print_success "Swap分区配置完成"
    else
        print_info "跳过Swap配置"
    fi
}

# 3. 安全配置
security_config() {
    print_info "开始安全配置..."
    
    # SSH配置
    configure_ssh
    
    # 防火墙配置
    configure_firewall
    
    # Fail2ban配置
    configure_fail2ban
    
    # 系统安全参数
    configure_system_security
    
    print_success "安全配置完成"
}

# SSH配置
configure_ssh() {
    log_info "配置SSH安全设置"
    
    # 备份现有配置
    backup_file "/etc/ssh/sshd_config"
    
    # 询问SSH端口
    local current_port=$(get_ssh_port)
    read -p "SSH端口 (当前: $current_port, 直接回车使用$SSH_PORT): " new_port
    new_port=${new_port:-$SSH_PORT}
    
    # 创建安全的SSH配置
    cat > /etc/ssh/sshd_config << EOF
# SSH安全配置 - 由系统初始化脚本生成
Port $new_port
Protocol 2

# 主机密钥
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# 强化加密算法
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# 认证设置
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# 会话安全
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 300
ClientAliveCountMax 2

# 功能限制
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*

# SFTP子系统
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
    
    # 测试配置
    if sshd -t; then
        restart_service "sshd"
        log_success "SSH配置更新完成，端口: $new_port"
        SSH_PORT=$new_port
    else
        log_error "SSH配置测试失败，恢复备份"
        # 恢复备份（这里可以添加备份恢复逻辑）
    fi
}

# 防火墙配置
configure_firewall() {
    log_info "配置UFW防火墙"
    
    # 确保UFW已安装
    if ! command -v ufw >/dev/null 2>&1; then
        log_error "UFW未安装"
        return 1
    fi
    
    # 基础规则
    ufw default deny incoming
    ufw default allow outgoing
    
    # SSH端口
    ufw allow "$SSH_PORT/tcp" comment 'SSH'
    
    # Web服务端口
    read -p "是否开放HTTP(80)和HTTPS(443)端口？(y/n): " open_web
    if [ "$open_web" = "y" ]; then
        ufw allow http comment 'HTTP'
        ufw allow https comment 'HTTPS'
    fi
    
    # Redis端口
    read -p "是否开放Redis端口(6379)？(y/n): " open_redis
    if [ "$open_redis" = "y" ]; then
        ufw allow 6379/tcp comment 'Redis'
    fi
    
    # 自定义端口
    read -p "是否需要开放其他端口？(格式: 端口/协议 描述, 如: 3306/tcp MySQL): " custom_port
    if [ -n "$custom_port" ]; then
        ufw allow $custom_port
    fi
    
    # 启用日志
    ufw logging on
    
    # 启用防火墙
    ufw --force enable
    systemctl enable ufw
    
    log_success "UFW防火墙配置完成"
}

# Fail2ban配置
configure_fail2ban() {
    log_info "配置Fail2ban入侵防护"
    
    # 备份现有配置
    backup_file "/etc/fail2ban/jail.local"
    
    # 创建jail.local配置
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# 基本设置
bantime = 3600
findtime = 600
maxretry = 5
banaction = ufw

# SSH保护 - 基本配置
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF
    
    # 测试配置
    log_info "测试Fail2ban配置"
    if fail2ban-client -t >/dev/null 2>&1; then
        log_success "基本配置测试通过"
        
        # 启动服务
        systemctl enable fail2ban
        if restart_service "fail2ban"; then
            log_success "Fail2ban基本配置完成"
            
            # 询问是否添加扩展保护
            echo ""
            read -p "是否添加扩展服务保护 (Apache/Nginx/Postfix)？(y/n): " add_extended
            if [ "$add_extended" = "y" ]; then
                add_extended_protection
            fi
        else
            log_error "Fail2ban启动失败"
        fi
    else
        log_error "Fail2ban配置测试失败，显示错误:"
        fail2ban-client -t || true
        log_warn "保持最小配置，稍后可手动修复"
    fi
}

# 添加扩展保护
add_extended_protection() {
    log_info "添加扩展服务保护"
    
    # 检查Apache
    if [ -d /etc/apache2 ] && [ -f /var/log/apache2/error.log ]; then
        log_info "检测到Apache，添加保护规则"
        cat >> /etc/fail2ban/jail.local << 'EOF'

# Apache保护
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/error.log
maxretry = 3
EOF
    fi
    
    # 检查Nginx
    if [ -d /etc/nginx ] && [ -f /var/log/nginx/error.log ]; then
        log_info "检测到Nginx，添加保护规则"
        cat >> /etc/fail2ban/jail.local << 'EOF'

# Nginx保护
[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3
EOF
    fi
    
    # 检查Postfix
    if [ -d /etc/postfix ] && [ -f /var/log/mail.log ]; then
        log_info "检测到Postfix，添加保护规则"
        cat >> /etc/fail2ban/jail.local << 'EOF'

# Postfix保护
[postfix]
enabled = true
port = smtp,465,submission
filter = postfix
logpath = /var/log/mail.log
maxretry = 3
EOF
    fi
    
    # 测试扩展配置
    if fail2ban-client -t >/dev/null 2>&1; then
        log_info "重新加载扩展配置"
        systemctl reload fail2ban
        sleep 2
        log_success "扩展保护配置完成"
    else
        log_error "扩展配置有错误，恢复基本配置"
        # 恢复基本配置
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
    
    # 创建Redis过滤器
    mkdir -p /etc/fail2ban/filter.d
    cat > /etc/fail2ban/filter.d/redis-server.conf << 'EOF'
[Definition]
failregex = ^ WARNING .* Client .* @ <HOST> .*
ignoreregex =
EOF
    
    systemctl enable fail2ban
    restart_service "fail2ban"
    
    log_success "Fail2ban配置完成"
}

# 系统安全参数配置
configure_system_security() {
    log_info "配置系统安全参数"
    
    # 文件权限掩码
    if ! grep -q "umask 027" /etc/profile; then
        echo "umask 027" >> /etc/profile
    fi
    
    # 限制core dumps
    if ! grep -q "hard core 0" /etc/security/limits.conf; then
        echo "* hard core 0" >> /etc/security/limits.conf
    fi
    
    # 系统资源限制
    cat >> /etc/security/limits.conf << 'EOF'

# 系统资源限制 - 由系统初始化脚本添加
* soft nofile 65535
* hard nofile 65535
* soft nproc 4096
* hard nproc 4096
EOF
    
    # 网络安全参数
    cat > /etc/sysctl.d/99-security.conf << 'EOF'
# 网络安全配置 - 由系统初始化脚本生成

# IP安全设置
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# TCP/IP安全设置
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# 文件系统安全
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# 内存管理优化
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 2
EOF
    
    sysctl -p /etc/sysctl.d/99-security.conf
    
    log_success "系统安全参数配置完成"
}

# 4. 用户管理
user_management() {
    print_info "用户管理"
    
    echo "请选择操作:"
    echo "1) 创建新用户"
    echo "2) 修改现有用户"
    echo "3) 删除用户"
    echo "4) 查看用户列表"
    
    read -p "请选择 (1-4): " user_choice
    
    case $user_choice in
        1) create_user ;;
        2) modify_user ;;
        3) delete_user ;;
        4) list_users ;;
        *) print_warning "无效选择" ;;
    esac
}

# 创建用户
create_user() {
    read -p "请输入要创建的用户名: " new_user
    
    if [ -z "$new_user" ]; then
        print_error "用户名不能为空"
        return 1
    fi
    
    if id "$new_user" &>/dev/null; then
        print_warning "用户 $new_user 已存在"
        return 1
    fi
    
    # 创建用户
    useradd -m -s /bin/bash "$new_user"
    
    # 设置密码
    read -p "请输入密码 (直接回车使用用户名作为密码): " user_password
    user_password=${user_password:-$new_user}
    echo "$new_user:$user_password" | chpasswd
    
    # 添加到组
    read -p "是否将用户添加到sudo组？(y/n): " add_sudo
    if [ "$add_sudo" = "y" ]; then
        usermod -aG sudo "$new_user"
        echo "$new_user ALL=(ALL) NOPASSWD: ALL" > "/etc/sudoers.d/$new_user"
        chmod 440 "/etc/sudoers.d/$new_user"
    fi
    
    read -p "是否将用户添加到docker组？(y/n): " add_docker
    if [ "$add_docker" = "y" ]; then
        if getent group docker >/dev/null; then
            usermod -aG docker "$new_user"
        else
            print_warning "Docker组不存在，请先安装Docker"
        fi
    fi
    
    log_success "用户 $new_user 创建完成"
    print_success "用户创建完成，密码: $user_password"
}

# 修改用户
modify_user() {
    read -p "请输入要修改的用户名: " target_user
    
    if ! id "$target_user" &>/dev/null; then
        print_error "用户 $target_user 不存在"
        return 1
    fi
    
    echo "当前用户 $target_user 的组:"
    groups "$target_user"
    
    echo "请选择修改操作:"
    echo "1) 重置密码"
    echo "2) 添加到sudo组"
    echo "3) 从sudo组移除"
    echo "4) 添加到docker组"
    echo "5) 从docker组移除"
    
    read -p "请选择 (1-5): " modify_choice
    
    case $modify_choice in
        1) 
            read -p "请输入新密码: " new_password
            echo "$target_user:$new_password" | chpasswd
            log_success "用户 $target_user 密码已重置"
            ;;
        2) 
            usermod -aG sudo "$target_user"
            log_success "用户 $target_user 已添加到sudo组"
            ;;
        3) 
            gpasswd -d "$target_user" sudo
            rm -f "/etc/sudoers.d/$target_user"
            log_success "用户 $target_user 已从sudo组移除"
            ;;
        4) 
            usermod -aG docker "$target_user"
            log_success "用户 $target_user 已添加到docker组"
            ;;
        5) 
            gpasswd -d "$target_user" docker
            log_success "用户 $target_user 已从docker组移除"
            ;;
        *) print_warning "无效选择" ;;
    esac
}

# 删除用户
delete_user() {
    read -p "请输入要删除的用户名: " target_user
    
    if ! id "$target_user" &>/dev/null; then
        print_error "用户 $target_user 不存在"
        return 1
    fi
    
    read -p "确认删除用户 $target_user 及其主目录？(yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        userdel -r "$target_user" 2>/dev/null || userdel "$target_user"
        rm -f "/etc/sudoers.d/$target_user"
        log_success "用户 $target_user 已删除"
    else
        print_info "取消删除操作"
    fi
}

# 列出用户
list_users() {
    print_info "系统用户列表:"
    echo "常规用户:"
    awk -F: '$3 >= 1000 && $3 < 65534 {print $1 " (UID: " $3 ")"}' /etc/passwd
    echo ""
    echo "系统用户:"
    awk -F: '$3 < 1000 || $3 >= 65534 {print $1 " (UID: " $3 ")"}' /etc/passwd | head -10
}

# 5. SSH密钥管理
ssh_key_management() {
    print_info "SSH密钥管理"
    
    echo "请选择操作:"
    echo "1) 为用户添加公钥"
    echo "2) 为用户生成密钥对"
    echo "3) 查看用户公钥"
    echo "4) 删除用户公钥"
    
    read -p "请选择 (1-4): " key_choice
    
    case $key_choice in
        1) add_public_key ;;
        2) generate_key_pair ;;
        3) view_public_keys ;;
        4) remove_public_key ;;
        *) print_warning "无效选择" ;;
    esac
}

# 添加公钥
add_public_key() {
    read -p "请输入用户名: " key_user
    
    if ! id "$key_user" &>/dev/null; then
        print_error "用户 $key_user 不存在"
        return 1
    fi
    
    # 创建.ssh目录
    mkdir -p "/home/$key_user/.ssh"
    chmod 700 "/home/$key_user/.ssh"
    
    echo "请粘贴公钥内容 (以ssh-开头，多行请用空格连接):"
    read -r pubkey
    
    if [ -n "$pubkey" ]; then
        echo "$pubkey" >> "/home/$key_user/.ssh/authorized_keys"
        chmod 600 "/home/$key_user/.ssh/authorized_keys"
        chown -R "$key_user:$key_user" "/home/$key_user/.ssh"
        
        log_success "公钥已添加到用户 $key_user"
        print_success "SSH公钥添加成功"
    else
        print_error "公钥内容为空"
    fi
}

# 生成密钥对
generate_key_pair() {
    read -p "请输入用户名: " key_user
    
    if ! id "$key_user" &>/dev/null; then
        print_error "用户 $key_user 不存在"
        return 1
    fi
    
    # 创建.ssh目录
    mkdir -p "/home/$key_user/.ssh"
    chmod 700 "/home/$key_user/.ssh"
    chown "$key_user:$key_user" "/home/$key_user/.ssh"
    
    read -p "请输入密钥密码 (直接回车为空密码): " key_password
    
    # 生成密钥
    su - "$key_user" -c "ssh-keygen -t ed25519 -N '$key_password' -f /home/$key_user/.ssh/id_ed25519"
    
    # 添加公钥到authorized_keys
    cat "/home/$key_user/.ssh/id_ed25519.pub" >> "/home/$key_user/.ssh/authorized_keys"
    chmod 600 "/home/$key_user/.ssh/authorized_keys"
    chown "$key_user:$key_user" "/home/$key_user/.ssh/authorized_keys"
    
    print_success "SSH密钥对生成完成"
    echo "私钥位置: /home/$key_user/.ssh/id_ed25519"
    echo "公钥内容:"
    cat "/home/$key_user/.ssh/id_ed25519.pub"
    
    log_success "为用户 $key_user 生成SSH密钥对"
}

# 查看公钥
view_public_keys() {
    read -p "请输入用户名: " key_user
    
    if ! id "$key_user" &>/dev/null; then
        print_error "用户 $key_user 不存在"
        return 1
    fi
    
    if [ -f "/home/$key_user/.ssh/authorized_keys" ]; then
        print_info "用户 $key_user 的授权公钥:"
        cat "/home/$key_user/.ssh/authorized_keys"
    else
        print_info "用户 $key_user 没有配置SSH公钥"
    fi
}

# 删除公钥
remove_public_key() {
    read -p "请输入用户名: " key_user
    
    if ! id "$key_user" &>/dev/null; then
        print_error "用户 $key_user 不存在"
        return 1
    fi
    
    if [ -f "/home/$key_user/.ssh/authorized_keys" ]; then
        echo "当前公钥:"
        nl "/home/$key_user/.ssh/authorized_keys"
        read -p "请输入要删除的公钥行号: " line_num
        
        if [[ "$line_num" =~ ^[0-9]+$ ]]; then
            sed -i "${line_num}d" "/home/$key_user/.ssh/authorized_keys"
            print_success "公钥删除成功"
            log_success "删除用户 $key_user 的第 $line_num 行公钥"
        else
            print_error "无效的行号"
        fi
    else
        print_info "用户 $key_user 没有配置SSH公钥"
    fi
}

# 6. 系统优化配置
system_optimization() {
    print_info "系统优化配置"
    log_info "开始系统优化配置"
    
    # 配置系统参数（已在安全配置中包含）
    print_info "系统安全参数已在安全配置中完成"
    
    # 配置时区
    read -p "是否配置时区？当前时区: $(timedatectl show --property=Timezone --value) (y/n): " config_timezone
    if [ "$config_timezone" = "y" ]; then
        echo "常用时区:"
        echo "1) Asia/Shanghai (中国)"
        echo "2) UTC (协调世界时)"
        echo "3) America/New_York (美国东部)"
        echo "4) Europe/London (英国)"
        echo "5) 自定义输入"
        
        read -p "请选择时区 (1-5): " tz_choice
        
        case $tz_choice in
            1) timedatectl set-timezone Asia/Shanghai ;;
            2) timedatectl set-timezone UTC ;;
            3) timedatectl set-timezone America/New_York ;;
            4) timedatectl set-timezone Europe/London ;;
            5) 
                read -p "请输入时区 (如: Asia/Tokyo): " custom_tz
                timedatectl set-timezone "$custom_tz" || print_error "时区设置失败"
                ;;
            *) print_warning "无效选择" ;;
        esac
        
        log_success "时区设置完成: $(timedatectl show --property=Timezone --value)"
    fi
    
    # 配置主机名
    read -p "是否修改主机名？当前: $(hostname) (y/n): " change_hostname
    if [ "$change_hostname" = "y" ]; then
        read -p "请输入新主机名: " new_hostname
        if [ -n "$new_hostname" ]; then
            hostnamectl set-hostname "$new_hostname"
            echo "127.0.1.1 $new_hostname" >> /etc/hosts
            log_success "主机名设置为: $new_hostname"
        fi
    fi
    
    print_success "系统优化配置完成"
}

# 7. 安装Docker
install_docker() {
    print_info "Docker安装"
    
    if command -v docker >/dev/null 2>&1; then
        local docker_version=$(docker --version)
        print_info "Docker已安装: $docker_version"
        read -p "是否重新安装？(y/n): " reinstall
        if [ "$reinstall" != "y" ]; then
            return 0
        fi
    fi
    
    log_info "开始安装Docker"
    
    # 下载并安装Docker
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    
    # 启用Docker服务
    systemctl enable docker
    systemctl start docker
    
    # 创建docker组
    groupadd docker 2>/dev/null || true
    
    # 添加用户到docker组
    read -p "请输入要添加到docker组的用户名 (直接回车跳过): " docker_user
    if [ -n "$docker_user" ] && id "$docker_user" &>/dev/null; then
        usermod -aG docker "$docker_user"
        log_success "用户 $docker_user 已添加到docker组"
    fi
    
    # 清理安装脚本
    rm -f get-docker.sh
    
    print_success "Docker安装完成"
    docker --version
    
    log_success "Docker安装完成"
}

# 8. bash自动补全配置
configure_bash_completion() {
    print_info "配置bash自动补全"
    
    # 检查是否已安装
    if ! dpkg -l | grep -q bash-completion; then
        log_info "安装bash-completion"
        apt-get install -y bash-completion
    fi
    
    # 全局配置
    if [ ! -f /etc/profile.d/bash_completion.sh ]; then
        cat > /etc/profile.d/bash_completion.sh << 'EOF'
# 全局bash自动补全配置
if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
fi
EOF
        chmod +x /etc/profile.d/bash_completion.sh
    fi
    
    # 为现有用户配置
    read -p "是否为所有普通用户启用bash自动补全？(y/n): " enable_for_users
    if [ "$enable_for_users" = "y" ]; then
        for user_home in /home/*; do
            if [ -d "$user_home" ]; then
                user=$(basename "$user_home")
                if [ -f "$user_home/.bashrc" ]; then
                    if ! grep -q "bash-completion" "$user_home/.bashrc"; then
                        cat >> "$user_home/.bashrc" << 'EOF'

# 启用bash自动补全
if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
fi
EOF
                        chown "$user:$user" "$user_home/.bashrc"
                        log_info "为用户 $user 启用bash自动补全"
                    fi
                fi
            fi
        done
    fi
    
    print_success "bash自动补全配置完成"
    log_success "bash自动补全配置完成"
}

# 9. 查看系统状态
show_system_status() {
    print_info "系统状态信息"
    
    echo -e "\n${BLUE}===== 系统基本信息 =====${NC}"
    echo "主机名: $(hostname)"
    echo "操作系统: $(lsb_release -d | cut -f2)"
    echo "内核版本: $(uname -r)"
    echo "运行时间: $(uptime -p)"
    echo "当前时间: $(date)"
    echo "时区: $(timedatectl show --property=Timezone --value)"
    
    echo -e "\n${BLUE}===== 网络配置 =====${NC}"
    echo "SSH端口: $(get_ssh_port)"
    echo "防火墙状态: $(get_ufw_status)"
    if command -v ufw >/dev/null 2>&1; then
        echo "防火墙规则:"
        ufw status numbered 2>/dev/null | head -10
    fi
    
    echo -e "\n${BLUE}===== 服务状态 =====${NC}"
    echo "SSH服务: $(systemctl is-active sshd)"
    echo "防火墙: $(systemctl is-active ufw)"
    echo "Fail2ban: $(systemctl is-active fail2ban)"
    if command -v docker >/dev/null 2>&1; then
        echo "Docker: $(systemctl is-active docker)"
    fi
    
    echo -e "\n${BLUE}===== 资源使用 =====${NC}"
    echo "内存使用:"
    free -h
    echo -e "\nSwap使用: $(get_swap_status)"
    echo -e "\n磁盘使用:"
    df -h / | tail -1
    
    echo -e "\n${BLUE}===== 用户信息 =====${NC}"
    echo "当前登录用户:"
    who
    echo -e "\n普通用户列表:"
    awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd
    
    if command -v fail2ban-client >/dev/null 2>&1; then
        echo -e "\n${BLUE}===== Fail2ban状态 =====${NC}"
        fail2ban-client status 2>/dev/null || echo "Fail2ban未运行"
    fi
}

# 10. 查看配置历史
show_config_history() {
    print_info "配置历史"
    
    if [ -f "$LOG_FILE" ]; then
        echo -e "\n${BLUE}===== 最近操作日志 =====${NC}"
        tail -50 "$LOG_FILE"
    else
        print_warning "没有找到日志文件"
    fi
    
    if [ -d "$BACKUP_DIR" ]; then
        echo -e "\n${BLUE}===== 配置备份文件 =====${NC}"
        ls -la "$BACKUP_DIR"
    else
        print_warning "没有找到备份目录"
    fi
    
    echo -e "\n${BLUE}===== SSH配置摘要 =====${NC}"
    if [ -f /etc/ssh/sshd_config ]; then
        grep -E "^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)" /etc/ssh/sshd_config
    fi
    
    echo -e "\n${BLUE}===== UFW规则摘要 =====${NC}"
    if command -v ufw >/dev/null 2>&1; then
        ufw status 2>/dev/null || echo "UFW未配置"
    fi
}

# 主程序
main() {
    # 初始化
    check_root
    init_environment
    
    while true; do
        show_menu
        read -p "请选择操作 (0-10): " choice
        
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
                print_success "脚本执行完成！"
                log_info "脚本正常退出"
                exit 0
                ;;
            *) 
                print_warning "无效选择，请重新输入"
                ;;
        esac
        
        echo ""
        read -p "按回车键继续..."
    done
}

# 信号处理
trap 'log_error "脚本被中断"; exit 1' INT TERM

# 启动主程序
main "$@"