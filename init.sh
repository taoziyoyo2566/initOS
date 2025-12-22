#!/bin/bash

# ==============================================================================
# Enhanced System Initialization Script (Refactored & Optimized)
# 功能：系统初始化、安全配置、用户管理、软件安装、BBR优化
# 特点：功能全量保留、安装效率优化、增加BBR/TFO支持、安全健壮性增强
# ==============================================================================

set -euo pipefail  # 严格模式：遇到错误立即退出

# 标准化PATH，避免非交互环境找不到基础命令
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# 设置非交互模式，避免apt安装时弹出紫色配置框
export DEBIAN_FRONTEND=noninteractive

# 全局变量
SCRIPT_NAME="Enhanced System Init"
LOG_FILE="/var/log/system_init.log"
CONFIG_DIR="/etc/system_init"
BACKUP_DIR="/etc/system_init/backups"
DEFAULT_SSH_PORT=32798
SSH_PORT="$DEFAULT_SSH_PORT"
SSH_DROPIN_FILE="/etc/ssh/sshd_config.d/99-initos.conf"
SYSCTL_NET_CONF="/etc/sysctl.d/99-network-optimization.conf"
LAST_BACKUP_PATH=""
AUTO_INSTALL_DEPS="y"
APT_UPDATED=0

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- 日志与基础函数 (保持原样) ---

log() {
    local level=$1
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$*"; }
log_warn() { log "WARN" "$*"; }
log_error() { log "ERROR" "$*"; }
log_success() { log "SUCCESS" "$*"; }

print_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $*"; }
print_error() { echo -e "${RED}[ERROR]${NC} $*"; }

error_exit() {
    log_error "$1"
    print_error "$1"
    exit 1
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

require_apt_get() {
    if ! command_exists apt-get; then
        log_error "未找到apt-get"
        return 1
    fi
    return 0
}

prompt_yes_no() {
    local prompt=$1
    local default=${2:-}
    local answer=""

    while true; do
        if [ "$default" = "y" ]; then
            read -p "$prompt (y/n, 默认y): " answer
            answer=${answer:-y}
        elif [ "$default" = "n" ]; then
            read -p "$prompt (y/n, 默认n): " answer
            answer=${answer:-n}
        else
            read -p "$prompt (y/n): " answer
        fi

        case "$answer" in
            y|Y) return 0 ;;
            n|N) return 1 ;;
        esac
    done
}

ensure_line_in_file() {
    local file=$1
    local line=$2
    [ ! -f "$file" ] && touch "$file"
    if ! grep -Fxq "$line" "$file"; then
        echo "$line" >> "$file"
    fi
}

set_systemd_limit() {
    local file=$1
    local key=$2
    local value=$3

    if [ ! -f "$file" ]; then
        return 0
    fi

    if grep -qE "^${key}=" "$file"; then
        sed -i -E "s/^${key}=.*/${key}=${value}/" "$file"
    elif grep -qE "^#${key}=" "$file"; then
        sed -i -E "s/^#${key}=.*/${key}=${value}/" "$file"
    else
        echo "${key}=${value}" >> "$file"
    fi
}

# --- APT 包管理优化 (逻辑优化：批量处理) ---

apt_update_once() {
    if [ "$APT_UPDATED" -eq 1 ]; then return 0; fi
    require_apt_get || return 1
    log_info "更新软件包列表"
    if ! apt-get update; then
        log_warn "软件包列表更新失败"
        return 1
    fi
    APT_UPDATED=1
    return 0
}

ensure_package() {
    local package=$1
    local cmd=${2:-$1}
    if command_exists "$cmd"; then return 0; fi
    if [ "$AUTO_INSTALL_DEPS" != "y" ]; then
        log_error "缺少命令: $cmd，且未启用自动安装"
        return 1
    fi
    require_apt_get || return 1
    apt_update_once || true
    log_info "安装依赖: $package"
    if ! apt-get install -y "$package"; then
        log_error "安装 $package 失败"
        return 1
    fi
    return 0
}

require_command() {
    local cmd=$1
    local package=${2:-}
    if command_exists "$cmd"; then return 0; fi
    if [ -n "$package" ]; then
        ensure_package "$package" "$cmd"
        return $?
    fi
    log_error "缺少命令: $cmd"
    return 1
}

# --- 辅助检查函数 (保持原样) ---

is_valid_port() {
    local port=${1:-}
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

backup_file() {
    local file=$1
    local backup_name
    backup_name=$(basename "$file").$(date +%Y%m%d_%H%M%S)
    LAST_BACKUP_PATH=""
    if [ -f "$file" ]; then
        cp "$file" "$BACKUP_DIR/$backup_name"
        LAST_BACKUP_PATH="$BACKUP_DIR/$backup_name"
        log_info "备份文件: $file -> $LAST_BACKUP_PATH"
        return 0
    fi
    return 1
}

get_user_home() {
    getent passwd "$1" | cut -d: -f6
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error_exit "请以root用户运行此脚本"
    fi
}

init_environment() {
    print_info "初始化环境..."
    mkdir -p "$CONFIG_DIR" "$BACKUP_DIR"
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    log_info "脚本启动 - $SCRIPT_NAME"
    if prompt_yes_no "缺少依赖时是否自动安装？" "y"; then
        AUTO_INSTALL_DEPS="y"
    else
        AUTO_INSTALL_DEPS="n"
    fi
    print_success "环境初始化完成"
}

check_service() {
    local service=$1
    if ! command_exists systemctl; then return 1; fi
    systemctl is-active --quiet "$service"
}

restart_service() {
    local service=$1
    log_info "重启服务: $service"
    if ! command_exists systemctl; then
        log_warn "systemctl不可用"
        return 1
    fi
    if systemctl restart "$service"; then
        log_success "服务 $service 重启成功"
        return 0
    fi
    log_error "服务 $service 重启失败"
    return 1
}

get_ssh_service_name() {
    if command_exists systemctl; then
        local unit_files
        unit_files=$(systemctl list-unit-files --type=service 2>/dev/null || true)
        if echo "$unit_files" | grep -q "^sshd.service"; then echo "sshd"; return 0; fi
        if echo "$unit_files" | grep -q "^ssh.service"; then echo "ssh"; return 0; fi
    fi
    echo "sshd"
}

safe_systemctl_state() {
    local service=$1
    if command_exists systemctl && systemctl is-active --quiet "$service" 2>/dev/null; then
        echo "active"
    else
        echo "inactive"
    fi
}

get_os_description() {
    local desc=""
    if command_exists lsb_release; then
        desc=$(lsb_release -d 2>/dev/null | cut -f2 || true)
    fi
    if [ -n "$desc" ]; then echo "$desc"; return 0; fi
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "${PRETTY_NAME:-${NAME:-未知}}"
        return 0
    fi
    echo "未知"
}

has_ssh_public_keys() {
    if [ -s /root/.ssh/authorized_keys ]; then return 0; fi
    if [ -d /home ]; then
        local key_file=""
        key_file=$(find /home -maxdepth 3 -type f -path "*/.ssh/authorized_keys" -size +0c -print -quit 2>/dev/null || true)
        if [ -n "$key_file" ]; then return 0; fi
    fi
    return 1
}

has_non_root_users() {
    local user=""
    user=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1; exit}' /etc/passwd)
    [ -n "$user" ]
}

# --- SSH Config Helper Functions (保持原样) ---

get_sshd_config_target() {
    local main_config="/etc/ssh/sshd_config"
    local dropin_dir="/etc/ssh/sshd_config.d"
    if [ -f "$main_config" ] && [ -d "$dropin_dir" ] && grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$main_config" 2>/dev/null; then
        echo "$SSH_DROPIN_FILE"
        return 0
    fi
    echo "$main_config"
}

set_sshd_option() {
    local file=$1
    local key=$2
    local value=$3
    if [ ! -f "$file" ]; then touch "$file"; fi
    if grep -qE "^[[:space:]]*Match[[:space:]]" "$file"; then
        if grep -qE "^[#[:space:]]*${key}[[:space:]]" "$file"; then
            sed -i -E "1,/^[[:space:]]*Match[[:space:]]/ s|^[#[:space:]]*${key}[[:space:]].*|${key} ${value}|" "$file"
        else
            sed -i -E "/^[[:space:]]*Match[[:space:]]/ i ${key} ${value}" "$file"
        fi
    else
        if grep -qE "^[#[:space:]]*${key}[[:space:]]" "$file"; then
            sed -i -E "s|^[#[:space:]]*${key}[[:space:]].*|${key} ${value}|" "$file"
        else
            echo "${key} ${value}" >> "$file"
        fi
    fi
}

write_sshd_dropin() {
    local file=$1
    local port=$2
    local permit_root=$3
    local password_auth=$4
    mkdir -p "$(dirname "$file")"
    cat > "$file" << EOF
# SSH安全配置 - 由系统初始化脚本生成
Port $port
PermitRootLogin $permit_root
PasswordAuthentication $password_auth
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
}

apply_ssh_config() {
    local file=$1
    local use_dropin=$2
    local port=$3
    local permit_root=$4
    local password_auth=$5
    if [ "$use_dropin" = "yes" ]; then
        write_sshd_dropin "$file" "$port" "$permit_root" "$password_auth"
    else
        set_sshd_option "$file" "Port" "$port"
        set_sshd_option "$file" "PermitRootLogin" "$permit_root"
        set_sshd_option "$file" "PasswordAuthentication" "$password_auth"
        set_sshd_option "$file" "PubkeyAuthentication" "yes"
        set_sshd_option "$file" "PermitEmptyPasswords" "no"
        set_sshd_option "$file" "ChallengeResponseAuthentication" "no"
        set_sshd_option "$file" "UsePAM" "yes"
        set_sshd_option "$file" "X11Forwarding" "no"
        set_sshd_option "$file" "LoginGraceTime" "30"
        set_sshd_option "$file" "MaxAuthTries" "3"
        set_sshd_option "$file" "MaxSessions" "5"
        set_sshd_option "$file" "ClientAliveInterval" "300"
        set_sshd_option "$file" "ClientAliveCountMax" "2"
    fi
}

test_and_restart_sshd() {
    if ! command_exists sshd; then
        log_error "未找到sshd命令，无法测试配置"
        return 1
    fi
    if ! sshd -t -f /etc/ssh/sshd_config; then
        log_error "SSH配置测试失败"
        return 1
    fi
    local ssh_service
    ssh_service=$(get_ssh_service_name)
    restart_service "$ssh_service"
}

restore_config() {
    local target=$1
    local backup=$2
    local existed=$3
    if [ -n "$backup" ] && [ -f "$backup" ]; then
        cp "$backup" "$target"
        return 0
    fi
    if [ "$existed" = "no" ]; then
        rm -f "$target"
    fi
    return 0
}

ufw_has_rule() {
    local needle=$1
    if ! command_exists ufw; then return 1; fi
    local status=""
    status=$(ufw status 2>/dev/null || true)
    echo "$status" | grep -qF "$needle"
}

# --- 菜单 (新增第11项) ---

show_menu() {
    clear
    echo -e "${BLUE}===== $SCRIPT_NAME =====${NC}"
    echo -e "${GREEN}当前配置状态:${NC}"
    echo "  SSH端口: $(get_ssh_port)"
    echo "  防火墙状态: $(get_ufw_status)"
    echo "  Fail2ban状态: $(get_fail2ban_status)"
    echo "  Swap状态: $(get_swap_status)"
    echo "  BBR状态: $(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')"
    echo ""
    echo "请选择要执行的操作:"
    echo "1) 🔄 系统更新和软件安装 (优化版)"
    echo "2) 💾 设置Swap分区 (含空间检查)"
    echo "3) 🔒 安全配置 (SSH/防火墙/Fail2ban)"
    echo "4) 👤 用户管理"
    echo "5) 🔑 SSH密钥管理"
    echo "6) ⚙️  系统优化配置 (时区/主机名)"
    echo "7) 📦 安装Docker"
    echo "8) 🛠️  bash自动补全配置"
    echo "9) 🔍 查看系统状态"
    echo "10) 📋 查看配置历史"
    echo -e "${YELLOW}11) 🚀 BBR与网络优化配置 (新增)${NC}"
    echo "0) 退出"
    echo ""
}

# --- 状态获取函数 (保持原样) ---

get_ssh_port() {
    local port=""
    if command_exists sshd; then
        port=$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}' || true)
    fi
    if [ -z "$port" ] && [ -f "$SSH_DROPIN_FILE" ]; then
        port=$(grep -E "^[[:space:]]*Port[[:space:]]+" "$SSH_DROPIN_FILE" | tail -1 | awk '{print $2}' || true)
    fi
    if [ -z "$port" ] && [ -f /etc/ssh/sshd_config ]; then
        port=$(grep -E "^[[:space:]]*Port[[:space:]]+" /etc/ssh/sshd_config | tail -1 | awk '{print $2}' || true)
    fi
    if [ -n "$port" ]; then echo "$port"; elif [ -f /etc/ssh/sshd_config ] || [ -d /etc/ssh/sshd_config.d ]; then echo "22"; else echo "未配置"; fi
}

get_ufw_status() {
    if command_exists ufw; then
        local status=$(ufw status 2>/dev/null | head -1 | awk '{print $2}' || true)
        echo "${status:-未知}"
    else echo "未安装"; fi
}

get_fail2ban_status() {
    if command_exists fail2ban-client; then
        if command_exists systemctl && systemctl is-active --quiet fail2ban 2>/dev/null; then echo "运行中"; else echo "未运行"; fi
    else echo "未安装"; fi
}

get_swap_status() {
    if ! command_exists free; then echo "未知"; return 0; fi
    local swap_total=$(free -h | awk '/Swap/ {print $2}')
    if [ "$swap_total" = "0B" ]; then echo "未配置"; else echo "$swap_total"; fi
}

# --- 1. 系统更新 (优化：批量安装 + Systemd 资源限制) ---

update_system() {
    print_info "开始系统更新和软件安装..."
    if ! require_apt_get; then error_exit "未找到apt-get，仅支持Debian/Ubuntu系系统"; fi

    log_info "更新软件包列表"
    apt-get update || error_exit "软件包列表更新失败"

    log_info "批量安装基础软件包"
    # 使用数组进行批量安装，提升效率
    local packages=(
        "curl" "vim" "ufw" "jq" "sudo" "fail2ban"
        "unattended-upgrades" "apt-listchanges" "bash-completion"
        "git" "net-tools" "dnsutils" "gh" "htop" "tree" "procps"
    )
    if ! apt-get install -y "${packages[@]}"; then
        log_warn "批量安装部分失败，尝试修复"
        apt-get install -f -y || true
    fi

    log_info "升级系统软件包"
    apt-get dist-upgrade -y || log_warn "系统升级部分失败"

    configure_auto_updates

    print_success "系统更新和软件安装完成"
}

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

# --- 2. Swap 配置 (优化：增加磁盘空间检测) ---

setup_swap() {
    print_info "Swap分区配置"
    if ! require_command mkswap util-linux || ! require_command swapon util-linux; then
        log_error "缺少必要命令，无法配置Swap"; return 1;
    fi

    local current_swap=$(get_swap_status)
    echo "当前Swap状态: $current_swap"

    if [ "$current_swap" != "未配置" ] && [ "$current_swap" != "未知" ]; then
        if ! prompt_yes_no "检测到已有Swap分区，是否重新配置？" "n"; then return 0; fi
        swapoff -a || true
        sed -i '/swapfile/d' /etc/fstab
        rm -f /swapfile
    fi

    read -p "请输入Swap大小（单位：G），直接回车跳过: " swap_size

    if [[ -n "$swap_size" && "$swap_size" =~ ^[0-9]+$ && "$swap_size" -gt 0 ]]; then
        # 优化：空间检查
        local free_space_mb=$(df -m / | awk 'NR==2 {print $4}')
        local required_mb=$((swap_size * 1024))
        
        if [ "$required_mb" -gt "$free_space_mb" ]; then
            log_error "磁盘剩余空间不足 (剩余: ${free_space_mb}MB, 需要: ${required_mb}MB)"
            return 1
        fi

        log_info "创建 ${swap_size}G 的Swap分区"
        if command_exists fallocate; then
            fallocate -l "${swap_size}G" /swapfile
        else
            dd if=/dev/zero of=/swapfile bs=1G count="$swap_size" status=progress
        fi

        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        ensure_line_in_file /etc/fstab "/swapfile none swap sw 0 0"

        cat > /etc/sysctl.d/99-swap.conf << 'EOF'
vm.swappiness = 10
EOF
        sysctl -p /etc/sysctl.d/99-swap.conf || log_warn "加载swap参数失败"
        log_success "Swap分区设置完成: ${swap_size}G"
        print_success "Swap分区配置完成"
    else
        print_info "跳过Swap配置"
    fi
}

# --- 3. 安全配置 (修改：SSH修改端口不重启UFW) ---

security_config() {
    print_info "开始安全配置..."
    configure_ssh || log_warn "SSH配置未完成"
    configure_firewall || log_warn "防火墙配置未完成"
    configure_fail2ban || log_warn "Fail2ban配置未完成"
    configure_system_security || log_warn "系统安全参数配置未完成"
    print_success "安全配置完成"
}

configure_ssh() {
    log_info "配置SSH安全设置"
    if ! ensure_package "openssh-server" "sshd"; then
        log_error "OpenSSH未安装，跳过SSH配置"; return 1;
    fi

    local config_target=$(get_sshd_config_target)
    local use_dropin="no"
    if [ "$config_target" = "$SSH_DROPIN_FILE" ]; then use_dropin="yes"; fi
    local config_existed="no"
    local ssh_backup=""
    if [ -f "$config_target" ]; then
        config_existed="yes"
        backup_file "$config_target"
        ssh_backup="$LAST_BACKUP_PATH"
    fi

    local current_port=$(get_ssh_port)
    if ! is_valid_port "$current_port"; then current_port="22"; fi

    read -p "SSH端口 (当前: $current_port, 直接回车保持当前端口): " new_port
    new_port=${new_port:-$current_port}
    if ! is_valid_port "$new_port"; then
        print_warning "无效端口，使用当前端口: $current_port"
        new_port="$current_port"
    fi

    local want_disable_password="no"
    if has_ssh_public_keys; then
        if prompt_yes_no "是否计划禁用密码登录（需先验证密钥登录）" "y"; then want_disable_password="yes"; fi
    else
        print_warning "未检测到SSH公钥，暂不建议禁用密码登录"
    fi

    local password_auth="yes"
    local permit_root="no"
    if prompt_yes_no "是否允许root通过SSH登录（不推荐）" "n"; then
        permit_root="prohibit-password"
        if prompt_yes_no "是否允许root使用密码登录" "n"; then permit_root="yes"; fi
    else
        if ! has_non_root_users; then
            print_warning "未检测到普通用户，禁用root登录可能导致无法SSH登录"
            if prompt_yes_no "是否临时允许root通过SSH登录" "y"; then
                permit_root="prohibit-password"
                if prompt_yes_no "是否允许root使用密码登录" "n"; then permit_root="yes"; fi
            fi
        fi
    fi

    apply_ssh_config "$config_target" "$use_dropin" "$new_port" "$permit_root" "$password_auth"

    if [ "$current_port" != "$new_port" ] && command_exists ufw; then
        if ! ufw_has_rule "$new_port/tcp"; then
            ufw allow "$new_port/tcp" comment 'SSH' || log_warn "UFW放行端口失败: $new_port"
            log_info "已预先放行SSH端口: $new_port"
        fi
    fi

    if ! test_and_restart_sshd; then
        log_error "SSH配置测试或重启失败，恢复备份"
        restore_config "$config_target" "$ssh_backup" "$config_existed"
        test_and_restart_sshd || true
        return 1
    fi

    SSH_PORT="$new_port"
    log_success "SSH基础配置完成，端口: $new_port"

    # 重要：针对修改端口后的特别提醒
    if [ "$current_port" != "$new_port" ] && ! command_exists ufw; then
        echo -e "${RED}***************************************************${NC}"
        echo -e "${RED}警告：SSH端口已修改为 $new_port${NC}"
        echo -e "${RED}未检测到UFW，请务必确认防火墙放行该端口！${NC}"
        echo -e "${RED}***************************************************${NC}"
        read -p "按回车键确认已知晓..."
    fi

    if [ "$want_disable_password" = "yes" ]; then
        print_warning "请在新的终端使用SSH密钥登录验证"
        if prompt_yes_no "已确认密钥登录无误，继续禁用密码登录？" "n"; then
            password_auth="no"
            apply_ssh_config "$config_target" "$use_dropin" "$new_port" "$permit_root" "$password_auth"
            if test_and_restart_sshd; then
                log_success "已禁用SSH密码登录"
            else
                log_error "禁用密码登录后测试失败，恢复为允许密码登录"
                apply_ssh_config "$config_target" "$use_dropin" "$new_port" "$permit_root" "yes"
                test_and_restart_sshd || true
                return 1
            fi
        else
            print_info "保留密码登录"
        fi
    fi
    return 0
}

configure_firewall() {
    log_info "配置UFW防火墙"
    if ! ensure_package "ufw" "ufw"; then log_error "UFW未安装"; return 1; fi

    ufw default deny incoming
    ufw default allow outgoing

    local ssh_port=$(get_ssh_port)
    if ! is_valid_port "$ssh_port"; then ssh_port="$SSH_PORT"; fi
    if ! is_valid_port "$ssh_port"; then ssh_port="22"; fi

    if ! ufw_has_rule "$ssh_port/tcp"; then
        ufw allow "$ssh_port/tcp" comment 'SSH'
    fi

    if prompt_yes_no "是否开放HTTP(80)和HTTPS(443)端口？" "n"; then
        if ! ufw_has_rule "80/tcp"; then ufw allow http comment 'HTTP'; fi
        if ! ufw_has_rule "443/tcp"; then ufw allow https comment 'HTTPS'; fi
    fi

    if prompt_yes_no "是否开放Redis端口(6379)？" "n"; then
        if ! ufw_has_rule "6379/tcp"; then ufw allow 6379/tcp comment 'Redis'; fi
    fi

    read -p "是否需要开放其他端口？(格式: 端口/协议 可选描述): " custom_port
    if [ -n "$custom_port" ]; then
        local port_spec="${custom_port%% *}"
        local port_comment="${custom_port#"$port_spec"}"
        port_comment="${port_comment# }"
        if ! ufw_has_rule "$port_spec"; then
            if [ -n "$port_comment" ]; then
                ufw allow "$port_spec" comment "$port_comment"
            else
                ufw allow "$port_spec"
            fi
        fi
    fi

    ufw logging on
    # 注意：这里会重新加载防火墙。如果上面SSH端口没放行对，可能会断连。
    # 但由于我们在 configure_ssh 里只修改配置不 reload ufw，且这里会重新检测 get_ssh_port，
    # 只要用户按顺序执行（先 ssh 配置，再 防火墙配置），逻辑是闭环的。
    ufw --force enable

    if command_exists systemctl; then systemctl enable ufw; fi
    log_success "UFW防火墙配置完成"
}

configure_fail2ban() {
    log_info "配置Fail2ban"
    if ! ensure_package "fail2ban" "fail2ban-client"; then return 1; fi
    backup_file "/etc/fail2ban/jail.local"

    local banaction="iptables-multiport"
    if command_exists ufw; then banaction="ufw"; fi

    local ssh_port=$(get_ssh_port)
    if ! is_valid_port "$ssh_port"; then ssh_port="22"; fi

    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
banaction = $banaction

[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

    log_info "测试Fail2ban配置"
    if fail2ban-client -t >/dev/null 2>&1; then
        log_success "基本配置测试通过"
        if command_exists systemctl; then systemctl enable fail2ban; fi
        if restart_service "fail2ban"; then
            log_success "Fail2ban基本配置完成"
            if prompt_yes_no "是否添加扩展服务保护 (Apache/Nginx/Postfix)？" "n"; then
                add_extended_protection
            fi
        else
            log_error "Fail2ban启动失败"; return 1;
        fi
    else
        log_error "Fail2ban配置测试失败"; fail2ban-client -t || true; return 1;
    fi
}

add_extended_protection() {
    log_info "添加扩展服务保护"
    # Apache
    if [ -d /etc/apache2 ] && [ -f /var/log/apache2/error.log ]; then
        cat >> /etc/fail2ban/jail.local << 'EOF'
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/error.log
maxretry = 3
EOF
    fi
    # Nginx
    if [ -d /etc/nginx ] && [ -f /var/log/nginx/error.log ]; then
        cat >> /etc/fail2ban/jail.local << 'EOF'
[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3
EOF
    fi
    # Postfix
    if [ -d /etc/postfix ] && [ -f /var/log/mail.log ]; then
        cat >> /etc/fail2ban/jail.local << 'EOF'
[postfix]
enabled = true
port = smtp,465,submission
filter = postfix
logpath = /var/log/mail.log
maxretry = 3
EOF
    fi
    if fail2ban-client -t >/dev/null 2>&1; then
        if command_exists systemctl; then systemctl reload fail2ban; fi
        log_success "扩展保护配置完成"
    else
        log_error "扩展配置错误，保持原样"
    fi
    mkdir -p /etc/fail2ban/filter.d
    cat > /etc/fail2ban/filter.d/redis-server.conf << 'EOF'
[Definition]
failregex = ^ WARNING .* Client .* @ <HOST> .*
ignoreregex =
EOF
}

configure_system_security() {
    log_info "配置系统安全参数"
    if prompt_yes_no "是否设置默认umask为027？" "y"; then
        cat > "/etc/profile.d/99-system-init.sh" << 'EOF'
umask 027
EOF
    fi

    if prompt_yes_no "是否设置系统资源限制(nofile/nproc)？" "y"; then
        local limits_dir="/etc/security/limits.d"
        if [ -d "$limits_dir" ]; then
            cat > "$limits_dir/99-system-init.conf" << 'EOF'
* hard core 0
* soft nofile 65535
* hard nofile 65535
* soft nproc 4096
* hard nproc 4096
EOF
        else
            ensure_line_in_file /etc/security/limits.conf "* hard core 0"
            ensure_line_in_file /etc/security/limits.conf "* soft nofile 65535"
            ensure_line_in_file /etc/security/limits.conf "* hard nofile 65535"
            ensure_line_in_file /etc/security/limits.conf "* soft nproc 4096"
            ensure_line_in_file /etc/security/limits.conf "* hard nproc 4096"
        fi

        set_systemd_limit /etc/systemd/system.conf "DefaultLimitNOFILE" "65535"
        set_systemd_limit /etc/systemd/system.conf "DefaultLimitNPROC" "65535"
    fi

    if prompt_yes_no "是否应用内核安全参数(sysctl)？" "y"; then
        cat > /etc/sysctl.d/99-security.conf << 'EOF'
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
        if require_command sysctl procps; then
            sysctl -p /etc/sysctl.d/99-security.conf || log_warn "加载内核参数失败"
        fi
    fi
    log_success "系统安全参数配置完成"
}

# --- 4/5. 用户与密钥管理 (逻辑完全保留) ---

user_management() {
    print_info "用户管理"
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

create_user() {
    read -p "请输入要创建的用户名: " new_user
    if [ -z "$new_user" ]; then print_error "用户名不能为空"; return 1; fi
    if id "$new_user" &>/dev/null; then print_warning "用户已存在"; return 1; fi
    useradd -m -s /bin/bash "$new_user"
    if prompt_yes_no "是否现在设置登录密码？" "y"; then
        if ! passwd "$new_user"; then print_warning "密码设置失败"; fi
    else
        passwd -l "$new_user" >/dev/null 2>&1 || true
        print_info "已锁定密码，请使用SSH密钥"
    fi
    if prompt_yes_no "是否将用户添加到sudo组？" "y"; then
        usermod -aG sudo "$new_user"
        if prompt_yes_no "是否允许无密码sudo？" "n"; then
            echo "$new_user ALL=(ALL) NOPASSWD: ALL" > "/etc/sudoers.d/$new_user"
            chmod 440 "/etc/sudoers.d/$new_user"
        fi
    fi
    if prompt_yes_no "是否将用户添加到docker组？" "n"; then
        if getent group docker >/dev/null; then usermod -aG docker "$new_user"; else print_warning "Docker组不存在"; fi
    fi
    log_success "用户 $new_user 创建完成"
}

modify_user() {
    read -p "请输入要修改的用户名: " target_user
    if ! id "$target_user" &>/dev/null; then print_error "用户不存在"; return 1; fi
    groups "$target_user"
    echo "1) 重置密码 2) 加入sudo 3) 移出sudo 4) 加入docker 5) 移出docker"
    read -p "选择: " m_choice
    case $m_choice in
        1) passwd "$target_user" ;;
        2) usermod -aG sudo "$target_user" ;;
        3) gpasswd -d "$target_user" sudo ; rm -f "/etc/sudoers.d/$target_user" ;;
        4) usermod -aG docker "$target_user" ;;
        5) gpasswd -d "$target_user" docker ;;
    esac
}

delete_user() {
    read -p "请输入要删除的用户名: " target_user
    if ! id "$target_user" &>/dev/null; then print_error "用户不存在"; return 1; fi
    read -p "确认删除 $target_user 及其主目录? (yes/no): " confirm
    if [ "$confirm" = "yes" ]; then
        userdel -r "$target_user" 2>/dev/null || userdel "$target_user"
        rm -f "/etc/sudoers.d/$target_user"
        log_success "用户已删除"
    fi
}

list_users() {
    print_info "常规用户:"
    awk -F: '$3 >= 1000 && $3 < 65534 {print $1 " (UID: " $3 ")"}' /etc/passwd
}

ssh_key_management() {
    print_info "SSH密钥管理"
    echo "1) 添加公钥 2) 生成密钥对 3) 查看公钥 4) 删除公钥"
    read -p "选择: " k_choice
    case $k_choice in
        1) add_public_key ;;
        2) generate_key_pair ;;
        3) view_public_keys ;;
        4) remove_public_key ;;
    esac
}

add_public_key() {
    read -p "用户名: " k_user
    if ! id "$k_user" &>/dev/null; then print_error "用户不存在"; return 1; fi
    local uhome=$(get_user_home "$k_user")
    mkdir -p "$uhome/.ssh"; chmod 700 "$uhome/.ssh"
    echo "粘贴公钥:"
    read -r pk
    if [ -n "$pk" ]; then
        echo "$pk" >> "$uhome/.ssh/authorized_keys"
        chmod 600 "$uhome/.ssh/authorized_keys"
        chown -R "$k_user:$k_user" "$uhome/.ssh"
        log_success "公钥添加成功"
    fi
}

generate_key_pair() {
    read -p "用户名: " k_user
    if ! id "$k_user" &>/dev/null; then print_error "用户不存在"; return 1; fi
    local uhome=$(get_user_home "$k_user")
    mkdir -p "$uhome/.ssh"; chmod 700 "$uhome/.ssh"; chown "$k_user:$k_user" "$uhome/.ssh"
    if prompt_yes_no "设置密钥密码？" "n"; then
        su - "$k_user" -c "ssh-keygen -t ed25519 -f $uhome/.ssh/id_ed25519"
    else
        su - "$k_user" -c "ssh-keygen -t ed25519 -N '' -f $uhome/.ssh/id_ed25519"
    fi
    cat "$uhome/.ssh/id_ed25519.pub" >> "$uhome/.ssh/authorized_keys"
    chmod 600 "$uhome/.ssh/authorized_keys"
    chown "$k_user:$k_user" "$uhome/.ssh/authorized_keys"
    print_success "密钥生成完成"
    cat "$uhome/.ssh/id_ed25519.pub"
}

view_public_keys() {
    read -p "用户名: " k_user
    if ! id "$k_user" &>/dev/null; then print_error "用户不存在"; return 1; fi
    local uhome=$(get_user_home "$k_user")
    if [ -f "$uhome/.ssh/authorized_keys" ]; then cat "$uhome/.ssh/authorized_keys"; else echo "无公钥"; fi
}

remove_public_key() {
    read -p "用户名: " k_user
    if ! id "$k_user" &>/dev/null; then print_error "用户不存在"; return 1; fi
    local uhome=$(get_user_home "$k_user")
    if [ -f "$uhome/.ssh/authorized_keys" ]; then
        nl "$uhome/.ssh/authorized_keys"
        read -p "删除行号: " ln
        if [[ "$ln" =~ ^[0-9]+$ ]]; then
            sed -i "${ln}d" "$uhome/.ssh/authorized_keys"
            log_success "公钥删除成功"
        fi
    fi
}

# --- 6. 系统优化 (保留原有时区/主机名) ---

system_optimization() {
    print_info "系统优化配置"
    if command_exists timedatectl; then
        if prompt_yes_no "是否配置时区？当前: $(timedatectl show --property=Timezone --value)" "y"; then
            echo "1) Asia/Shanghai 2) UTC 3) America/New_York 4) Europe/London 5) 自定义"
            read -p "选择: " tz_c
            case $tz_c in
                1) timedatectl set-timezone Asia/Shanghai ;;
                2) timedatectl set-timezone UTC ;;
                3) timedatectl set-timezone America/New_York ;;
                4) timedatectl set-timezone Europe/London ;;
                5) read -p "输入时区: " ctz; timedatectl set-timezone "$ctz" ;;
            esac
            log_success "时区已设置"
        fi
    fi

    if prompt_yes_no "是否修改主机名？当前: $(hostname)" "n"; then
        read -p "新主机名: " nh
        if [ -n "$nh" ]; then
            if command_exists hostnamectl; then hostnamectl set-hostname "$nh"; else hostname "$nh"; fi
            sed -i -E "s/^127\.0\.1\.1.*/127.0.1.1 $nh/" /etc/hosts || echo "127.0.1.1 $nh" >> /etc/hosts
            log_success "主机名设置为: $nh"
        fi
    fi
}

# --- 7. Docker安装 (保留) ---

install_docker() {
    print_info "Docker安装"
    if command_exists docker; then
        print_info "Docker已安装: $(docker --version)"
        if ! prompt_yes_no "重新安装？" "n"; then return 0; fi
    fi
    if ! ensure_package "curl" "curl"; then return 1; fi
    local script_url="https://get.docker.com"
    if prompt_yes_no "是否使用镜像下载Docker安装脚本？" "n"; then
        echo "1) DaoCloud 镜像 (https://get.daocloud.io/docker)"
        echo "2) 自定义地址 (可填阿里云/清华源提供的脚本地址)"
        read -p "请选择 (1-2): " mirror_choice
        case $mirror_choice in
            1) script_url="https://get.daocloud.io/docker" ;;
            2)
                read -p "请输入安装脚本URL: " custom_url
                if [ -n "$custom_url" ]; then
                    script_url="$custom_url"
                else
                    log_error "安装脚本URL为空"
                    return 1
                fi
                ;;
            *) print_warning "无效选择，使用官方源" ;;
        esac
    fi
    if ! curl -fsSL "$script_url" -o get-docker.sh; then
        log_error "下载Docker安装脚本失败: $script_url"
        return 1
    fi
    sh get-docker.sh
    if command_exists systemctl; then systemctl enable docker; systemctl start docker; fi
    read -p "加入docker组的用户名: " du
    if [ -n "$du" ] && id "$du" &>/dev/null; then usermod -aG docker "$du"; fi
    rm -f get-docker.sh
    log_success "Docker安装完成"
}

# --- 8. Bash补全 (保留) ---

configure_bash_completion() {
    print_info "配置bash自动补全"
    ensure_package "bash-completion"
    if [ ! -f /etc/profile.d/bash_completion.sh ]; then
        cat > /etc/profile.d/bash_completion.sh << 'EOF'
if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
fi
EOF
        chmod +x /etc/profile.d/bash_completion.sh
    fi
    log_success "Bash补全配置完成"
}

# --- 9/10. 查看状态/历史 (保留) ---

show_system_status() {
    print_info "系统状态"
    echo "OS: $(get_os_description)"
    echo "Kernel: $(uname -r)"
    echo "SSH Port: $(get_ssh_port)"
    echo "UFW: $(get_ufw_status)"
    echo "Fail2ban: $(get_fail2ban_status)"
    echo "BBR: $(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')"
    free -h
    df -h / | tail -1
}

show_config_history() {
    print_info "操作历史"
    tail -20 "$LOG_FILE"
    ls -la "$BACKUP_DIR" 2>/dev/null || echo "无备份"
}

# --- 11. BBR与网络优化 (新增功能模块) ---

configure_bbr_optimization() {
    print_info "BBR与网络优化配置"
    echo "功能说明："
    echo " - 开启 BBR 拥塞控制算法 (大幅提升弱网速度)"
    echo " - 开启 TCP Fast Open (fastopen=3)"
    echo " - 开启 TCP MTU Probing (解决MTU黑洞问题)"
    echo ""
    echo "1) ✅ 开启 BBR + 网络优化"
    echo "2) 🔙 恢复默认设置"
    echo "0) 返回主菜单"
    
    read -p "请选择: " bbr_choice
    case $bbr_choice in
        1)
            log_info "正在配置 BBR 及网络参数..."
            cat > "$SYSCTL_NET_CONF" << EOF
# 拥塞控制与队列优化
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP Fast Open (客户端/服务端同时开启)
net.ipv4.tcp_fastopen = 3

# MTU 探测 (解决部分网络环境下的丢包问题)
net.ipv4.tcp_mtu_probing = 1

# 基础TCP连接优化
net.ipv4.tcp_slow_start_after_idle = 0
EOF
            if sysctl -p "$SYSCTL_NET_CONF"; then
                log_success "BBR 与网络优化参数已应用"
                echo -e "${GREEN}当前算法: $(sysctl net.ipv4.tcp_congestion_control)${NC}"
            else
                log_error "参数应用失败"
            fi
            ;;
        2)
            log_info "恢复网络参数默认值"
            rm -f "$SYSCTL_NET_CONF"
            sysctl --system
            log_success "已恢复默认"
            ;;
        0)
            return 0
            ;;
        *)
            print_warning "无效选择"
            ;;
    esac
}

# --- 主程序 ---

main() {
    check_root
    init_environment

    while true; do
        show_menu
        read -p "请选择操作 (0-11): " choice
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
            11) configure_bbr_optimization ;;
            0)
                print_success "退出脚本"
                exit 0
                ;;
            *)
                print_warning "无效选择"
                ;;
        esac
        echo ""
        read -p "按回车键继续..."
    done
}

trap 'log_error "脚本被中断"; exit 1' INT TERM

main "$@"
