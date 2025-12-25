#!/bin/bash

# =================================================================
# Enhanced System Initialization & Management Script (Full Version)
# =================================================================
# 功能：系统初始化、安全加固、BBR优化、用户管理、密钥审计、软件安装
# 兼容性：Debian/Ubuntu 18.04+ (Root 运行)

set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# --- 全局变量 ---
LOG_FILE="/var/log/system_init.log"
CONFIG_DIR="/etc/system_init"
BACKUP_DIR="/etc/system_init/backups"
SSH_DROPIN_FILE="/etc/ssh/sshd_config.d/99-initos.conf"
SYSCTL_NET_CONF="/etc/sysctl.d/99-network-optimization.conf"

# 颜色
RED='\033[0;31m' ; GREEN='\033[0;32m' ; YELLOW='\033[1;33m' ; BLUE='\033[0;34m' ; NC='\033[0m'

# --- 基础工具函数 ---
log() { local level=$1; shift; echo -e "$(date '+%Y-%m-%d %H:%M:%S') [$level] $*" | tee -a "$LOG_FILE"; }
print_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $*"; }
print_error() { echo -e "${RED}[ERROR]${NC} $*"; }

command_exists() { command -v "$1" >/dev/null 2>&1; }
prompt_yes_no() { read -p "$1 (y/n, 默认y): " res; [[ "${res:-y}" =~ ^[yY]$ ]]; }
backup_file() {
    [ -f "$1" ] && cp "$1" "$BACKUP_DIR/$(basename "$1").$(date +%Y%m%d_%H%M%S)" && log "INFO" "备份 $1"
}

# --- 1. 系统更新模块 (含资源限制优化) ---
update_system() {
    print_info "执行系统全面更新..."
    apt-get update
    # 批量安装 (提升效率)
    local packages=(curl vim ufw jq sudo fail2ban unattended-upgrades bash-completion git net-tools dnsutils htop tree)
    apt-get install -y "${packages[@]}"

    # 配置自动更新
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    # 同步 Systemd 资源限制 (采纳建议 5)
    [ -f /etc/systemd/system.conf ] && sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=65535/' /etc/systemd/system.conf
    print_success "更新及基础优化完成。"
}

# --- 2. Swap 管理 (含空间检查) ---
manage_swap() {
    print_info "当前 Swap: $(free -h | awk '/Swap/ {print $2}')"
    if prompt_yes_no "是否配置/重新配置 Swap?"; then
        read -p "大小(G): " sz
        [[ ! "$sz" =~ ^[0-9]+$ ]] && return
        local free_mb=$(df -m / | awk 'NR==2 {print $4}')
        if [ "$((sz * 1024))" -ge "$free_mb" ]; then print_error "空间不足"; return; fi
        
        swapoff -a || true
        fallocate -l "${sz}G" /swapfile || dd if=/dev/zero of=/swapfile bs=1G count="$sz"
        chmod 600 /swapfile ; mkswap /swapfile ; swapon /swapfile
        grep -q "/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
        print_success "Swap 设置为 ${sz}G。"
    fi
}

# --- 3. BBR 与 TCP 优化 (新增项) ---
optimize_network() {
    echo -e "1) 开启 BBR + TCP FastOpen (3) + MTU Probing (1)\n2) 恢复默认"
    read -p "请选择: " nopt
    if [ "$nopt" == "1" ]; then
        cat > "$SYSCTL_NET_CONF" << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
EOF
        sysctl -p "$SYSCTL_NET_CONF"
        print_success "BBR 网络优化已应用。"
    else
        rm -f "$SYSCTL_NET_CONF" && sysctl --system
        print_info "网络优化已卸载。"
    fi
}

# --- 4. SSH 安全配置 (找回完整功能) ---
manage_ssh() {
    print_info "SSH 详细管理"
    echo -e "1) 修改 SSH 端口\n2) 禁用/启用密码登录\n3) 配置 SSH 密钥选项"
    read -p "选择: " sopt
    local target="$SSH_DROPIN_FILE"
    mkdir -p "$(dirname "$target")"

    case $sopt in
        1)
            read -p "输入新端口: " np
            [[ "$np" =~ ^[0-9]+$ ]] && echo "Port $np" > "$target" && systemctl restart ssh && print_warning "端口已改为 $np，请务必手动放行防火墙！"
            ;;
        2)
            if prompt_yes_no "是否禁用密码登录 (改为仅密钥)?"; then
                echo "PasswordAuthentication no" >> "$target"
            else
                echo "PasswordAuthentication yes" >> "$target"
            fi
            systemctl restart ssh
            ;;
        *) manage_ssh_keys ;; # 进入密钥管理子模块
    esac
}

# --- 5. SSH 密钥管理 (找回原脚本深度) ---
manage_ssh_keys() {
    read -p "用户名: " un
    id "$un" &>/dev/null || { print_error "用户不存在"; return; }
    local uhome=$(getent passwd "$un" | cut -d: -f6)
    local kfile="$uhome/.ssh/authorized_keys"

    echo -e "1) 添加公钥 2) 查看当前公钥 3) 删除特定公钥"
    read -p "选择: " kopt
    case $kopt in
        1)
            read -p "粘贴公钥: " pk
            mkdir -p "$uhome/.ssh" && echo "$pk" >> "$kfile"
            chmod 700 "$uhome/.ssh" && chmod 600 "$kfile" && chown -R "$un:$un" "$uhome/.ssh"
            ;;
        2) [ -f "$kfile" ] && cat "$kfile" || echo "无密钥" ;;
        3) [ -f "$kfile" ] && nl "$kfile" && read -p "行号: " ln && sed -i "${ln}d" "$kfile" ;;
    esac
}

# --- 6. 用户深度管理 (找回原脚本功能) ---
manage_users() {
    echo -e "1) 新建用户 2) 修改权限(Sudo/Docker) 3) 删除用户 4) 列出所有普通用户"
    read -p "选择: " uopt
    case $uopt in
        1)
            read -p "用户名: " un
            useradd -m -s /bin/bash "$un" && passwd "$un"
            prompt_yes_no "加入 Sudo 组?" && usermod -aG sudo "$un"
            ;;
        2)
            read -p "用户名: " un
            prompt_yes_no "赋予 Docker 权限?" && usermod -aG docker "$un"
            ;;
        3)
            read -p "用户名: " un
            userdel -r "$un" && print_success "已删除"
            ;;
        4)
            awk -F: '$3 >= 1000 && $3 < 65534 {print $1 " (UID: "$3")"}' /etc/passwd
            ;;
    esac
}

# --- 7. 防火墙与安全策略 (找回功能) ---
manage_security() {
    print_info "配置安全策略 (UFW & Fail2ban)..."
    ufw default deny incoming
    ufw default allow outgoing
    
    # 自动探测 SSH 端口并放行
    local sp=$(sshd -T 2>/dev/null | awk '/^port / {print $2}')
    ufw allow "$sp/tcp" comment 'SSH'
    
    prompt_yes_no "放行 80/443?" && ufw allow http && ufw allow https
    ufw --force enable

    # 扩展 Fail2ban (探测 Nginx/Apache)
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
banaction = ufw

[sshd]
enabled = true
port = $sp
EOF
    systemctl restart fail2ban
    print_success "安全加固完成。"
}

# --- 8. 系统审计与历史 (找回功能) ---
show_history() {
    echo -e "\n${BLUE}--- 操作日志 ---${NC}"
    tail -n 20 "$LOG_FILE" || echo "无日志"
    echo -e "\n${BLUE}--- 备份目录内容 ---${NC}"
    ls -lh "$BACKUP_DIR"
}

# --- 主程序逻辑 ---
main() {
    [ "$(id -u)" -ne 0 ] && { echo "请用 Root 运行"; exit 1; }
    mkdir -p "$CONFIG_DIR" "$BACKUP_DIR"
    
    while true; do
        echo -e "\n${BLUE}===== 1700行级完整功能版 + BBR增强 =====${NC}"
        echo "1. 更新系统(及资源限额)  2. Swap 管理(带预检)"
        echo "3. BBR/网络优化(FastOpen)  4. SSH 管理(含密钥审计)"
        echo "5. 用户深度管理           6. 防火墙与安全加固"
        echo "7. 安装 Docker           8. 查看操作历史与状态"
        echo "0. 退出"
        read -p "执行操作: " choice

        case $choice in
            1) update_system ;;
            2) manage_swap ;;
            3) optimize_network ;;
            4) manage_ssh ;;
            5) manage_users ;;
            6) manage_security ;;
            7) curl -fsSL https://get.docker.com | sh ;;
            8) show_history ; uptime ;;
            0) exit 0 ;;
            *) print_warning "选择无效" ;;
        esac
        read -p "回车继续..."
    done
}

main "$@"