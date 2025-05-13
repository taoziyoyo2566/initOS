#!/bin/bash

set -e

# 确保以root权限运行
if [ "$(id -u)" -ne 0 ]; then
    echo "请以root用户运行此脚本"
    exit 1
fi

### 功能1：设置Swap分区 ###
echo "===== 设置Swap分区 ====="
read -p "请输入Swap大小（单位：G），直接回车跳过: " swap_size
if [[ -n "$swap_size" ]]; then
    echo "设置${swap_size}G的Swap分区..."
    fallocate -l ${swap_size}G /swapfile || dd if=/dev/zero of=/swapfile bs=1G count=$swap_size
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo "/swapfile none swap sw 0 0" >> /etc/fstab
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    sysctl -p
    echo "Swap设置完成。"
else
    echo "未设置Swap分区。"
fi

### 功能2：安装并配置软件 ###
echo "===== 安装并配置软件包 ====="
apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y
apt-get install -y curl vim ufw jq sudo fail2ban unattended-upgrades apt-listchanges bash-completion git net-tools dnsutils gh

# 自动更新配置
cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
EOF

# Fail2ban配置
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
banaction = ufw

[sshd]
enabled = true
port = 32798
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

# 创建Fail2ban Redis过滤器
mkdir -p /etc/fail2ban/filter.d
cat > /etc/fail2ban/filter.d/redis-server.conf << EOF
[Definition]
failregex = ^ WARNING .* Client .* @ <HOST> .*
ignoreregex =
EOF

# 安装Docker
curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh

# 防火墙配置
ufw default deny incoming
ufw default allow outgoing
ufw allow 32798/tcp comment 'SSH'
ufw allow http comment 'HTTP'
ufw allow https comment 'HTTPS'
ufw allow 6379/tcp comment 'Redis'
ufw logging on

systemctl enable ufw
systemctl enable fail2ban
ufw --force enable
systemctl restart fail2ban

# SSH配置（简化版）
sed -i.bak 's/#Port 22/Port 32798/' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

### 功能3：添加用户 ###
echo "===== 添加新用户 ====="
read -p "请输入要创建的用户名: " new_user
if [[ -n "$new_user" ]]; then
    useradd -m -s /bin/bash $new_user
    echo "$new_user:$new_user" | chpasswd
    read -p "是否将用户添加到docker组？(y/n): " add_docker
    [[ "$add_docker" == "y" ]] && usermod -aG docker $new_user
    read -p "是否将用户添加到sudo组？(y/n): " add_sudo
    [[ "$add_sudo" == "y" ]] && usermod -aG sudo $new_user
    echo "$new_user ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/$new_user
    chmod 440 /etc/sudoers.d/$new_user
    echo "用户$new_user创建完成。"
else
    echo "未创建任何用户。"
fi

### 功能4：添加SSH密钥 ###
echo "===== 为用户添加SSH密钥 ====="
read -p "请输入要添加密钥的用户名（直接回车跳过）: " key_user
if [[ -n "$key_user" ]]; then
    if id "$key_user" &>/dev/null; then
        mkdir -p /home/$key_user/.ssh
        read -p "请粘贴公钥内容: " pubkey
        echo "$pubkey" > /home/$key_user/.ssh/authorized_keys
        chmod 700 /home/$key_user/.ssh
        chmod 600 /home/$key_user/.ssh/authorized_keys
        chown -R $key_user:$key_user /home/$key_user/.ssh
        echo "已成功为用户$key_user添加SSH密钥。"
    else
        echo "用户$key_user 不存在。"
    fi
else
    echo "未添加任何密钥。"
fi

echo "===== 所有设置已完成 ====="
