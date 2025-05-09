#!/bin/bash

# 系统初始化脚本 - 安装必要软件、配置SSH和防火墙、创建用户

# 确保以root权限运行
if [ "$(id -u)" -ne 0 ]; then
    echo "请以root用户运行此脚本"
    exit 1
fi

echo "===== 系统初始化脚本 ====="
echo "此脚本将更新系统、安装软件包、配置SSH和防火墙，并创建新用户"
echo ""

# 必须手动指定用户名
read -p "请输入要创建的用户名: " username

# 验证用户名非空
if [ -z "$username" ]; then
    echo "错误: 用户名不能为空"
    exit 1
fi

# 密码默认和用户名相同
user_password=$username

echo "===== 开始系统配置 ====="

# 更新系统
echo "正在更新系统..."
apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y

# 安装基本软件包
echo "正在安装必要软件包..."
apt-get install -y curl vim ufw jq sudo fail2ban unattended-upgrades apt-listchanges bash-completion git net-tools 

# 配置自动更新
echo "正在配置自动安全更新..."
cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Download-Upgradeable-Packages "1";
EOF

# 配置Fail2ban - 多服务保护
echo "正在配置Fail2ban..."
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# 默认设置
bantime = 3600
findtime = 600
maxretry = 5
banaction = ufw
banaction_allports = ufw

# SSH保护
[sshd]
enabled = true
port = 32798
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

# Web服务器保护 - Apache
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache*/*error.log
maxretry = 3

[apache-badbots]
enabled = true
port = http,https
filter = apache-badbots
logpath = /var/log/apache*/*access.log
maxretry = 2

# Web服务器保护 - Nginx
[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-botsearch]
enabled = true
port = http,https
filter = nginx-botsearch
logpath = /var/log/nginx/access.log
maxretry = 2

# 邮件服务器保护
[postfix]
enabled = true
port = smtp,465,submission
filter = postfix
logpath = /var/log/mail.log
maxretry = 3

[postfix-sasl]
enabled = true
port = smtp,465,submission,imap,imaps,pop3,pop3s
filter = postfix-sasl
logpath = /var/log/mail.log
maxretry = 3

# Redis服务器保护
[redis-server]
enabled = true
port = 6379
filter = redis-server
logpath = /var/log/redis/redis-server.log
maxretry = 3
EOF

# 创建自定义Redis fail2ban过滤器
mkdir -p /etc/fail2ban/filter.d
cat > /etc/fail2ban/filter.d/redis-server.conf << EOF
[Definition]
failregex = ^ WARNING .* Client .* @ <HOST> .*
ignoreregex =
EOF

# 安装Docker
echo "正在安装Docker..."
curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh

# 配置SSH
echo "正在配置SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# 使用更安全的设置
cat > /etc/ssh/sshd_config << EOF
Port 32798
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# 使用更强的密钥交换算法和密码
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com

# 鉴权设置
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# 会话设置
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# 安全加固
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

# 配置UFW防火墙
echo "正在配置防火墙..."
ufw default deny incoming
ufw default allow outgoing

ufw allow 32798/tcp comment 'SSH'
ufw allow http comment 'HTTP'
ufw allow https comment 'HTTPS'
ufw allow 6379/tcp comment 'Redis'
ufw logging on

# 创建用户
echo "正在创建用户: $username..."
useradd -m -s /bin/bash $username

# 创建用户组
groupadd docker_users 2>/dev/null || true
usermod -aG sudo,docker_users,users,docker $username

# 设置密码
echo "$username:$user_password" | chpasswd

# 准备SSH目录
mkdir -p /home/$username/.ssh
chmod 700 /home/$username/.ssh

# 如果root用户有authorized_keys文件，则复制到新用户
if [ -f /root/.ssh/authorized_keys ]; then
    echo "复制SSH授权密钥..."
    cp /root/.ssh/authorized_keys /home/$username/.ssh/
    chmod 600 /home/$username/.ssh/authorized_keys
    chown -R $username:$username /home/$username/.ssh/
fi

# 限制sudo访问
echo "配置sudo权限..."
echo "$username ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/$username
chmod 440 /etc/sudoers.d/$username

# 为新用户生成SSH密钥
echo "为用户 $username 生成SSH密钥..."
su - $username -c "ssh-keygen -t ed25519 -N '$user_password' -f /home/$username/.ssh/id_ed25519"

# 配置bash-completion
echo "配置bash自动补全..."
cat >> /home/$username/.bashrc << EOF

# 启用 bash-completion
if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
fi
EOF

# 确保bash-completion也在全局可用
if [ ! -f /etc/profile.d/bash_completion.sh ]; then
    cat > /etc/profile.d/bash_completion.sh << EOF
# 全局启用 bash-completion
if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
fi
EOF
    chmod +x /etc/profile.d/bash_completion.sh
fi

# 配置系统安全设置
echo "配置系统安全设置..."
# 设置更严格的文件权限掩码
echo "umask 027" >> /etc/profile

# 限制core dumps
echo "* hard core 0" >> /etc/security/limits.conf

# 系统资源限制
cat >> /etc/security/limits.conf << EOF
* soft nofile 65535
* hard nofile 65535
* soft nproc 4096
* hard nproc 4096
EOF

# 优化系统参数
cat > /etc/sysctl.d/99-security.conf << EOF
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

# 启用并激活服务
echo "启用服务..."
systemctl enable ufw
systemctl enable fail2ban
ufw --force enable

# 重启SSH服务
echo "重启SSH服务..."
systemctl restart sshd
systemctl restart fail2ban

echo ""
echo "===== 系统初始化完成 ====="
echo "创建的用户: $username"
echo "初始密码: $username (用于SSH密钥)"
echo "SSH端口: 32798"
echo "请使用密钥认证方式登录"
echo "登录命令示例: ssh -p 32798 -i /path/to/private_key $username@YOUR_SERVER_IP"
echo ""
echo "安全提示:"
echo "- SSH私钥已生成在用户主目录: /home/$username/.ssh/id_ed25519"
echo "- 请立即将SSH私钥安全地下载到本地机器"
echo "- 公钥已自动添加到authorized_keys"
echo "- fail2ban已配置保护SSH、Web、邮件和Redis服务"
echo "- bash自动补全功能已启用"
echo ""
