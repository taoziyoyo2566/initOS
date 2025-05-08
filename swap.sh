# 设置 swap 文件
read -p "请输入要创建的 swap 文件大小（单位为G，例如输入16表示16G）: " swap_size

if [[ "$swap_size" =~ ^[0-9]+$ ]]; then
    echo "正在创建 ${swap_size}G 的 swap 文件..."

    if [ -f /swapfile ]; then
        echo "检测到已有 /swapfile，跳过创建"
    else
        fallocate -l ${swap_size}G /swapfile || dd if=/dev/zero of=/swapfile bs=1G count=$swap_size status=progress
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        echo "Swap 文件已成功创建并启用"
    fi

    # 优化 swap 使用策略
    sysctl -w vm.swappiness=10
    echo 'vm.swappiness=10' >> /etc/sysctl.conf
else
    echo "未输入有效的数字，跳过 swap 设置"
fi
