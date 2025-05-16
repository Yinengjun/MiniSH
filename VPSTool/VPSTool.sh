#!/bin/bash

# 获取系统信息
get_os_name() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$NAME"
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        echo "$DISTRIB_ID"
    elif [ -f /etc/redhat-release ]; then
        echo "CentOS"
    else
        echo "未知的系统"
    fi
}

OS_NAME=$(get_os_name)

# 获取虚拟化类型
get_virtualization_type() {
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        VIRT_TYPE=$(systemd-detect-virt)
    elif command -v virt-what >/dev/null 2>&1; then
        VIRT_TYPE=$(virt-what)
    else
        VIRT_TYPE="无法检测到虚拟化类型"
    fi
    echo "$VIRT_TYPE"
}

VIRT_TYPE=$(get_virtualization_type)

# 清理系统垃圾
clean() {
    local mode="$1"

    echo "正在清理系统日志..."
    if [ "$mode" == "deep" ]; then
        # 深度清理：清空所有日志
        sudo find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
        echo "所有系统日志已清空。"
    else
        # 常规清理：清除 7 天前的日志
        sudo journalctl --vacuum-time=7d
        echo "7 天前的系统日志已删除。"
    fi

    # 检查包管理器
    if command -v apt > /dev/null; then
        echo "正在清理 apt 包管理器..."
        sudo apt clean
        echo "安装包缓存清理完成。"
        sudo apt autoclean
        echo "过期缓存清理完成。"
        sudo apt autoremove -y
        echo "不再需要的依赖包删除完成。"
        sudo apt autoremove --purge -y
        echo "旧内核清理完成。"

    elif command -v yum > /dev/null; then
        echo "正在清理 yum 包管理器..."
        sudo yum clean all
        echo "yum 包管理器清理完成。"
        sudo package-cleanup --oldkernels --count=2
        echo "旧内核清理完成。"

    elif command -v dnf > /dev/null; then
        echo "正在清理 dnf 包管理器..."
        sudo dnf clean all
        echo "dnf 包管理器清理完成。"
        sudo dnf autoremove -y
        echo "不再需要的依赖包删除完成。"
        sudo dnf remove --oldinstallonly
        echo "旧内核清理完成。"

    elif command -v pacman > /dev/null; then
        echo "正在清理 pacman 包管理器..."
        sudo pacman -Scc --noconfirm
        echo "pacman 包管理器清理完成。"
        sudo pacman -Rns $(pacman -Qdtq) --noconfirm
        echo "不再需要的依赖包删除完成。"

    elif command -v zypper > /dev/null; then
        echo "正在清理 zypper 包管理器..."
        sudo zypper clean
        echo "zypper 包管理器清理完成。"
        sudo zypper rm $(zypper se --unneeded | awk '{print $3}')
        echo "不再需要的依赖包删除完成。"

    else
        echo "未检测到支持的包管理器，跳过相关清理步骤。"
    fi

    # 清理用户的临时文件
    echo "正在清理用户临时文件..."
    rm -rf ~/.cache/*
    rm -rf ~/.local/share/Trash/*
    echo "用户临时文件清理完成。"

    # 清理临时文件
    echo "正在删除系统临时文件..."
    sudo rm -rf /tmp/*
    sudo rm -rf /var/tmp/*
    echo "系统临时文件删除完成。"

    # 检查 Docker 是否安装
    if command -v docker > /dev/null; then
        echo "正在清理 Docker 的未使用资源..."
        if [ "$mode" == "deep" ]; then
            docker system prune -a -f --volumes
            docker network prune -f
            docker volume prune -f
            echo "Docker 的未使用资源清理完成。"
        else
            docker image prune -a -f
            echo "未使用的 Docker 镜像清理完成。"
        fi
    else
        echo "未检测到 Docker，跳过 Docker 清理步骤。"
    fi
}

# 显示网络菜单
network_menu() {
    while true; do
        clear
        echo "网络设置菜单："
        echo "1. 设置IP优先级"
        echo "2. 设置DNS"
        echo "3. TCP一键管理"
        echo "4. NNC tool"
        echo "0. 返回主菜单"
        read -p "请输入选项: " NETWORK_OPTION

        case $NETWORK_OPTION in
            1)
                set_ip_priority
                ;;
            2)
                configure_dns
                ;;
            3)
                echo "TCP一键管理"
                wget -O tcpx.sh "https://github.com/ylx2016/Linux-NetSpeed/raw/master/tcpx.sh" && chmod +x tcpx.sh && ./tcpx.sh
                ;;
            4)
                echo "nnc tool"
                wget http://sh.nekoneko.cloud/tools.sh -O tools.sh && bash tools.sh
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选项"
                ;;
        esac
    done
}

# 设置IP优先级
set_ip_priority() {
    clear
    echo "1. IPv4优先"
    echo "2. IPv6优先"
    read -p "请选择IP优先级 (1 或 2): " IP_OPTION
    case $IP_OPTION in
        1)
            if ! grep -q "^precedence ::ffff:0:0/96 100" /etc/gai.conf; then
                sudo sh -c 'echo "precedence ::ffff:0:0/96 100" >> /etc/gai.conf'
                echo "IPv4优先已设置。"
            else
                echo "IPv4优先已存在，无需重复设置。"
            fi
            ;;
        2)
            if grep -q "^precedence ::ffff:0:0/96 100" /etc/gai.conf; then
                sudo sed -i '/^precedence ::ffff:0:0\/96 100/d' /etc/gai.conf
                echo "IPv4优先已取消，IPv6优先。"
            else
                echo "未找到IPv4优先设置，无需更改。"
            fi
            ;;
        *)
            echo "无效的选项，请选择 1 或 2。"
            ;;
    esac
}

# 添加DNS配置
add_dns() {
    DNS_IP="$1"
    if ! grep -q "nameserver $DNS_IP" /etc/resolv.conf; then
        sudo bash -c "echo 'nameserver $DNS_IP' >> /etc/resolv.conf"
        echo "$DNS_IP 已添加。"
    else
        echo "$DNS_IP 已存在。"
    fi
}

# 配置IPv4 DNS
configure_ipv4_dns() {
    echo "1. 添加DNS"
    echo "2. 覆盖DNS（默认）"
    read -p "请选择操作 (1 或 2): " DNS_OP
    if [[ $DNS_OP -eq 1 ]]; then
        add_dns "1.1.1.1"
        add_dns "8.8.8.8"
    else
        sudo bash -c 'echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf'
        echo "已覆盖并设置新的IPv4 DNS。"
    fi
    sudo systemctl restart networking
    echo "网络服务已重启。"
}

# 配置双栈DNS
configure_dual_stack_dns() {
    echo "1. 添加DNS"
    echo "2. 覆盖DNS（默认）"
    read -p "请选择操作 (1 或 2): " DNS_OP
    if [[ $DNS_OP -eq 1 ]]; then
        add_dns "1.1.1.1"
        add_dns "8.8.8.8"
        add_dns "2606:4700:4700::1111"
        add_dns "2001:4860:4860::8888"
    else
        sudo bash -c 'echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 2606:4700:4700::1111\nnameserver 2001:4860:4860::8888" > /etc/resolv.conf'
        echo "已覆盖并设置新的双栈DNS。"
    fi
    sudo systemctl restart networking
    echo "网络服务已重启。"
}


# 设置DNS
configure_dns() {
    clear
    echo "当前DNS设置："
    cat /etc/resolv.conf
    echo "1. 配置IPv4 DNS"
    echo "2. 配置双栈DNS"
    echo "3. 查看当前IP地址"
    echo "4. 返回"

    read -p "请选择DNS配置选项: " DNS_OPTION
    case $DNS_OPTION in
        1)
            configure_ipv4_dns
            ;;
        2)
            configure_dual_stack_dns
            ;;
        3)
            echo "当前IPv4地址："
            if ! curl -s --connect-timeout 5 ip.sb; then
                echo "无法获取IPv4地址。"
            fi

            echo "当前IPv6地址："
            if ! timeout 5 curl -s ipv6.ip.sb; then
                echo "无法获取IPv6地址。"
            fi
            ;;
        4)
            return
            ;;
        *)
            echo "无效的选项"
            ;;
    esac
}

# 显示安装代理服务端菜单
install_proxy_server_menu() {
    clear
    while true; do
        echo "安装代理服务端菜单："
        echo "1. 3X-UI"
        echo "2. X-UI"
        echo "3. Misaka-hysteria"
        echo "4. 32M-Reality-Alpine"
        echo "0. 返回主菜单"
        read -p "请输入选项: " PROXY_OPTION

        case $PROXY_OPTION in
            1)
                echo "请选择 3X-UI 版本："
                echo "1. 安装最新版（默认）"
                echo "2. 指定版本"
                read -p "请输入选项: " VERSION_OPTION

                if [ "$VERSION_OPTION" == "2" ]; then
                    read -p "请输入版本号（默认1.7.9）： " VERSION
                    VERSION=${VERSION:-1.7.9}
                    echo "正在安装 3X-UI 版本 $VERSION..."
                    VERSION=v$VERSION bash <(curl -Ls "https://raw.githubusercontent.com/mhsanaei/3x-ui/refs/tags/$VERSION/install.sh")
                else
                    echo "正在安装 3X-UI 最新版..."
                    bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
                fi
                ;;
            2)
                echo "正在安装 X-UI..."
                bash <(curl -Ls https://raw.githubusercontent.com/vaxilu/x-ui/master/install.sh)
                ;;
            3)
                echo "下载并启动Misaka-hysteria脚本..."
                wget -N --no-check-certificate https://raw.githubusercontent.com/Misaka-blog/hysteria-install/main/hy2/hysteria.sh && bash hysteria.sh
                ;;
            4)
                echo "正在安装 32M-Reality-Alpine..."
                apk update && apk add bash && wget https://raw.githubusercontent.com/lgdlkq/32m/main/xr_install.sh -O xr_install.sh && bash xr_install.sh
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选项"
                ;;
        esac
    done
}

# 微型机哪吒被控端优化
optimize_nezha() {
    clear
    while true; do
        echo "微型机哪吒被控端优化选项："
        echo "1. 优先v6旗帜"
        echo "2. 减少哪吒上报(风险)"
        echo "3. 禁用哪吒Webshell"
        echo "4. 降级被控端"
        echo "5. 删除被控端"
        echo "0. 返回主菜单"
        read -p "请输入选项: " NEZHA_OPTION

        case $NEZHA_OPTION in
            1)
                bash <(curl -s https://raw.githubusercontent.com/xykt/Utilities/main/nezha/ipv6flag.sh)
                ;;
            2)
                bash <(curl -s https://raw.githubusercontent.com/xykt/Utilities/main/nezha/lxc_error_reducer.sh)
                ;;
            3)
                bash <(curl -s https://raw.githubusercontent.com/xykt/Utilities/main/nezha/nowebshell.sh)
                ;;
            4)
                bash <(curl -s https://raw.githubusercontent.com/xykt/Utilities/main/nezha/fix1706.sh)
                ;;
            5)
                systemctl stop nezha-agent
                systemctl disable nezha-agent
                rm -rf /opt/nezha/agent
                echo "被控端已删除。"
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选项"
                ;;
        esac
    done
}

# 更改SSH端口
change_ssh_port() {
    clear
    CURRENT_PORT=$(grep -E "^Port" /etc/ssh/sshd_config | awk '{print $2}')
    echo "当前SSH端口: $CURRENT_PORT"
    
    read -p "是否更改端口 (输入 'YES' 确定，否则返回上级菜单): " CONFIRM

    if [[ "$CONFIRM" == "YES" ]]; then
        read -p "请输入新端口: " NEW_PORT
        
        # 检查新端口是否在范围内（例如 1024-65535）
        if [[ $NEW_PORT -ge 1024 && $NEW_PORT -le 65535 ]]; then
            # 修改配置文件
            sudo sed -i "s/^Port .*/Port $NEW_PORT/" /etc/ssh/sshd_config
            # 重启SSH服务
            sudo systemctl restart ssh
            echo "SSH端口已更改为 $NEW_PORT，服务已重启。"
        else
            echo "无效的端口，端口范围应在1024到65535之间。"
        fi
    else
        echo "返回上级菜单。"
    fi
}

# 网络安全与防滥用菜单
network_security_menu() {
    while true; do
        clear
        echo "网络安全与防滥用选项："
        echo "1. UFW防火墙管理"
        echo "2. Fail2ban SSH防护"
        echo "3. 更改SSH端口（没完成）"
        echo "4. 屏蔽BT"
        echo "5. 屏蔽挖矿"
        echo "6. 屏蔽测速站"
        echo "7. 查看密码登陆成功的IP地址及其次数"
        echo "8. 查看密码登陆失败的IP地址及其次数"
        echo "0. 返回上级菜单"
        read -p "请输入选项: " SECURITY_OPTION

        case $SECURITY_OPTION in
            1)
                echo "正在安装UFW防火墙..."
                sudo apt-get install -y ufw
                echo "UFW防火墙已安装。"
                ;;
            2)
                echo "正在安装Fail2ban SSH防护..."
                sudo apt-get install -y fail2ban
                echo "Fail2ban已安装。"
                ;;
            3)
                change_ssh_port
                ;;
            4)
                echo "正在屏蔽BT..."
                for rule in "torrent" ".torrent" "peer_id=" "announce" "info_hash" "get_peers" "BitTorrent" "announce_peer" "BitTorrent protocol" "announce.php?passkey=" "magnet:" "xunlei" "sandai" "Thunder" "XLLiveUD"; do
                    sudo iptables -A OUTPUT -m string --string "$rule" --algo bm -j DROP
                done
                echo "BT已屏蔽。"
                ;;
            5)
                echo "正在屏蔽挖矿..."
                for rule in "ethermine.com" "antpool.one" "antpool.com" "pool.bar" "get_peers" "announce_peer" "find_node" "seed_hash"; do
                    sudo iptables -A OUTPUT -m string --string "$rule" --algo bm -j DROP
                done
                echo "挖矿已屏蔽。"
                ;;
            6)
                echo "正在屏蔽测速站..."
                for rule in ".speed" "speed." ".speed." "fast.com" "speedtest.net" "speedtest.com" "speedtest.cn" "test.ustc.edu.cn" "10000.gd.cn" "db.laomoe.com" "jiyou.cloud" "ovo.speedtestcustom.com" "speed.cloudflare.com" "speedtest"; do
                    sudo iptables -A OUTPUT -m string --string "$rule" --algo bm -j DROP
                done
                echo "测速站已屏蔽。"
                ;;
            7)
                echo "密码登陆成功的IP地址及其次数"
                grep "Accepted password for root" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr | more
                ;;
            8)
                echo "密码登陆失败的IP地址及其次数"
                grep "Failed password for root" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr | more
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选项"
                ;;
        esac
    done
}

# 安装 iPerf3
install_iperf3() {
    clear
    OS_NAME=$(get_os_name)
    if [[ "$OS_NAME" == *"Debian"* ]] || [[ "$OS_NAME" == *"Ubuntu"* ]]; then
        sudo apt install iperf3 -y
    else
        echo "当前系统不支持自动安装 iPerf3。请手动安装。"
    fi
}

# 启动 iPerf3 服务端
start_server() {
    clear
    echo "启动 iPerf3 服务端..."
    iperf3 -s
}

# 启动 iPerf3 客户端
start_client() {
    clear
    read -p "请输入服务器 IP: " server_ip
    read -p "请输入端口号（默认为 5201）: " port
    port=${port:-5201}
    read -p "请输入测试时间（秒，默认为 10）: " duration
    duration=${duration:-10}
    read -p "请输入窗口大小（如 64K，默认为不设置）: " window_size

    command="iperf3 -c $server_ip -p $port -t $duration"
    if [ -n "$window_size" ]; then
        command="$command -w $window_size"
    fi
    echo "启动 iPerf3 客户端..."
    eval $command
}

# 显示 iPerf3 菜单
iperf3_menu() {
    clear
    while true; do
        echo "=== iPerf3 测试菜单 ==="
        echo "1. 安装 iPerf3"
        echo "2. 启动服务端"
        echo "3. 启动客户端"
        echo "4. 退出"

        read -p "请选择一个选项: " choice

        case $choice in
            1) 
                install_iperf3
                ;;
            2) 
                start_server
                ;;
            3) 
                start_client
                ;;
            4) 
                exit 0
                ;;
            *) 
                echo "无效选项，请重试。"
                ;;
        esac
    done
}

# 显示 测试菜单
function test_menu() {
    clear
    echo "===== 测试菜单 ====="
    echo "1. 流媒体检测（含DNS解锁）"
    echo "2. IP质量体检"
    echo "3. 三网双栈详细回程"
    echo "4. Speedtest（Bench.im）"
    echo "5. HyperSpeed三网测速"
    echo "6. iPerf3"
    echo "0. 返回主菜单"
    echo "====================="
    read -p "请选择一个选项: " choice
    case $choice in
        1)
            echo "运行流媒体检测（含DNS解锁）..."
            bash <(curl -L -s media.ispvps.com)
            ;;
        2)
            echo "运行IP质量体检..."
            bash <(curl -Ls IP.Check.Place)
            ;;
        3)
            echo "运行三网双栈详细回程测试..."
            wget -N --no-check-certificate https://raw.githubusercontent.com/Chennhaoo/Shell_Bash/master/AutoTrace.sh && chmod +x AutoTrace.sh && bash AutoTrace.sh
            ;;
        4)
            echo "运行Speedtest（Bench.im）..."
            wget https://bench.im/x/x86_64/speedtest-cli && chmod +x speedtest-cli && ./speedtest-cli
            ;;
        5)
            echo "运行HyperSpeed三网测速..."
            bash <(wget -qO- https://bench.im/hyperspeed)
            ;;
        6)
            iperf3_menu
            ;;
        0)
            main_menu  # 假设有主菜单功能
            ;;
        *)
            echo "无效选项，请重试"
            test_menu
            ;;
    esac
}

# 显示菜单
while true; do
    clear
    echo "VPSTool V1.0.0"
    # 输出系统类型
    echo "当前系统是 $OS_NAME"
    # 输出虚拟化类型
    echo "虚拟化类型是 $VIRT_TYPE"
    echo "请选择操作："
    echo "00. 更新脚本"
    echo "1. 更新软件包"
    echo "2. 安装常见软件包"
    echo "3. 微型机哪吒被控端优化"
    echo "4. WARP"
    echo "5. 清理系统"
    echo "6. 网络设置"
    echo "7. 安装代理服务端"
    echo "8. 删除未使用的 Docker 镜像"
    echo "9. 安全与防滥用"
    echo "10. VPS"
    echo "11. 测试"
    echo "0. 退出"
    read -p "请输入选项: " OPTION

    case $OPTION in
        00)
            echo "正在更新脚本..."
            curl -o "$0" -Ls https://raw.githubusercontent.com/Yinengjun/MiniSH/refs/heads/main/VPSTool/VPSTool.sh
            chmod +x "$0"
            exec bash "$0"
            ;;
        1)
            echo "正在更新软件包..."
            if [[ "$OS_NAME" == *"Ubuntu"* || "$OS_NAME" == *"Debian"* ]]; then
                sudo apt update && sudo apt upgrade -y
            elif [[ "$OS_NAME" == *"CentOS"* ]]; then
                sudo yum update -y
            elif [[ "$OS_NAME" == *"Alpine"* ]]; then
                sudo apk update && sudo apk upgrade
            else
                echo "不支持的系统，无法更新软件包。"
            fi
            ;;
        2)
            echo "正在安装常见软件包..."
            if [[ "$OS_NAME" == *"Ubuntu"* || "$OS_NAME" == *"Debian"* ]]; then
                sudo apt install -y wget curl sudo
            elif [[ "$OS_NAME" == *"CentOS"* ]]; then
                sudo yum install -y wget curl sudo
            elif [[ "$OS_NAME" == *"Alpine"* ]]; then
                sudo apk add wget curl sudo
            else
                echo "不支持的系统，无法安装软件包。"
            fi
            ;;
        3)
            optimize_nezha
            ;;
        4)
            echo "WARP"
            wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && bash menu.sh
            ;;
        5)
            # 用户选择清理模式
            clear
            echo "请选择清理模式："
            echo "1. 常规清理"
            echo "2. 深度清理"
            read -p "请输入选项（默认 1）： " choice
            choice=${choice:-1}  # 默认选项为 1

            if [ "$choice" == "2" ]; then
                clean "deep"
            else
                clean "normal"
            fi
            ;;
        6)
            network_menu
            ;;
        7)
            install_proxy_server_menu
            ;;
        8)
            echo "正在删除未使用的 Docker 镜像..."
            docker image prune -a --force
            echo "未使用的 Docker 镜像已删除。"
            ;;
        9)
            network_security_menu
            ;;
        10)
            wget https://raw.githubusercontent.com/uselibrary/memoryCheck/main/memoryCheck.sh && chmod +x memoryCheck.sh && bash memoryCheck.sh
            echo "1. 关闭气球驱动（默认）"
            echo "0. 返回主菜单"
            read -p "请输入选项: " Balloon

            if [ "$Balloon" == "1" ]; then
                echo "正在关闭气球驱动..."
                echo "blacklist virtio_balloon" | sudo tee /etc/modprobe.d/blacklist.conf
                sudo update-initramfs -u
                echo "气球驱动已关闭。"
            elif [ "$Balloon" == "0" ]; then
                echo "返回主菜单..."
                return
            else
                echo "无效的选项，请重新输入。"
            fi
            ;;
        11)
            test_menu
            ;;
        0)
            echo "退出脚本。"
            exit 0
            ;;
        *)
            echo "无效的选项"
            ;;
    esac
done
