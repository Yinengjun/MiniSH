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
        echo "9. 指定国家蔽连接"
        echo "10. 指定端口屏蔽大陆连接"
        echo "0. 返回上级菜单"
        read -p "请输入选项: " SECURITY_OPTION

        case $SECURITY_OPTION in
            1)
                UFW_menu
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
            9)
                echo "指定国家蔽连接"
                if [[ -f ./block-ips.sh ]]; then
                    echo "已存在 block-ips.sh，正在执行..."
                    chmod +x ./block-ips.sh
                    ./block-ips.sh
                else
                    echo "下载并安装 block-ips.sh..."
                    wget -O block-ips.sh https://raw.githubusercontent.com/iiiiiii1/Block-IPs-from-countries/refs/heads/master/block-ips.sh
                    chmod +x block-ips.sh
                    ./block-ips.sh
                fi
                ;;
            10)
                echo "指定端口屏蔽大陆连接"
                if [[ -f ./cnblock.sh ]]; then
                    echo "已存在 cnblock.sh，正在执行..."
                    chmod +x ./cnblock.sh
                    ./cnblock.sh
                else
                    echo "下载并安装 cnblock.sh..."
                    wget -O cnblock.sh https://gitlab.com/gitlabvps1/cnipblocker/-/raw/main/cnblock.sh
                    chmod +x cnblock.sh
                    ./cnblock.sh
                fi
                ;;
            0)
                return
                ;;
            *)
                echo "无效的选项"
                ;;
        esac
        echo ""
        read -p "按 Enter 键继续..." temp
    done
}

# UFW管理菜单函数
UFW_menu() {
    while true; do
        echo "UFW 防火墙"
        echo "1. 安装 UFW"
        echo "2. 状态检查"
        echo "3. 启动 UFW"
        echo "4. 关闭 UFW"
        echo "5. 重启 UFW"
        echo "6. 查看规则"
        echo "7. 添加规则"
        echo "8. 删除规则"
        echo "9. 删除所有规则"
        echo "10. 查看日志"
        echo "0. 退出"
        read -p "请输入选项 [0-10]: " choice

        case $choice in
            1)
                echo "正在安装 UFW..."
                apt update && apt install -y ufw
                echo "UFW 安装完成。"
                ;;
            2)
                status=$(ufw status | head -n 1)
                echo "当前状态: $status"
                if [[ "$status" == "Status: inactive" ]]; then
                    read -p "UFW 未启用。是否现在启用？(yes/no): " enable_now
                    if [[ $enable_now == "yes" ]]; then
                        ufw enable
                        echo "UFW 已启用。"
                    fi
                fi
                ;;
            3)
                ufw enable
                echo "UFW 已启动。"
                ;;
            4)
                ufw disable
                echo "UFW 已关闭。"
                ;;
            5)
                echo "重启 UFW（先关闭再启动）..."
                ufw disable
                ufw enable
                echo "UFW 已重启。"
                ;;
            6)
                echo "1. 仅查看允许规则 (ALLOW)"
                echo "2. 仅查看禁止规则 (DENY)"
                echo "3. 常见端口规则 (22, 80, 443, 8080)"
                echo "4. 查看全部规则"
                read -p "请选择 [1-4]: " filter_choice

                case $filter_choice in
                    1)
                        rules=($(ufw status numbered | sed '1d' | grep -i "ALLOW"))
                        ;;
                    2)
                        rules=($(ufw status numbered | sed '1d' | grep -i "DENY"))
                        ;;
                    3)
                        rules=($(ufw status numbered | sed '1d' | grep -E "22|80|443|8080"))
                        ;;
                    *)
                        rules=($(ufw status numbered | sed '1d'))
                        ;;
                esac

                total_lines=${#rules[@]}
                page=0
                per_page=20

                while true; do
                    clear
                    echo "-------- UFW 规则 (分页显示) --------"
                    start=$((page * per_page))
                    end=$((start + per_page - 1))

                    if [ $start -ge $total_lines ]; then
                        echo "没有更多规则了。"
                        break
                    fi

                    for i in $(seq $start $end); do
                        if [ $i -lt $total_lines ]; then
                            echo "${rules[$i]}"
                        fi
                    done

                    echo "-------------------------------------"
                    echo "页数：$((page + 1)) / $(( (total_lines + per_page - 1) / per_page ))"
                    echo "[n] 下一页 | [p] 上一页 | [b] 返回主菜单"
                    read -p "请选择操作: " nav

                    case $nav in
                        n)
                            page=$((page + 1))
                            ;;
                        p)
                            if [ $page -gt 0 ]; then
                                page=$((page - 1))
                            fi
                            ;;
                        b)
                            break
                            ;;
                        *)
                            echo "无效输入。"
                            sleep 1
                            ;;
                    esac
                done
                ;;
            7)
                add_UFW_rule_menu
                ;;
            8)
                ufw status numbered
                read -p "请输入要删除的规则编号：" rule_num
                ufw delete $rule_num
                echo "规则 $rule_num 已删除。"
                ;;
            9)
                echo "⚠️ 警告：将删除所有规则！"
                read -p "确认删除所有规则？(yes/no): " confirm
                if [[ $confirm == "yes" ]]; then
                    ufw reset
                    echo "所有规则已重置（删除）。"
                else
                    echo "操作取消。"
                fi
                ;;
            10)
                echo "启用日志记录..."
                ufw logging on
                echo "最近 UFW 日志（按 Ctrl+C 退出）:"
                sleep 1
                tail -f /var/log/ufw.log
                ;;
            0)
                echo "退出 UFW 管理菜单。"
                break
                ;;
            *)
                echo "无效选项，请输入 1-11 之间的数字。"
                ;;
        esac
        echo ""
    done
}

# 添加UFW规则
add_UFW_rule_menu() {
    while true; do
        echo "添加 UFW 规则"
        echo "1. 简单规则 (对象 + 操作 + 端口 + 协议)"
        echo "2. 自定义规则 (手动输入)"
        echo "3. 放行 WEB 端口 (80, 443)"
        echo "4. 放行 SSH (22)"
        echo "5. 放行常见服务端口 (8080)"
        echo "6. 一键放行常用组合 (22, 80, 443, 8080)"
        echo "7. 返回上一级"
        read -p "请选择 [1-7]: " sub_choice

        case $sub_choice in
            1)
                read -p "目标对象（回车跳过，支持 IP / 网段）： " target
                read -p "操作类型（allow 或 deny）： " action
                if [[ "$action" != "allow" && "$action" != "deny" ]]; then
                    echo "无效操作类型，仅支持 allow 或 deny。"
                    continue
                fi

                read -p "端口号（单个: 80，多个: 80,443，范围: 1000:2000）： " ports
                if ! [[ "$ports" =~ ^[0-9:,]+$ ]]; then
                    echo "端口格式错误，请使用合法格式（80,443 或 1000:2000）"
                    continue
                fi

                read -p "协议（tcp / udp / any，默认 any）： " proto
                proto=${proto,,}
                [[ -z "$proto" ]] && proto="any"
                if [[ "$proto" != "tcp" && "$proto" != "udp" && "$proto" != "any" ]]; then
                    echo "协议必须为 tcp、udp 或 any。"
                    continue
                fi

                rule_desc="$action $proto port $ports"
                [[ -n "$target" ]] && rule_desc+=" from $target"

                if ufw status | grep -iq "$action.*$ports.*$proto"; then
                    echo "规则已存在：$rule_desc"
                else
                    cmd="ufw $action proto $proto to any port $ports"
                    [[ -n "$target" ]] && cmd+=" from $target"
                    echo "执行：$cmd"
                    eval $cmd
                fi
                ;;
            2)
                read -p "请输入完整自定义命令（例如 allow from 192.168.1.0/24 to any port 80 proto tcp）: ufw " custom
                if ufw status | grep -iq "$custom"; then
                    echo "规则已存在：ufw $custom"
                else
                    ufw $custom
                fi
                ;;
            3)
                for port in 80 443; do
                    if ufw status | grep -iq "$port/tcp"; then
                        echo "规则已存在：$port/tcp"
                    else
                        ufw allow $port/tcp
                    fi
                done
                ;;
            4)
                if ufw status | grep -iq "22/tcp"; then
                    echo "规则已存在：22/tcp"
                else
                    ufw allow 22/tcp
                fi
                ;;
            5)
                if ufw status | grep -iq "8080/tcp"; then
                    echo "规则已存在：8080/tcp"
                else
                    ufw allow 8080/tcp
                fi
                ;;
            6)
                for port in 22 80 443 8080; do
                    if ufw status | grep -iq "$port/tcp"; then
                        echo "规则已存在：$port/tcp"
                    else
                        ufw allow $port/tcp
                        echo "已放行：$port/tcp"
                    fi
                done
                ;;
            7)
                echo "返回主菜单。"
                break
                ;;
            *)
                echo "无效选项，请输入 1-7。"
                ;;
        esac
        echo ""
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

# 显示 系统设置菜单
system_settings_menu() {
    while true; do
        clear
        echo "系统设置"
        echo "1. 更改主机名"
        echo "2. 管理计划任务"
        echo "3. 切换软件源"
        echo "4. 服务管理"
        echo "5. 设置时区"
        echo "6. 修改 Swap 大小"
        echo "7. 查看端口占用"
        echo "8. 重启系统"
        echo "9. 修改登录密码"
        echo "0. 返回主菜单"
        read -p "请输入选项: " sys_option

        case $sys_option in
            1)
                read -p "请输入新的主机名: " new_hostname
                if [[ -n "$new_hostname" ]]; then
                    sudo hostnamectl set-hostname "$new_hostname"
                    echo "主机名已更改为: $new_hostname"
                else
                    echo "主机名不能为空。"
                fi
                read -p "按回车键继续..."
                ;;
            2)
                cron_job_menu
                ;;
            3)
                echo "正在切换软件源…"
                bash <(curl -sSL https://linuxmirrors.cn/main.sh)
                read -p "按回车键继续..."
                ;;
            4)
                service_management_menu
                ;;
            5)
                set_timezone_menu
                ;;
            6)
                total_mem=$(free -m | awk '/^Mem:/{print $2}')
                recommended_swap=$(awk 'BEGIN {
                    m='$total_mem'*2;
                    p=512;
                    while(p<m){ p*=2 };
                    print p
                }')
                echo "系统内存：${total_mem}MB"
                echo "推荐 Swap 大小：${recommended_swap}MB (内存约两倍，2 的指数)"
                read -p "请输入新的 Swap 大小（单位 MB，默认：${recommended_swap}）: " swap_size
                swap_size=${swap_size:-$recommended_swap}
                if [[ "$swap_size" =~ ^[0-9]+$ ]]; then
                    sudo swapoff -a
                    sudo dd if=/dev/zero of=/swapfile bs=1M count=$swap_size status=progress
                    sudo chmod 600 /swapfile
                    sudo mkswap /swapfile
                    sudo swapon /swapfile
                    sudo sed -i '/\/swapfile/d' /etc/fstab
                    echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab > /dev/null
                    echo "Swap 大小已设置为 ${swap_size}MB。"
                else
                    echo "请输入有效的数字。"
                fi
                read -p "按回车键继续..."
                ;;
            7)
                read -p "请输入要查看的端口（留空查看所有端口）: " port
                if [[ -n "$port" ]]; then
                    sudo lsof -i :$port
                else
                    sudo ss -tuln
                fi
                read -p "按回车键继续..."
                ;;
            8)
                read -p "确认重启系统？[y/N]: " confirm
                if [[ "$confirm" =~ ^[yY]$ ]]; then
                    sudo reboot
                fi
                ;;
            9)
                echo "修改登录密码"
                echo "1) 当前用户（$(whoami)）"
                echo "2) 指定用户"
                read -p "请选择选项: " pwd_option
                if [[ "$pwd_option" == "1" ]]; then
                    echo "为当前用户设置密码：$(whoami)"
                    sudo passwd $(whoami)
                elif [[ "$pwd_option" == "2" ]]; then
                    echo "系统用户列表："
                    users=($(cut -d: -f1 /etc/passwd | grep -E -v '^(nobody|root|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|www-data|backup|list|irc|gnats|systemd|_.*|halt|operator|gdm|sshd|messagebus|usbmuxd|uuidd|avahi|dnsmasq|ntp|nfsnobody|rpc|polkitd|dbus|tcpdump|mysql|postgres|ftp|rpcuser|named|mailnull|smmsp|apache|xfs|vcsa|postfix|qemu|saslauth|chrony|dhcpd|nginx|firewalld|nm-openconnect|lightdm|systemd-resolve|systemd-network)$'))
                    for i in "${!users[@]}"; do
                        echo "$i) ${users[$i]}"
                    done
                    read -p "请输入用户序号: " user_index
                    selected_user=${users[$user_index]}
                    if [[ -n "$selected_user" ]]; then
                        echo "为用户 $selected_user 设置密码："
                        sudo passwd "$selected_user"
                    else
                        echo "无效的用户序号。"
                    fi
                else
                    echo "无效选项。"
                fi
                read -p "按回车键继续..."
                ;;
            0)
                break
                ;;
            *)
                echo "无效选项。"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 管理计划任务
cron_job_menu() {
    while true; do
        clear
        echo "计划任务管理"
        echo "1. 查看当前用户计划任务"
        echo "2. 编辑当前用户计划任务"
        echo "3. 清空当前用户计划任务"
        echo "4. 简单添加当前用户计划任务"
        echo "5. 删除特定当前用户计划任务"
        echo "0. 返回上级菜单"
        read -p "请输入选项: " cron_option

        case $cron_option in
            1)
                echo "当前计划任务："
                crontab -l || echo "无计划任务或 crontab 未设置。"
                read -p "按回车键继续..."
                ;;
            2)
                crontab -e
                ;;
            3)
                crontab -r
                echo "已清空当前用户计划任务。"
                read -p "按回车键继续..."
                ;;
            4)
                # 简单添加任务
                echo "=== 添加新计划任务 ==="
                # 1) 选择常用周期或自定义
                echo "请选择调度周期："
                echo " 1) 每分钟  2) 每小时  3) 每天  4) 每周  5) 每月  6) 自定义"
                read -p "输入序号 [1-6]: " sched_choice

                case $sched_choice in
                    1) cron_expr="* * * * *" ;;
                    2) cron_expr="0 * * * *" ;;
                    3) cron_expr="0 0 * * *" ;;
                    4) cron_expr="0 0 * * 0" ;;
                    5) cron_expr="0 0 1 * *" ;;
                    6)
                        read -p "分钟 (0-59, 用逗号/短横/星号): " m
                        read -p "小时 (0-23, 用逗号/短横/星号): " h
                        read -p "日 (1-31, 用逗号/短横/星号): " dom
                        read -p "月 (1-12, 用逗号/短横/星号): " mon
                        read -p "周几 (0-7, 用逗号/短横/星号, 0和7都代表周日): " dow
                        cron_expr="$m $h $dom $mon $dow"
                        ;;
                    *)
                        echo "无效选项，使用默认“每天”"
                        cron_expr="0 0 * * *"
                        ;;
                esac

                # 2) 询问要执行的命令
                read -p "请输入要执行的命令或脚本（完整路径）： " cmd
                if [[ -z "$cmd" ]]; then
                    echo "命令不能为空，添加取消。"
                else
                    new_entry="$cron_expr $cmd"
                    existing=$(crontab -l 2>/dev/null)

                    if echo "$existing" | grep -Fxq "$new_entry"; then
                        echo "⚠️ 该计划任务已存在，不会重复添加："
                        echo "   $new_entry"
                    else
                        ( echo "$existing"; echo "$new_entry" ) | crontab -
                        echo "✅ 已添加新任务："
                        echo "   $new_entry"
                    fi
                fi
                read -p "按回车键继续..."
                ;;
            5)
                # 删除特定任务
                echo "=== 删除计划任务 ==="
                # 读取现有任务到数组
                mapfile -t lines < <(crontab -l 2>/dev/null)
                if [ ${#lines[@]} -eq 0 ]; then
                    echo "当前没有任何计划任务。"
                    read -p "按回车键继续..."
                    continue
                fi

                # 列出并编号
                echo "0) 取消"
                for i in "${!lines[@]}"; do
                    idx=$((i+1))
                    printf "%2d) %s\n" "$idx" "${lines[i]}"
                done

                # 读用户选择
                read -p "请输入要删除的任务编号: " del_idx
                if ! [[ "$del_idx" =~ ^[0-9]+$ ]] || [ "$del_idx" -lt 0 ] || [ "$del_idx" -gt ${#lines[@]} ]; then
                    echo "无效编号，取消操作。"
                elif [ "$del_idx" -eq 0 ]; then
                    echo "已取消。"
                else
                    # 确认
                    sel="${lines[$((del_idx-1))]}"
                    read -p "确认删除以下任务？[y/N]: $sel  " yn
                    case "$yn" in
                        [Yy]*)
                            # 从数组中过滤掉选中行
                            new_lines=()
                            for j in "${!lines[@]}"; do
                                [ $j -eq $((del_idx-1)) ] && continue
                                new_lines+=("${lines[j]}")
                            done
                            # 写回 crontab
                            printf "%s\n" "${new_lines[@]}" | crontab -
                            echo "已删除任务："
                            echo "  $sel"
                            ;;
                        *)
                            echo "已取消删除。"
                            ;;
                    esac
                fi
                read -p "按回车键继续..."
                ;;
            0)
                break
                ;;
            *)
                echo "无效选项。"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# 服务管理
service_management_menu() {
    # 你可以在这里添加或调整常用服务名称
    local services=("sshd" "nginx" "docker" "自定义服务")
    while true; do
        clear
        echo "服务管理"
        for i in "${!services[@]}"; do
            printf "%2d) %s\n" "$((i+1))" "${services[i]}"
        done
        echo " 0) 返回上级菜单"
        read -p "请选择要管理的服务: " svc_idx

        # 返回主菜单
        if [[ "$svc_idx" == "0" ]]; then
            break
        fi

        # 检查索引合法性
        if ! [[ "$svc_idx" =~ ^[1-9]$ ]] || [ "$svc_idx" -gt "${#services[@]}" ]; then
            echo "无效编号。"
            read -p "按回车键继续..."
            continue
        fi

        # 读取服务名
        svc="${services[$((svc_idx-1))]}"
        if [[ "$svc" == "自定义服务" ]]; then
            read -p "请输入自定义服务名称（systemctl 名称）: " svc
            [[ -z "$svc" ]] && { echo "服务名不能为空。"; read -p "按回车键继续..."; continue; }
        fi

        # 操作子菜单
        while true; do
            clear
            echo "管理服务: $svc"
            echo " 1) 查看状态"
            echo " 2) 启动"
            echo " 3) 停止"
            echo " 4) 重启"
            echo " 5) 重新加载配置"
            echo " 0) 返回上级菜单"
            read -p "请选择操作: " action

            case $action in
                1) sudo systemctl status "$svc";;
                2) sudo systemctl start "$svc" && echo "$svc 已启动";;
                3) sudo systemctl stop "$svc" && echo "$svc 已停止";;
                4) sudo systemctl restart "$svc" && echo "$svc 已重启";;
                5) sudo systemctl reload "$svc" && echo "$svc 配置已重新加载";;
                0) break;;
                *) echo "无效选项。";;
            esac
            read -p "按回车键继续..."
        done
    done
}

# 设置时区
set_timezone_menu() {
    while true; do
        clear
        current_tz=$(timedatectl | grep "Time zone" | awk '{print $3}')
        echo "当前时区：$current_tz"
        echo
        echo "1. 修改时区"
        echo "2. 退出"
        read -p "请选择操作: " opt

        case $opt in
            1)
                while true; do
                    clear
                    echo "请选择时区（常见选项）："
                    echo "1. Asia/Shanghai (中国标准时间)"
                    echo "2. Asia/Tokyo (日本)"
                    echo "3. Asia/Kolkata (印度)"
                    echo "4. Europe/London (英国)"
                    echo "5. America/New_York (纽约)"
                    echo "6. Australia/Sydney (悉尼)"
                    echo "7. 自定义（输入 UTC 偏移）"
                    echo "0. 返回"
                    read -p "请输入选项: " tz_opt

                    case $tz_opt in
                        1) tz="Asia/Shanghai" ;;
                        2) tz="Asia/Tokyo" ;;
                        3) tz="Asia/Kolkata" ;;
                        4) tz="Europe/London" ;;
                        5) tz="America/New_York" ;;
                        6) tz="Australia/Sydney" ;;
                        7)
                            read -p "请输入 UTC 偏移（如 +8 或 -5）: " offset
                            # 转换为 Region/City 格式（根据偏移推断）
                            tz=$(timedatectl list-timezones | grep -E "Etc/GMT[-+]" | grep "Etc/GMT$((-1 * offset))")
                            if [[ -z "$tz" ]]; then
                                echo "不支持的偏移值，请输入范围在 -12 到 +14。"
                                read -p "按回车键继续..."
                                continue
                            fi
                            ;;
                        0) break ;;
                        *) echo "无效选项"; read -p "按回车键继续..."; continue ;;
                    esac

                    if [[ -n "$tz" ]]; then
                        sudo timedatectl set-timezone "$tz"
                        echo "已设置时区为：$tz"
                        read -p "按回车键继续..."
                        break
                    fi
                done
                ;;
            2)
                break
                ;;
            *)
                echo "无效选项"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

# Docker
docker_management_menu() {
    if ! command -v docker &> /dev/null; then
        echo "未检测到 Docker。"
        echo "1. 安装 Docker"
        echo "2. 返回主菜单"
        read -p "请输入选项: " docker_missing_option
        case $docker_missing_option in
            1)
                echo "正在安装 Docker..."
                if [[ -f /etc/debian_version ]]; then
                    sudo apt-get update
                    sudo apt-get install -y \
                        ca-certificates \
                        curl \
                        gnupg \
                        lsb-release
                    sudo mkdir -p /etc/apt/keyrings
                    curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo "$ID")/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
                    echo \
                      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$(. /etc/os-release && echo "$ID") \
                      $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
                    sudo apt-get update
                    sudo apt-get install -y docker-ce docker-ce-cli containerd.io
                    sudo systemctl enable docker
                    sudo systemctl start docker
                    echo "Docker 安装完成。"
                else
                    echo "当前系统不支持自动安装 Docker，请手动安装后重试。"
                fi
                read -p "按回车键继续..."
                ;;
            *)
                echo "返回主菜单..."
                sleep 1
                return
                ;;
        esac
    fi

    while true; do
        clear
        echo "Docker 管理菜单"
        echo "1. 查看容器列表"
        echo "2. 查看镜像列表"
        echo "3. 启动容器"
        echo "4. 停止容器"
        echo "5. 删除已停止的容器"
        echo "6. 删除未使用的镜像"
        echo "7. 清理所有未使用资源"
        echo "8. 查看 Docker 占用空间"
        echo "9. 重启容器"
        echo "10. 查看容器日志"
        echo "11. 进入容器"
        echo "12. 设置容器资源限制"
        echo "13. 设置容器重启规则"
        echo "0. 返回主菜单"
        read -p "请输入选项: " DOCKER_OPTION

        case $DOCKER_OPTION in
            1)
                docker ps -a
                read -p "按回车键继续..." ;;
            2)
                docker images
                read -p "按回车键继续..." ;;
            3)
                docker ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Status}}"
                read -p "请输入要启动的容器ID或名称: " container_id
                docker start "$container_id"
                echo "容器 $container_id 已启动。"
                read -p "按回车键继续..." ;;
            4)
                docker ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Status}}"
                read -p "请输入要停止的容器ID或名称: " container_id
                docker stop "$container_id"
                echo "容器 $container_id 已停止。"
                read -p "按回车键继续..." ;;
            5)
                docker container prune -f
                echo "已删除所有已停止的容器。"
                read -p "按回车键继续..." ;;
            6)
                docker image prune -a -f
                echo "已删除所有未使用的镜像。"
                read -p "按回车键继续..." ;;
            7)
                docker system prune -a -f
                echo "已清理所有未使用资源。"
                read -p "按回车键继续..." ;;
            8)
                docker system df
                read -p "按回车键继续..." ;;
            9)
                docker ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Status}}"
                read -p "请输入要重启的容器ID或名称: " container_id
                docker restart "$container_id"
                echo "容器 $container_id 已重启。"
                read -p "按回车键继续..." ;;
            10)
                docker ps -a --format "table {{.ID}}\t{{.Names}}"
                read -p "请输入要查看日志的容器ID或名称: " container_id
                docker logs --tail 50 "$container_id"
                read -p "按回车键继续..." ;;
            11)
                docker ps -a --format "table {{.ID}}\t{{.Names}}"
                read -p "请输入要进入的容器ID或名称: " container_id
                docker exec -it "$container_id" bash || docker exec -it "$container_id" sh
                read -p "按回车键继续..." ;;
            12)
                docker ps -a --format "table {{.ID}}\t{{.Names}}"
                read -p "请输入容器ID或名称: " container_id
                read -p "请输入内存限制（例如 512m 或 1g，留空不修改）: " mem_limit
                read -p "请输入 CPU 限制（如 0.5 表示50%，留空不修改）: " cpu_limit
                update_cmd="docker update"
                [[ -n "$mem_limit" ]] && update_cmd+=" --memory $mem_limit"
                [[ -n "$cpu_limit" ]] && update_cmd+=" --cpus $cpu_limit"
                update_cmd+=" $container_id"
                eval "$update_cmd"
                echo "资源限制已更新。"
                read -p "按回车键继续..." ;;
            13)
                docker ps -a --format "table {{.ID}}\t{{.Names}}"
                read -p "请输入容器ID或名称: " container_id
                echo "可用重启策略：no | always | unless-stopped | on-failure"
                read -p "请输入重启策略: " restart_policy
                docker update --restart="$restart_policy" "$container_id"
                echo "重启策略已设置为 $restart_policy。"
                read -p "按回车键继续..." ;;
            0)
                break ;;
            *)
                echo "无效的选项，请重新输入。"
                sleep 1 ;;
        esac
    done
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
    echo "12. Docker管理"
    echo "99. 系统设置"
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
            du -sh /var/log/
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
        12)
            docker_management_menu
            ;;
        99)
            system_settings_menu
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
