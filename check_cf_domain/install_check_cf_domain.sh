#!/bin/bash

echo "📦 开始安装 check_cf_domain 脚本组..."

# === Telegram 通知配置 ===
read -p "请输入 Telegram BOT_TOKEN: " BOT_TOKEN
read -p "请输入 Telegram CHAT_ID: " CHAT_ID

# === 设置 check_cf_domain.sh 执行时间 ===
read -p "设置 check_cf_domain.sh 执行时间 (默认 04:00，格式 HH:MM): " TIME2
TIME2=${TIME2:-04:00}
H2=$(echo "$TIME2" | cut -d: -f1)
M2=$(echo "$TIME2" | cut -d: -f2)

# === 设置安装路径 ===
INSTALL_DIR="$(pwd)/check_cf_domain"
mkdir -p "$INSTALL_DIR"

# === 是否使用域名订阅更新 ===
read -p "请输入 domains.txt 订阅地址（可回车跳过）: " URL

USE_SUBSCRIPTION=false
if [ -n "$URL" ]; then
    USE_SUBSCRIPTION=true
fi

# === 处理 update_domains.sh ===
if [ "$USE_SUBSCRIPTION" = true ]; then
    echo "➡️ 使用订阅地址更新 domains.txt"
    SCRIPT1_URL="https://raw.githubusercontent.com/Yinengjun/MiniSH/refs/heads/main/check_cf_domain/update_domains.sh"
    SCRIPT1_PATH="${INSTALL_DIR}/update_domains.sh"
    curl -fsSL "$SCRIPT1_URL" -o "$SCRIPT1_PATH" || { echo "❌ 下载失败: $SCRIPT1_URL"; exit 1; }
    sed -i "s|BOT_TOKEN=\"\"|BOT_TOKEN=\"${BOT_TOKEN}\"|g" "$SCRIPT1_PATH"
    sed -i "s|CHAT_ID=\"\"|CHAT_ID=\"${CHAT_ID}\"|g" "$SCRIPT1_PATH"
    sed -i "s|URL=\"\"|URL=\"${URL}\"|g" "$SCRIPT1_PATH"
    chmod +x "$SCRIPT1_PATH"

    # 设置定时任务时间（可自定义）
    read -p "设置 update_domains.sh 执行时间 (默认 03:00，格式 HH:MM): " TIME1
    TIME1=${TIME1:-03:00}
    H1=$(echo "$TIME1" | cut -d: -f1)
    M1=$(echo "$TIME1" | cut -d: -f2)
    CRON1="${M1} ${H1} * * * ${SCRIPT1_PATH}"
else
    echo "📝 未使用订阅，手动创建 domains.txt"
    echo "请输入你想要添加的子域名，每行一个，输入空行结束："
    DOMAINS=()
    while true; do
        read -p "> " domain
        [[ -z "$domain" ]] && break
        DOMAINS+=("$domain")
    done
    printf "%s\n" "${DOMAINS[@]}" > "${INSTALL_DIR}/domains.txt"
    echo "✅ 已保存到 ${INSTALL_DIR}/domains.txt"
fi

# === 下载 check_cf_dns.sh ===
SCRIPT2_URL="https://raw.githubusercontent.com/Yinengjun/MiniSH/refs/heads/main/check_cf_domain/check_cf_domain.sh"
SCRIPT2_PATH="${INSTALL_DIR}/check_cf_domain.sh"
curl -fsSL "$SCRIPT2_URL" -o "$SCRIPT2_PATH" || { echo "❌ 下载失败: $SCRIPT2_URL"; exit 1; }
sed -i "s|BOT_TOKEN=\"\"|BOT_TOKEN=\"${BOT_TOKEN}\"|g" "$SCRIPT2_PATH"
sed -i "s|CHAT_ID=\"\"|CHAT_ID=\"${CHAT_ID}\"|g" "$SCRIPT2_PATH"
chmod +x "$SCRIPT2_PATH"

# === 安装 crontab ===
(crontab -l 2>/dev/null | grep -v "$SCRIPT1_PATH" | grep -v "$SCRIPT2_PATH"; \
[ "$USE_SUBSCRIPTION" = true ] && echo "$CRON1"; \
echo "${M2} ${H2} * * * ${SCRIPT2_PATH}") | crontab -

# === 校验定时任务是否成功 ===
CRONTAB_CONTENT=$(crontab -l 2>/dev/null)

echo ""
if [ "$USE_SUBSCRIPTION" = true ]; then
    if echo "$CRONTAB_CONTENT" | grep -q "$SCRIPT1_PATH"; then
        echo "✅ 定时任务添加成功: update_domains.sh @ $TIME1"
    else
        echo "⚠️  update_domains.sh 添加失败"
    fi
else
    echo "✅ 已跳过 update_domains.sh 安装"
fi

if echo "$CRONTAB_CONTENT" | grep -q "$SCRIPT2_PATH"; then
    echo "✅ 定时任务添加成功: check_cf_dns.sh @ $TIME2"
else
    echo "⚠️  check_cf_dns.sh 添加失败"
fi
