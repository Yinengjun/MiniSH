#!/bin/bash

echo "📦 正在安装 update_domains.sh 和 check_cf_dns.sh 脚本..."

# === 用户输入 TG 配置 ===
read -p "请输入 Telegram BOT_TOKEN: " BOT_TOKEN
read -p "请输入 Telegram CHAT_ID: " CHAT_ID

# === 用户设置定时任务时间（默认值可回车） ===
read -p "设置 update_domains.sh 执行时间 (默认 03:00，格式 HH:MM): " TIME1
read -p "设置 check_cf_dns.sh 执行时间 (默认 04:00，格式 HH:MM): " TIME2

TIME1=${TIME1:-03:00}
TIME2=${TIME2:-04:00}

# 拆解时间
H1=$(echo "$TIME1" | cut -d: -f1)
M1=$(echo "$TIME1" | cut -d: -f2)
H2=$(echo "$TIME2" | cut -d: -f1)
M2=$(echo "$TIME2" | cut -d: -f2)

# === 设置安装路径 ===
INSTALL_DIR="$(pwd)/check_cf_dns"
mkdir -p "$INSTALL_DIR"

SCRIPT1_URL="https://114.com/update_domains.sh"
SCRIPT2_URL="https://114.com/check_cf_dns.sh"

SCRIPT1_PATH="${INSTALL_DIR}/update_domains.sh"
SCRIPT2_PATH="${INSTALL_DIR}/check_cf_dns.sh"

# === 下载脚本 ===
echo "⬇️ 正在下载脚本..."
curl -fsSL "$SCRIPT1_URL" -o "$SCRIPT1_PATH" || { echo "❌ 下载失败: $SCRIPT1_URL"; exit 1; }
curl -fsSL "$SCRIPT2_URL" -o "$SCRIPT2_PATH" || { echo "❌ 下载失败: $SCRIPT2_URL"; exit 1; }

# === 注入 TOKEN 和 CHAT_ID ===
for SCRIPT in "$SCRIPT1_PATH" "$SCRIPT2_PATH"; do
    sed -i "s|BOT_TOKEN=\"\"|BOT_TOKEN=\"${BOT_TOKEN}\"|g" "$SCRIPT"
    sed -i "s|CHAT_ID=\"\"|CHAT_ID=\"${CHAT_ID}\"|g" "$SCRIPT"
    chmod +x "$SCRIPT"
done

# === 添加到 crontab（去重后添加） ===
CRON1="${M1} ${H1} * * * ${SCRIPT1_PATH}"
CRON2="${M2} ${H2} * * * ${SCRIPT2_PATH}"

(crontab -l 2>/dev/null | grep -v "$SCRIPT1_PATH" | grep -v "$SCRIPT2_PATH"; \
echo "$CRON1"; \
echo "$CRON2") | crontab -

# === 验证是否成功写入 crontab ===
CRONTAB_CONTENT=$(crontab -l 2>/dev/null)

if echo "$CRONTAB_CONTENT" | grep -q "$SCRIPT1_PATH" && echo "$CRONTAB_CONTENT" | grep -q "$SCRIPT2_PATH"; then
    echo "✅ 定时任务添加成功："
    echo " - update_domains.sh @ $TIME1"
    echo " - check_cf_dns.sh  @ $TIME2"
else
    echo "❌ 定时任务添加失败，请手动检查 crontab。"
    exit 1
fi
