#!/usr/bin/env bash

# check_cf_domain.sh - 检查一系列子域名是否属于 Cloudflare，并通过 Telegram Bot 发送告警
# 使用方法：
#   1. 在脚本顶部填写以下变量：
#        BOT_TOKEN="<your_bot_token>"    # Telegram Bot Token
#        CHAT_ID="<your_chat_id>"        # Telegram Chat ID
#   2. 配置 domains.txt，每行一个子域，#开头或空行将被忽略
#   3. 可选配置：
#        ENABLE_NOTIF_START_END=true      # 是否发送开始/结束通知，默认 true
#        ENABLE_DETAILED=false            # 是否发送详细通知（包含域名、IP、结果），默认 false
#   4. 添加到 crontab 定时执行，例如：
#        0 * * * * /path/to/check_cf_domain.sh

# ======== 配置区（请自行填写） ========
BOT_TOKEN=""
CHAT_ID=""
ENABLE_NOTIF_START_END=true
ENABLE_DETAILED=false
DOMAINS_FILE="./domains.txt"
CURL_TIMEOUT=5
# =======================================

# 发送 Telegram 消息，静默丢弃所有输出
send_msg() {
  curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
       -d "chat_id=${CHAT_ID}" \
       -d "text=$1" > /dev/null 2>&1
}

# 配置校验
if [[ -z "$BOT_TOKEN" || -z "$CHAT_ID" ]]; then
  exit 1
fi

# 开始通知
if [[ "$ENABLE_NOTIF_START_END" == "true" ]]; then
  send_msg "⚙️ 开始执行 Cloudflare DNS 检测脚本"
fi

# 检测并通知
while IFS= read -r domain || [[ -n "$domain" ]]; do
  [[ "$domain" =~ ^# ]] && continue
  domain="$(echo "$domain" | xargs)"
  [[ -z "$domain" ]] && continue

  # 请求 /cdn-cgi/trace
  resp=$(curl -s --max-time $CURL_TIMEOUT "https://${domain}/cdn-cgi/trace")
  if [[ $? -ne 0 ]]; then
    status="未知 (请求失败)"
  elif [[ "$resp" == *"fl="* ]]; then
    status="✅ 属于 Cloudflare"
  else
    status="❌ 不属于 Cloudflare"
  fi

  if [[ "$ENABLE_DETAILED" == "true" ]]; then
    ip=$(dig +short "$domain" | head -n1)
    send_msg "🌐 域名: ${domain}\nIP: ${ip:-未知}\n结果: ${status}"
  else
    if [[ "$status" == 属于* ]]; then
      send_msg "⚠️ 警告: ${domain} 托管于 Cloudflare"
    fi
  fi

done < "$DOMAINS_FILE"

# 结束通知
if [[ "$ENABLE_NOTIF_START_END" == "true" ]]; then
  send_msg "✅ 完成 Cloudflare DNS 检测脚本"
fi
