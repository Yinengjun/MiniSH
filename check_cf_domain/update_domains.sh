#!/bin/bash

# 设置下载链接和保存路径
URL=""
DEST="./domains.txt"  # ⚠️ 修改为你实际要保存的路径

# Telegram 相关
BOT_TOKEN=""
CHAT_ID=""
TG_API="https://api.telegram.org/bot${BOT_TOKEN}/sendMessage"

# 下载 domains.txt
if curl -fsSL "$URL" -o "$DEST"; then
    curl -s -X POST "$TG_API" -d chat_id="$CHAT_ID" -d text="✅ domains.txt 已成功更新。"
else
    curl -s -X POST "$TG_API" -d chat_id="$CHAT_ID" -d text="❌ 更新失败，无法下载 domains.txt。"
fi
