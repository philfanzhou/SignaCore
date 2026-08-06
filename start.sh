#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DATA_DIR="${SCRIPT_DIR}/data"
IMAGE_NAME="quantumzhou.identity:20260502"
CONTAINER_NAME="ruoyu-identity"
Port="5002"
HOST_IP="192.168.100.10"

CONSUL_HTTP_ADDR="${HOST_IP}:8500"
CONSUL_TOKEN="${CONSUL_TOKEN:-}"

# 凭据一律由外部注入（GitHub Actions secrets / 运维 shell 环境）。
# 本仓库是 public repo，任何写死在这里的值等同于对全网公开。
# 以下展开在停止旧容器之前执行：缺值时部署直接失败，正在跑的容器不受影响。
#   :?  = 未设置则报错退出（必填）
#   ?   = 未设置则报错退出，显式设为空串是合法的（用于关闭短信绕过）
ADMIN_USERNAME="${ADMIN_BOOTSTRAP_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_BOOTSTRAP_PASSWORD:?ADMIN_BOOTSTRAP_PASSWORD is required (secret store, never commit it)}"
SMS_BYPASS_CODE="${SMS_BYPASS_CODE?SMS_BYPASS_CODE is required; set it to an empty string to disable the SMS bypass}"
SMS_BYPASS_PHONES="${SMS_BYPASS_PHONES?SMS_BYPASS_PHONES is required; comma-separated allow list, empty disables the SMS bypass}"
SMS_OTP_HMAC_KEY="${SMS_OTP_HMAC_KEY:?SMS_OTP_HMAC_KEY is required (base64, at least 32 random bytes)}"

if [ -n "$(docker ps -q --filter "name=^/${CONTAINER_NAME}$")" ]; then
    docker stop "$CONTAINER_NAME"
fi
if [ -n "$(docker ps -aq --filter "name=^/${CONTAINER_NAME}$")" ]; then
    docker rm "$CONTAINER_NAME"
fi

mkdir -p "$DATA_DIR"
chown -R 1000:1000 "$DATA_DIR" 2>/dev/null || true

docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    -p "${Port}:5002" \
    -e TZ=Asia/Shanghai \
    -e APP_TITLE="${CONTAINER_NAME}" \
    -e CONSUL_HTTP_ADDR="${CONSUL_HTTP_ADDR}" \
    -e CONSUL_TOKEN="${CONSUL_TOKEN}" \
    -e Consul__Discovery__PreferIPAddress=true \
    -e Consul__Discovery__IPAddress="${HOST_IP}" \
    -e Consul__Discovery__Port="${Port}" \
    -e ADMIN_BOOTSTRAP_USERNAME="${ADMIN_USERNAME}" \
    -e ADMIN_BOOTSTRAP_PASSWORD="${ADMIN_PASSWORD}" \
    -e Sms__BypassCode="${SMS_BYPASS_CODE}" \
    -e Sms__BypassPhones="${SMS_BYPASS_PHONES}" \
    -e Sms__OtpHmacKey="${SMS_OTP_HMAC_KEY}" \
    -v "${DATA_DIR}:/app/data" \
    "$IMAGE_NAME"
