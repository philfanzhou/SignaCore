#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DATA_DIR="${SCRIPT_DIR}/data"
IMAGE_TAG="${IMAGE_TAG:-latest}"
IMAGE_NAME="${IMAGE_NAME:-signacore:${IMAGE_TAG}}"
CONTAINER_NAME="${CONTAINER_NAME:-signacore}"
PORT="${PORT:-5002}"
HOST_IP="${HOST_IP:-192.168.100.10}"

CONSUL_HTTP_ADDR="${HOST_IP}:8500"
CONSUL_TOKEN="${CONSUL_TOKEN:-}"

# Inject credentials from a secret store or the operator's environment.
# Validate them before stopping the existing container so a bad deployment leaves it running.
# `:?` requires a non-empty value; `?` permits an explicitly empty value.
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
CONTAINER_UID="${CONTAINER_UID:-$(docker run --rm --entrypoint id "$IMAGE_NAME" -u)}"
CONTAINER_GID="${CONTAINER_GID:-$(docker run --rm --entrypoint id "$IMAGE_NAME" -g)}"
chown -R "$CONTAINER_UID:$CONTAINER_GID" "$DATA_DIR" 2>/dev/null || true

docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    -p "${PORT}:5002" \
    -e TZ=Asia/Shanghai \
    -e APP_TITLE="${CONTAINER_NAME}" \
    -e CONSUL_HTTP_ADDR="${CONSUL_HTTP_ADDR}" \
    -e CONSUL_TOKEN="${CONSUL_TOKEN}" \
    -e Consul__Discovery__PreferIPAddress=true \
    -e Consul__Discovery__IPAddress="${HOST_IP}" \
    -e Consul__Discovery__Port="${PORT}" \
    -e ADMIN_BOOTSTRAP_USERNAME="${ADMIN_USERNAME}" \
    -e ADMIN_BOOTSTRAP_PASSWORD="${ADMIN_PASSWORD}" \
    -e Sms__BypassCode="${SMS_BYPASS_CODE}" \
    -e Sms__BypassPhones="${SMS_BYPASS_PHONES}" \
    -e Sms__OtpHmacKey="${SMS_OTP_HMAC_KEY}" \
    -v "${DATA_DIR}:/app/data" \
    "$IMAGE_NAME"
