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

ADMIN_USERNAME="admin"
ADMIN_PASSWORD="Qwer1234"
SMS_BYPASS_CODE="666666"

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
    -v "${DATA_DIR}:/app/data" \
    "$IMAGE_NAME"
