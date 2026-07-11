#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DATA_DIR="${SCRIPT_DIR}/data"
IMAGE_TAG="20260502"
IMAGE_NAME="quantumzhou.identity:${IMAGE_TAG}"
CONTAINER_NAME="ruoyu-identity"
NETWORK_NAME="ruoyu-net"
HTTP_PORT=10891
DB_PROVIDER="PostgreSQL"
DB_NAME="quantumzhou_identity"

ADMIN_USERNAME="admin"
ADMIN_PASSWORD="Qwer1234"

SMS_BYPASS_CODE="666666"

# ========== Consul 集成配置（Identity 部署脚本固定接入 Consul）==========
CONSUL_HTTP_ADDR="${CONSUL_HTTP_ADDR:-host.docker.internal:8500}"
CONSUL_TOKEN="${CONSUL_TOKEN:-}"

docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || docker network create "$NETWORK_NAME"
if [ -n "$(docker ps -q --filter "name=^/${CONTAINER_NAME}$")" ]; then
    docker stop "$CONTAINER_NAME"
fi
if [ -n "$(docker ps -aq --filter "name=^/${CONTAINER_NAME}$")" ]; then
    docker rm "$CONTAINER_NAME"
fi

mkdir -p "$DATA_DIR/master-key" "$DATA_DIR/consul"
chown -R 1000:1000 "$DATA_DIR" 2>/dev/null || true

if [ -z "$ADMIN_PASSWORD" ]; then
    echo "Please set ADMIN_PASSWORD in start.sh before deployment."
    exit 1
fi

docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    --network "$NETWORK_NAME" \
    -p "${HTTP_PORT}:5002" \
    -e TZ=Asia/Shanghai \
    -e APP_TITLE="${CONTAINER_NAME}" \
    -e AdminWeb__AdminUsernames__0="${ADMIN_USERNAME}" \
    -e ADMIN_BOOTSTRAP_USERNAME="${ADMIN_USERNAME}" \
    -e ADMIN_BOOTSTRAP_PASSWORD="${ADMIN_PASSWORD}" \
    -e Sms__BypassCode="${SMS_BYPASS_CODE}" \
    -e Database__Provider="${DB_PROVIDER}" \
    -e Database__Name="${DB_NAME}" \
    -e CONSUL_HTTP_ADDR="${CONSUL_HTTP_ADDR}" \
    -e CONSUL_TOKEN="${CONSUL_TOKEN}" \
    -v "${DATA_DIR}/master-key:/app/master-key" \
    -v "${DATA_DIR}/consul:/app/data/consul" \
    "$IMAGE_NAME"

echo "${CONTAINER_NAME} started"
docker logs -f -t "$CONTAINER_NAME"
