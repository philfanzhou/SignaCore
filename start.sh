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
DB_HOST="ruoyu-postgres"
DB_PORT="5432"
DB_NAME="quantumzhou_identity"
DB_USER="postgres"
DB_PASS="postgres"

ADMIN_USERNAME="admin"
ADMIN_PASSWORD="Qwer1234"

SMS_BYPASS_CODE="666666"

LOKI_URI="http://ruoyu-loki:3100"

# ========== Consul 集成配置（独立模式默认，不设置 CONSUL_MODE = 独立模式）==========
CONSUL_MODE="${CONSUL_MODE:-Off}"
CONSUL_HOST="${CONSUL_HOST:-host.docker.internal}"
CONSUL_PORT="${CONSUL_PORT:-8500}"
CONSUL_SERVICE_NAME="${CONSUL_SERVICE_NAME:-QuantumZhou.Identity}"
CONSUL_TOKEN="${CONSUL_TOKEN:-}"
CONSUL_CONFIG_FILE="${SCRIPT_DIR}/../../../script/env-script/06-consul/config/server.json"

# 条件拼接 Consul 环境变量：On 时注入 -e 参数，Off 时为空（独立模式行为不变）
CONSUL_ENV=""
CONFIG_ENV=""
if [ "${CONSUL_MODE}" = "On" ]; then
    if [ -z "${CONSUL_TOKEN}" ] && [ -f "${CONSUL_CONFIG_FILE}" ]; then
        CONSUL_TOKEN="$(sed -n 's/.*"agent"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "${CONSUL_CONFIG_FILE}" | head -n 1)"
    fi

    CONSUL_ENV="-e CONSUL_MODE=On -e CONSUL_HOST=${CONSUL_HOST} -e CONSUL_PORT=${CONSUL_PORT} -e CONSUL_SERVICE_NAME=${CONSUL_SERVICE_NAME}"
    if [ -n "${CONSUL_TOKEN}" ]; then
        CONSUL_ENV="${CONSUL_ENV} -e CONSUL_TOKEN=${CONSUL_TOKEN}"
    fi

    CONFIG_ENV="-e DB_PASSWORD=${DB_PASS}"
else
    CONFIG_ENV="\
 -e Database__Provider=${DB_PROVIDER} \
 -e Database__Name=${DB_NAME} \
 -e PostgreSql__Host=${DB_HOST} \
 -e PostgreSql__Port=${DB_PORT} \
 -e PostgreSql__Username=${DB_USER} \
 -e DB_PASSWORD=${DB_PASS} \
 -e LOKI_URI=${LOKI_URI}"
fi

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
    ${CONFIG_ENV} \
    ${CONSUL_ENV} \
    -v "${DATA_DIR}/master-key:/app/master-key" \
    -v "${DATA_DIR}/consul:/app/data/consul" \
    "$IMAGE_NAME"

echo "${CONTAINER_NAME} started"
docker logs -f -t "$CONTAINER_NAME"
