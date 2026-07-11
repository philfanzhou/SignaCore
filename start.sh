#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DATA_DIR="${SCRIPT_DIR}/data"
IMAGE_NAME="quantumzhou.identity:20260502"
CONTAINER_NAME="ruoyu-identity"
NETWORK_NAME="ruoyu-net"
HTTP_PORT=5002

CONSUL_HTTP_ADDR="host.docker.internal:8500"
CONSUL_TOKEN="${CONSUL_TOKEN:-}"

DB_NAME="ruoyu_identity"
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="Qwer1234"
SMS_BYPASS_CODE="666666"

docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || docker network create "$NETWORK_NAME"
if [ -n "$(docker ps -q --filter "name=^/${CONTAINER_NAME}$")" ]; then
    docker stop "$CONTAINER_NAME"
fi
if [ -n "$(docker ps -aq --filter "name=^/${CONTAINER_NAME}$")" ]; then
    docker rm "$CONTAINER_NAME"
fi

mkdir -p "$DATA_DIR/master-key"
chown -R 1000:1000 "$DATA_DIR" 2>/dev/null || true

docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    --network "$NETWORK_NAME" \
    --add-host=host.docker.internal:host-gateway \
    -p "${HTTP_PORT}:5002" \
    -e TZ=Asia/Shanghai \
    -e APP_TITLE="${CONTAINER_NAME}" \
    -e CONSUL_HTTP_ADDR="${CONSUL_HTTP_ADDR}" \
    -e CONSUL_TOKEN="${CONSUL_TOKEN}" \
    -e ADMIN_BOOTSTRAP_USERNAME="${ADMIN_USERNAME}" \
    -e ADMIN_BOOTSTRAP_PASSWORD="${ADMIN_PASSWORD}" \
    -e Sms__BypassCode="${SMS_BYPASS_CODE}" \
    -e Database__Name="${DB_NAME}" \
    -v "${DATA_DIR}/master-key:/app/master-key" \
    "$IMAGE_NAME"

echo "${CONTAINER_NAME} started"
docker logs -f -t "$CONTAINER_NAME"
