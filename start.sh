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
# Teacher Portal 测试应用凭据（DatabaseInitializer 启动时自动种子到 app_registrations 表）
# CI 环境中 Teacher Portal 和 Assistant Portal 复用同一组凭据
TEACHER_PORTAL_APP_ID="a6eab9bd87404c0ababc910114d11a62"
TEACHER_PORTAL_APP_SECRET="cGzoAwXaP+PahtD3qXYVY75IJiPWtfbt/4SIt+WrKoQ="
# 首次部署需要 AutoMigrate=true 让 EF Core 创建 security_keys 等表
# 详见 docs/deploy-test/03-known-issues.md 的 N5
AUTO_MIGRATE="${DATABASE_AUTO_MIGRATE:-true}"

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
    -e TEACHER_PORTAL_APP_ID="${TEACHER_PORTAL_APP_ID}" \
    -e TEACHER_PORTAL_APP_SECRET="${TEACHER_PORTAL_APP_SECRET}" \
    -e Database__Name="${DB_NAME}" \
    -e Database__AutoMigrate="${AUTO_MIGRATE}" \
    -v "${DATA_DIR}/master-key:/app/master-key" \
    "$IMAGE_NAME"

echo "${CONTAINER_NAME} started"
docker logs -f -t "$CONTAINER_NAME"
