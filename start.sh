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
DB_NAME="ruoyu_identity"
DB_USER="postgres"
DB_PASS="postgres"
CONNECTION_STRING="Host=${DB_HOST};Port=${DB_PORT};Database=${DB_NAME};Username=${DB_USER};Password=${DB_PASS};"

ADMIN_USERNAME="admin"
ADMIN_PASSWORD="Qwer1234"

SMS_BYPASS_CODE="666666"

LOKI_URI="http://ruoyu-loki:3100"

# ===== Portal App Registrations =====
TEACHER_PORTAL_APP_ID="${TEACHER_PORTAL_APP_ID:-}"
TEACHER_PORTAL_APP_SECRET="${TEACHER_PORTAL_APP_SECRET:-}"
ASSISTANT_PORTAL_APP_ID="${ASSISTANT_PORTAL_APP_ID:-}"
ASSISTANT_PORTAL_APP_SECRET="${ASSISTANT_PORTAL_APP_SECRET:-}"

docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || docker network create "$NETWORK_NAME"
if [ -n "$(docker ps -q --filter "name=^/${CONTAINER_NAME}$")" ]; then
    docker stop "$CONTAINER_NAME"
fi
if [ -n "$(docker ps -aq --filter "name=^/${CONTAINER_NAME}$")" ]; then
    docker rm "$CONTAINER_NAME"
fi

mkdir -p "$DATA_DIR/master-key"
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
    -e Database__Provider="${DB_PROVIDER}" \
    -e ConnectionStrings__PostgreSQL="${CONNECTION_STRING}" \
    -e AdminWeb__AdminUsernames__0="${ADMIN_USERNAME}" \
    -e ADMIN_BOOTSTRAP_USERNAME="${ADMIN_USERNAME}" \
    -e ADMIN_BOOTSTRAP_PASSWORD="${ADMIN_PASSWORD}" \
    -e Sms__BypassCode="${SMS_BYPASS_CODE}" \
    -e LOKI_URI="${LOKI_URI}" \
    -e TEACHER_PORTAL_APP_ID="${TEACHER_PORTAL_APP_ID}" \
    -e TEACHER_PORTAL_APP_SECRET="${TEACHER_PORTAL_APP_SECRET}" \
    -e ASSISTANT_PORTAL_APP_ID="${ASSISTANT_PORTAL_APP_ID}" \
    -e ASSISTANT_PORTAL_APP_SECRET="${ASSISTANT_PORTAL_APP_SECRET}" \
    -v "${DATA_DIR}/master-key:/app/master-key" \
    "$IMAGE_NAME"

echo "${CONTAINER_NAME} started"
docker logs -f -t "$CONTAINER_NAME"
