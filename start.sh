#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
IMAGE_TAG="20260502"
IMAGE="quantumzhou.identity:${IMAGE_TAG}"
CONTAINER_NAME="ruoyu-identity"
NETWORK_NAME="ruoyu-net"

#GRPC_PORT=10890
HTTP_PORT=10891

DB_HOST="ruoyu-postgres"
DB_PORT="5432"
DB_NAME="ruoyu_identity"
DB_USER="postgres"
DB_PASS="postgres"
CONNECTION_STRING="Host=${DB_HOST};Port=${DB_PORT};Database=${DB_NAME};Username=${DB_USER};Password=${DB_PASS};"
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="Qwer1234"

DATA_DIR="${SCRIPT_DIR}/data"

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
    -e Database__Provider="PostgreSQL" \
    -e ConnectionStrings__PostgreSQL="${CONNECTION_STRING}" \
    -e AdminWeb__AdminUsernames__0="${ADMIN_USERNAME}" \
    -e ADMIN_BOOTSTRAP_USERNAME="${ADMIN_USERNAME}" \
    -e ADMIN_BOOTSTRAP_PASSWORD="${ADMIN_PASSWORD}" \
    -e Callback__AllowPrivateAddresses="true" \
    -e Callback__AllowedDomains__0="ruoyu-teacher-api" \
    -v "${DATA_DIR}/master-key:/app/master-key" \
    "$IMAGE"

echo "${CONTAINER_NAME} started"
docker logs -f -t "$CONTAINER_NAME"
