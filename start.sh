#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DATA_DIR="${DATA_DIR:-${SCRIPT_DIR}/data}"
CONFIG_DIR="${CONFIG_DIR:-${SCRIPT_DIR}/config}"
BOOTSTRAP_FILE="${CONFIG_DIR}/signacore.bootstrap.json"
IMAGE_TAG="${IMAGE_TAG:-latest}"
IMAGE_NAME="${IMAGE_NAME:-signacore:${IMAGE_TAG}}"
CONTAINER_NAME="${CONTAINER_NAME:-signacore}"
PORT="${PORT:-5002}"

# The launcher owns deployment concerns only: image, container name, host port, mounts, restart
# policy, and timezone. Application configuration lives in the business database and is managed
# through first-run setup and the administration pages. The database connection and the external
# root key live in the writable bootstrap file below.
LIVE_URL="${LIVE_URL:-http://127.0.0.1:${PORT}/health/live}"
READY_URL="${READY_URL:-http://127.0.0.1:${PORT}/health/ready}"
BOOTSTRAP_STATUS_URL="${BOOTSTRAP_STATUS_URL:-http://127.0.0.1:${PORT}/api/bootstrap/status}"
SETUP_STATUS_URL="${SETUP_STATUS_URL:-http://127.0.0.1:${PORT}/api/setup/status}"
LIVE_ATTEMPTS="${LIVE_ATTEMPTS:-60}"
READY_ATTEMPTS="${READY_ATTEMPTS:-60}"
HEALTH_INTERVAL_SECONDS="${HEALTH_INTERVAL_SECONDS:-2}"
STOP_TIMEOUT_SECONDS="${STOP_TIMEOUT_SECONDS:-35}"

if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required for deployment health verification" >&2
    exit 1
fi

if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Image not found: $IMAGE_NAME" >&2
    exit 1
fi

mkdir -p "$DATA_DIR" "$CONFIG_DIR"
IMAGE_ID="$(docker image inspect "$IMAGE_NAME" --format '{{.Id}}')"
CONTAINER_UID="${CONTAINER_UID:-$(docker run --rm --entrypoint id "$IMAGE_ID" -u)}"
CONTAINER_GID="${CONTAINER_GID:-$(docker run --rm --entrypoint id "$IMAGE_ID" -g)}"
chown -R "$CONTAINER_UID:$CONTAINER_GID" "$DATA_DIR" 2>/dev/null || true
# The bootstrap backend creates and atomically replaces the file, so the runtime identity needs
# exclusive read/write access to this persistent directory.
chown -R "$CONTAINER_UID:$CONTAINER_GID" "$CONFIG_DIR" 2>/dev/null || true
chmod 700 "$CONFIG_DIR" 2>/dev/null || true
chmod 600 "$CONFIG_DIR"/* 2>/dev/null || true

ROLLBACK_NAME="${CONTAINER_NAME}-rollback-$(date +%s)-$$"
PREVIOUS_CONTAINER_ID="$(docker ps -aq --filter "name=^/${CONTAINER_NAME}$")"
PREVIOUS_WAS_RUNNING=false
DEPLOYMENT_IN_PROGRESS=false

restore_previous() {
    DEPLOYMENT_IN_PROGRESS=false
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    if [ -n "$PREVIOUS_CONTAINER_ID" ]; then
        docker rename "$ROLLBACK_NAME" "$CONTAINER_NAME" >/dev/null
        if [ "$PREVIOUS_WAS_RUNNING" = true ]; then
            docker start "$CONTAINER_NAME" >/dev/null
        fi
        echo "Deployment failed; restored previous container: $CONTAINER_NAME" >&2
    else
        echo "Deployment failed; no previous container was available to restore" >&2
    fi
}

rollback_on_unexpected_exit() {
    local status="$?"
    if [ "$status" -ne 0 ] && [ "$DEPLOYMENT_IN_PROGRESS" = true ]; then
        restore_previous
    fi
    exit "$status"
}

trap rollback_on_unexpected_exit EXIT

if [ -n "$PREVIOUS_CONTAINER_ID" ]; then
    if [ -n "$(docker ps -q --filter "name=^/${CONTAINER_NAME}$")" ]; then
        PREVIOUS_WAS_RUNNING=true
        docker stop --time "$STOP_TIMEOUT_SECONDS" "$CONTAINER_NAME" >/dev/null
    fi
    docker rename "$CONTAINER_NAME" "$ROLLBACK_NAME"
fi
DEPLOYMENT_IN_PROGRESS=true

DOCKER_ENV_ARGS=(
    -e "TZ=${TZ:-Asia/Shanghai}"
    -e "APP_TITLE=${APP_TITLE:-${CONTAINER_NAME}}"
)

# `unless-stopped` is what turns "setup completed" into "process restarted into the normal host":
# the setup-mode host stops itself once the setup transaction has committed.
if ! docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    -p "${PORT}:5002" \
    "${DOCKER_ENV_ARGS[@]}" \
    -v "${CONFIG_DIR}:/app/config" \
    -v "${DATA_DIR}:/app/data" \
    "$IMAGE_ID"; then
    restore_previous
    exit 1
fi

container_is_running() {
    [ -n "$(docker ps -q --filter "name=^/${CONTAINER_NAME}$")" ]
}

# Liveness first: a brand-new instance is deliberately not ready, and waiting for readiness would
# make it impossible to ever reach the setup page.
LIVE=false
for ((attempt = 1; attempt <= LIVE_ATTEMPTS; attempt++)); do
    if curl -fsS --max-time 3 "$LIVE_URL" >/dev/null 2>&1; then
        LIVE=true
        break
    fi
    if ! container_is_running; then
        break
    fi
    sleep "$HEALTH_INTERVAL_SECONDS"
done

if [ "$LIVE" != true ]; then
    echo "New container failed liveness verification at $LIVE_URL" >&2
    docker logs --tail 200 "$CONTAINER_NAME" >&2 || true
    restore_previous
    exit 1
fi

for ((attempt = 1; attempt <= READY_ATTEMPTS; attempt++)); do
    if curl -fsS --max-time 3 "$READY_URL" >/dev/null 2>&1; then
        if [ -n "$PREVIOUS_CONTAINER_ID" ]; then
            docker rm "$ROLLBACK_NAME" >/dev/null ||
                echo "Warning: healthy deployment retained rollback container $ROLLBACK_NAME" >&2
        fi
        DEPLOYMENT_IN_PROGRESS=false
        echo "Deployment ready: $CONTAINER_NAME ($IMAGE_ID)"
        exit 0
    fi

    # With no file the process stays live in protected Bootstrap Configuration Mode. This is a
    # successful deployment awaiting an operator, not a readiness failure.
    if curl -fsS --max-time 3 "$BOOTSTRAP_STATUS_URL" 2>/dev/null | grep -Eq '"status":"(required|restarting)"'; then
        if [ -n "$PREVIOUS_CONTAINER_ID" ]; then
            docker rm "$ROLLBACK_NAME" >/dev/null ||
                echo "Warning: retained rollback container $ROLLBACK_NAME" >&2
        fi
        DEPLOYMENT_IN_PROGRESS=false
        echo "Deployment is awaiting bootstrap configuration: $CONTAINER_NAME ($IMAGE_ID)"
        echo "Open http://<host>:${PORT}/bootstrap and enter the one-time code printed in the container log:"
        echo "  docker logs $CONTAINER_NAME"
        exit 0
    fi

    # A live-but-not-ready instance whose setup endpoint reports "pending" is a brand-new
    # installation waiting for an operator, not a failed deployment.
    if curl -fsS --max-time 3 "$SETUP_STATUS_URL" 2>/dev/null | grep -q '"status":"pending"'; then
        if [ -n "$PREVIOUS_CONTAINER_ID" ]; then
            docker rm "$ROLLBACK_NAME" >/dev/null ||
                echo "Warning: retained rollback container $ROLLBACK_NAME" >&2
        fi
        DEPLOYMENT_IN_PROGRESS=false
        echo "Deployment is awaiting first-run setup: $CONTAINER_NAME ($IMAGE_ID)"
        echo "Open http://<host>:${PORT}/setup and enter the one-time setup code printed in the container log:"
        echo "  docker logs $CONTAINER_NAME"
        exit 0
    fi

    if ! container_is_running; then
        break
    fi
    sleep "$HEALTH_INTERVAL_SECONDS"
done

echo "New container failed readiness verification at $READY_URL" >&2
docker logs --tail 200 "$CONTAINER_NAME" >&2 || true
restore_previous
exit 1
