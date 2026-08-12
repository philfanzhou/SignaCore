#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DATA_DIR="${SCRIPT_DIR}/data"
IMAGE_TAG="${IMAGE_TAG:-latest}"
IMAGE_NAME="${IMAGE_NAME:-signacore:${IMAGE_TAG}}"
CONTAINER_NAME="${CONTAINER_NAME:-signacore}"
PORT="${PORT:-5002}"
HOST_IP="${HOST_IP:-192.168.100.10}"

CONSUL_HTTP_ADDR="${CONSUL_HTTP_ADDR:-${HOST_IP}:8500}"
CONSUL_TOKEN="${CONSUL_TOKEN:-}"

# Inject credentials from a secret store or the operator's environment.
# Validate them before stopping the existing container so a bad deployment leaves it running.
# `:?` requires a non-empty value; `?` permits an explicitly empty value.
ADMIN_USERNAME="${ADMIN_BOOTSTRAP_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_BOOTSTRAP_PASSWORD:?ADMIN_BOOTSTRAP_PASSWORD is required (secret store, never commit it)}"
SMS_BYPASS_CODE="${SMS_BYPASS_CODE?SMS_BYPASS_CODE is required; set it to an empty string to disable the SMS bypass}"
SMS_BYPASS_PHONES="${SMS_BYPASS_PHONES?SMS_BYPASS_PHONES is required; comma-separated allow list, empty disables the SMS bypass}"
SMS_OTP_HMAC_KEY="${SMS_OTP_HMAC_KEY:?SMS_OTP_HMAC_KEY is required (base64, at least 32 random bytes)}"
RSA_MASTER_KEY="${RSA_MASTER_KEY:?RSA_MASTER_KEY is required (secret store, never commit it)}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:${PORT}/health}"
HEALTH_ATTEMPTS="${HEALTH_ATTEMPTS:-60}"
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

mkdir -p "$DATA_DIR"
IMAGE_ID="$(docker image inspect "$IMAGE_NAME" --format '{{.Id}}')"
CONTAINER_UID="${CONTAINER_UID:-$(docker run --rm --entrypoint id "$IMAGE_ID" -u)}"
CONTAINER_GID="${CONTAINER_GID:-$(docker run --rm --entrypoint id "$IMAGE_ID" -g)}"
chown -R "$CONTAINER_UID:$CONTAINER_GID" "$DATA_DIR" 2>/dev/null || true

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
    -e "TZ=Asia/Shanghai"
    -e "APP_TITLE=${CONTAINER_NAME}"
    -e "CONSUL_HTTP_ADDR=${CONSUL_HTTP_ADDR}"
    -e "CONSUL_TOKEN=${CONSUL_TOKEN}"
    -e "Consul__Discovery__PreferIPAddress=true"
    -e "Consul__Discovery__IPAddress=${HOST_IP}"
    -e "Consul__Discovery__Port=${PORT}"
    -e "ADMIN_BOOTSTRAP_USERNAME=${ADMIN_USERNAME}"
    -e "ADMIN_BOOTSTRAP_PASSWORD=${ADMIN_PASSWORD}"
    -e "RSA_MASTER_KEY=${RSA_MASTER_KEY}"
    -e "Sms__BypassCode=${SMS_BYPASS_CODE}"
    -e "Sms__BypassPhones=${SMS_BYPASS_PHONES}"
    -e "Sms__OtpHmacKey=${SMS_OTP_HMAC_KEY}"
)

append_optional_env() {
    local source_name="$1"
    local target_name="$2"
    if [ -n "${!source_name:-}" ]; then
        DOCKER_ENV_ARGS+=(-e "${target_name}=${!source_name}")
    fi
}

append_optional_env DATABASE_PROVIDER Database__Provider
append_optional_env DATABASE_SERVER_VERSION Database__ServerVersion
append_optional_env DATABASE_CONNECTION_STRING Database__ConnectionString
append_optional_env JWT_ISSUER Jwt__Issuer
append_optional_env JWT_AUDIENCE Jwt__Audience
append_optional_env ALLOW_NON_HTTPS_ISSUER Security__AllowNonHttpsIssuer
append_optional_env PUBLIC_BASE_URL Endpoints__PublicBaseUrl
append_optional_env ADMIN_WEB_ORIGIN AdminWeb__AllowedOrigins__0
append_optional_env CALLBACK_ALLOWED_DOMAIN Callback__AllowedDomains__0
append_optional_env CALLBACK_ALLOW_PRIVATE_ADDRESSES Callback__AllowPrivateAddresses
append_optional_env CALLBACK_REQUIRE_HTTPS Callback__RequireHttps
append_optional_env REVERSE_PROXY_IP ReverseProxy__KnownProxies__0
append_optional_env OTLP_ENDPOINT OpenTelemetry__OtlpEndpoint
append_optional_env LOKI_URI Loki__Uri

if ! docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    -p "${PORT}:5002" \
    "${DOCKER_ENV_ARGS[@]}" \
    -v "${DATA_DIR}:/app/data" \
    "$IMAGE_ID"; then
    restore_previous
    exit 1
fi

for ((attempt = 1; attempt <= HEALTH_ATTEMPTS; attempt++)); do
    if [ "$(curl -fsS --max-time 3 "$HEALTH_URL" 2>/dev/null || true)" = "Healthy" ]; then
        if [ -n "$PREVIOUS_CONTAINER_ID" ]; then
            docker rm "$ROLLBACK_NAME" >/dev/null ||
                echo "Warning: healthy deployment retained rollback container $ROLLBACK_NAME" >&2
        fi
        DEPLOYMENT_IN_PROGRESS=false
        echo "Deployment healthy: $CONTAINER_NAME ($IMAGE_ID)"
        exit 0
    fi

    if [ -z "$(docker ps -q --filter "name=^/${CONTAINER_NAME}$")" ]; then
        break
    fi
    sleep "$HEALTH_INTERVAL_SECONDS"
done

echo "New container failed health verification at $HEALTH_URL" >&2
docker logs --tail 200 "$CONTAINER_NAME" >&2 || true
restore_previous
exit 1
