#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_TAG="${IMAGE_TAG:-latest}"
IMAGE_NAME="${IMAGE_NAME:-signacore:${IMAGE_TAG}}"

echo "=========================================="
echo "Building SignaCore: $IMAGE_NAME"
echo "=========================================="

build_args=(docker build)
if [ -n "${SIGNACORE_NODE_IMAGE:-}" ]; then
    case "$SIGNACORE_NODE_IMAGE" in
        public.ecr.aws/docker/library/node:24-alpine@sha256:83f1c388c31fb2e51f7cbd4dea949b96260798c98f206e8e4696bc93bd964e3a|docker.io/library/node:24-alpine@sha256:83f1c388c31fb2e51f7cbd4dea949b96260798c98f206e8e4696bc93bd964e3a)
            build_args+=(--build-arg "NODE_IMAGE=$SIGNACORE_NODE_IMAGE") ;;
        *) echo "SIGNACORE_NODE_IMAGE must be a pinned official CI Node reference." >&2; exit 2 ;;
    esac
fi

"${build_args[@]}" \
    -f "$SCRIPT_DIR/src/SignaCore.Host/Dockerfile" \
    -t "$IMAGE_NAME" \
    "$SCRIPT_DIR"

echo "Image built: $IMAGE_NAME"
