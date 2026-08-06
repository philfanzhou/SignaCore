#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_TAG="${IMAGE_TAG:-latest}"
IMAGE_NAME="${IMAGE_NAME:-signacore:${IMAGE_TAG}}"

echo "=========================================="
echo "Building SignaCore: $IMAGE_NAME"
echo "=========================================="

docker build \
    -f "$SCRIPT_DIR/src/SignaCore.Host/Dockerfile" \
    -t "$IMAGE_NAME" \
    "$SCRIPT_DIR"

echo "Image built: $IMAGE_NAME"
