#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_TAG="${IMAGE_TAG:-20260502}"
IMAGE_NAME="${IMAGE_NAME:-quantumzhou.identity:${IMAGE_TAG}}"

echo "=========================================="
echo "Building QuantumZhou.Identity: $IMAGE_NAME"
echo "=========================================="

docker build \
    -f "$SCRIPT_DIR/backend/Host/Dockerfile" \
    -t "$IMAGE_NAME" \
    "$SCRIPT_DIR"

echo "Image built: $IMAGE_NAME"
