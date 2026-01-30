#!/bin/bash
#
# Test container build locally or on a VM
#
# Usage: ./test-container.sh [--with-tdx]
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Create version file
echo '__version__ = "test"' > _version.py

# Check for Docker/Podman
if command -v docker &> /dev/null; then
    RUNTIME="docker"
elif command -v podman &> /dev/null; then
    RUNTIME="podman"
else
    echo "ERROR: Docker or Podman required"
    exit 1
fi

echo "Using runtime: $RUNTIME"

# Build image
echo "Building container image..."
$RUNTIME build -t attestation-api:test .

# Stop existing container if running
$RUNTIME rm -f cc-attestation-test 2>/dev/null || true

# Run container
echo "Starting container..."
if [[ "$1" == "--with-tdx" ]]; then
    echo "Running with TDX device access..."
    $RUNTIME run -d \
        --name cc-attestation-test \
        -p 8000:8000 \
        -e "IMAGE_DIGEST=sha256:local-test-build" \
        --device /dev/tdx_guest:/dev/tdx_guest \
        -v /sys/kernel/config/tsm:/sys/kernel/config/tsm:rw \
        attestation-api:test
else
    echo "Running without TDX (ping only)..."
    $RUNTIME run -d \
        --name cc-attestation-test \
        -p 8000:8000 \
        -e "IMAGE_DIGEST=sha256:local-test-build" \
        attestation-api:test
fi

# Wait for startup
echo "Waiting for service to start..."
sleep 3

# Test endpoints
echo ""
echo "=== Testing /ping ==="
curl -s http://localhost:8000/ping | jq .

if [[ "$1" == "--with-tdx" ]]; then
    echo ""
    echo "=== Testing /attestation ==="
    curl -s -X POST http://localhost:8000/attestation \
        -H "Content-Type: application/json" \
        -d '{"nonce": "deadbeef"}' | jq .
fi

echo ""
echo "=== Container logs ==="
$RUNTIME logs cc-attestation-test

echo ""
echo "Container running. To stop: $RUNTIME rm -f cc-attestation-test"
