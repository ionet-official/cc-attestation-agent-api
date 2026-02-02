#!/bin/bash
#
# Container-based Attestation API Deployment Script
#
# This script pulls, verifies, and deploys the attestation API as a container
# with full signature and SBOM verification.
#
# Usage: ./deploy.sh <version> [--skip-vuln-scan]
#
# Prerequisites:
#   - Docker or Podman
#   - cosign (will be installed if missing)
#   - slsa-verifier (will be installed if missing)
#   - grype (optional, for vulnerability scanning)
#
set -e
set -u
set -o pipefail

# Configuration
GITHUB_ORG="${GITHUB_ORG:-ionet-official}"
GITHUB_REPO="${GITHUB_REPO:-cc-attestation-agent-api}"
REGISTRY="${REGISTRY:-ghcr.io}"
IMAGE_NAME="${REGISTRY}/${GITHUB_ORG}/${GITHUB_REPO}"
CONTAINER_NAME="${CONTAINER_NAME:-cc-attestation}"
CERTS_DIR="${CERTS_DIR:-/opt/ionet/cc-attestation-agent-api/certs}"
ENV_FILE="${ENV_FILE:-/etc/default/cc-attestation}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}==>${NC} $1"; }
log_warn() { echo -e "${YELLOW}==> WARNING:${NC} $1"; }
log_error() { echo -e "${RED}==> ERROR:${NC} $1" >&2; }

# Detect container runtime
if command -v docker &> /dev/null; then
    CONTAINER_RUNTIME="docker"
elif command -v podman &> /dev/null; then
    CONTAINER_RUNTIME="podman"
else
    log_error "Neither Docker nor Podman found. Please install one of them."
    exit 1
fi

log_info "Using container runtime: $CONTAINER_RUNTIME"

# Parse arguments
VERSION="${1:-}"
SKIP_VULN_SCAN=false

if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version> [--skip-vuln-scan]"
    echo ""
    echo "Arguments:"
    echo "  version          Version to deploy (e.g., v1.0.0 or 1.0.0)"
    echo "  --skip-vuln-scan Skip vulnerability scanning"
    echo ""
    echo "Environment variables:"
    echo "  GITHUB_ORG       GitHub organization (default: ionet-official)"
    echo "  GITHUB_REPO      GitHub repository (default: cc-attestation-agent-api)"
    echo "  REGISTRY         Container registry (default: ghcr.io)"
    echo "  CONTAINER_NAME   Container name (default: cc-attestation)"
    echo "  CERTS_DIR        SSL certificates directory (default: /opt/ionet/cc-attestation-agent-api/certs)"
    echo "  CERT_CN          Common Name for SSL certificate (default: hostname)"
    echo "  VLLM_API_KEY     API key for vLLM (will prompt if not set)"
    echo ""
    echo "SSL Certificates:"
    echo "  If certs/key.pem and certs/cert.pem don't exist, a self-signed"
    echo "  certificate will be generated. For production, replace with proper"
    echo "  certificates (e.g., Cloudflare Origin Certificate)."
    exit 1
fi

for arg in "$@"; do
    if [[ "$arg" == "--skip-vuln-scan" ]]; then
        SKIP_VULN_SCAN=true
    fi
done

# Normalize version
VERSION="${VERSION#v}"
VERSION_TAG="v${VERSION}"

# ==============================================================================
# Get image digest from release
# ==============================================================================
log_info "Fetching image digest for version ${VERSION_TAG}..."

RELEASE_URL="https://github.com/${GITHUB_ORG}/${GITHUB_REPO}/releases/download/${VERSION_TAG}"

# Download image digest
IMAGE_DIGEST=$(curl -fsSL "${RELEASE_URL}/image-digest.txt" | tr -d '[:space:]')

if [[ -z "$IMAGE_DIGEST" ]]; then
    log_error "Failed to fetch image digest"
    exit 1
fi

FULL_IMAGE="${IMAGE_NAME}@${IMAGE_DIGEST}"
log_info "Image: ${FULL_IMAGE}"

# ==============================================================================
# Install verification tools if needed
# ==============================================================================
install_cosign() {
    log_info "Installing cosign..."
    COSIGN_VERSION="v2.2.4"
    curl -fsSL -o /tmp/cosign "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
    chmod +x /tmp/cosign
    sudo mv /tmp/cosign /usr/local/bin/
}

install_slsa_verifier() {
    log_info "Installing slsa-verifier..."
    SLSA_VERIFIER_VERSION="v2.6.0"
    curl -fsSL -o /tmp/slsa-verifier "https://github.com/slsa-framework/slsa-verifier/releases/download/${SLSA_VERIFIER_VERSION}/slsa-verifier-linux-amd64"
    chmod +x /tmp/slsa-verifier
    sudo mv /tmp/slsa-verifier /usr/local/bin/
}

install_grype() {
    log_info "Installing grype..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
}

if ! command -v cosign &> /dev/null; then
    install_cosign
fi

if ! command -v slsa-verifier &> /dev/null; then
    install_slsa_verifier
fi

# ==============================================================================
# Verify image signature
# ==============================================================================
log_info "Verifying image signature with Sigstore..."

if ! cosign verify "$FULL_IMAGE" \
    --certificate-identity-regexp ".*" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    2>/dev/null; then
    log_error "Image signature verification failed!"
    exit 1
fi

log_info "Image signature verified successfully"

# ==============================================================================
# Verify SBOM attestation
# ==============================================================================
log_info "Verifying SBOM attestation..."

if ! cosign verify-attestation "$FULL_IMAGE" \
    --type cyclonedx \
    --certificate-identity-regexp ".*" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    2>/dev/null; then
    log_error "SBOM attestation verification failed!"
    exit 1
fi

log_info "SBOM attestation verified successfully"

# ==============================================================================
# Verify SLSA provenance (Level 3)
# ==============================================================================
log_info "Verifying SLSA provenance..."

if ! slsa-verifier verify-image "$FULL_IMAGE" \
    --source-uri "github.com/${GITHUB_ORG}/${GITHUB_REPO}" \
    2>/dev/null; then
    log_error "SLSA provenance verification failed!"
    exit 1
fi

log_info "SLSA provenance verified successfully (Level 3)"

# ==============================================================================
# Vulnerability scanning
# ==============================================================================
if [[ "$SKIP_VULN_SCAN" != "true" ]]; then
    if ! command -v grype &> /dev/null; then
        log_warn "grype not installed. Install it for vulnerability scanning."
        read -p "Install grype now? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_grype
        else
            log_warn "Skipping vulnerability scan"
            SKIP_VULN_SCAN=true
        fi
    fi

    if [[ "$SKIP_VULN_SCAN" != "true" ]]; then
        log_info "Scanning image for vulnerabilities..."

        if ! grype "$FULL_IMAGE" --fail-on critical; then
            log_error "Critical vulnerabilities detected!"
            read -p "Continue anyway? [y/N] " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
            log_warn "Continuing despite vulnerabilities..."
        else
            log_info "No critical vulnerabilities found"
        fi
    fi
else
    log_warn "Skipping vulnerability scan (--skip-vuln-scan)"
fi

echo ""
log_info "============================================"
log_info "All verifications passed!"
log_info "============================================"
echo ""

# ==============================================================================
# Pull image
# ==============================================================================
log_info "Pulling container image..."

$CONTAINER_RUNTIME pull "$FULL_IMAGE"

# ==============================================================================
# Stop existing container if running
# ==============================================================================
if $CONTAINER_RUNTIME ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    log_info "Stopping existing container..."
    $CONTAINER_RUNTIME stop "$CONTAINER_NAME" 2>/dev/null || true
    $CONTAINER_RUNTIME rm "$CONTAINER_NAME" 2>/dev/null || true
fi

# ==============================================================================
# Generate SSL certificates if needed
# ==============================================================================
CERT_FILE="${CERTS_DIR}/cert.pem"
KEY_FILE="${CERTS_DIR}/key.pem"

sudo mkdir -p "$CERTS_DIR"

if [[ ! -f "$CERT_FILE" ]] || [[ ! -f "$KEY_FILE" ]]; then
    log_info "SSL certificates not found, generating self-signed certificates..."

    # Get hostname for certificate CN
    CERT_CN="${CERT_CN:-$(hostname -f 2>/dev/null || echo 'localhost')}"

    # Generate self-signed certificate valid for 365 days
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -subj "/CN=${CERT_CN}" \
        -addext "subjectAltName=DNS:${CERT_CN},DNS:localhost,IP:127.0.0.1" \
        2>/dev/null

    sudo chmod 600 "$KEY_FILE"
    sudo chmod 644 "$CERT_FILE"

    log_info "Self-signed certificates generated for CN=${CERT_CN}"
    log_warn "For production, replace with proper certificates (e.g., Cloudflare Origin Certificate)"
else
    log_info "SSL certificates already exist, skipping generation"
fi

# ==============================================================================
# Prompt for vLLM API key
# ==============================================================================
if [[ -z "${VLLM_API_KEY:-}" ]]; then
    echo ""
    read -p "Enter vLLM API key (required for /completion endpoint): " -r VLLM_API_KEY
    if [[ -z "$VLLM_API_KEY" ]]; then
        log_warn "No vLLM API key provided - /completion endpoint will not work"
    fi
fi

# ==============================================================================
# Run container
# ==============================================================================
log_info "Starting container..."

# Build environment file args if exists
ENV_ARGS=""
if [[ -f "$ENV_FILE" ]]; then
    ENV_ARGS="--env-file $ENV_FILE"
fi

# Build TDX/confidential computing args (optional - only on supported hardware)
TDX_ARGS=""
if [[ -e /dev/tdx_guest ]]; then
    TDX_ARGS="$TDX_ARGS --device /dev/tdx_guest:/dev/tdx_guest"
    log_info "TDX device detected, enabling hardware attestation"
fi
# Mount /sys/kernel/config if TSM report interface exists (for TDX attestation)
# Note: We mount the parent dir because /sys/kernel/config doesn't exist in containers
if [[ -d /sys/kernel/config/tsm/report ]]; then
    TDX_ARGS="$TDX_ARGS -v /sys/kernel/config:/sys/kernel/config:rw"
    log_info "TSM report interface detected, mounting for attestation"
elif [[ -d /sys/kernel/config/tsm ]]; then
    log_warn "TSM directory exists but report interface not found - skipping mount"
fi
if [[ -z "$TDX_ARGS" ]]; then
    log_warn "No TDX/confidential computing hardware detected - CPU attestation will be unavailable"
fi

# Build vLLM args
VLLM_ARGS=""
if [[ -n "${VLLM_API_KEY:-}" ]]; then
    VLLM_ARGS="-e VLLM_API_KEY=${VLLM_API_KEY}"
fi

$CONTAINER_RUNTIME run -d \
    --name "$CONTAINER_NAME" \
    --user root \
    --network host \
    --privileged \
    --gpus all \
    --restart unless-stopped \
    -p 443:443 \
    -e "IMAGE_DIGEST=${IMAGE_DIGEST}" \
    -e "VLLM_CONTAINER_NAME=vllm-server" \
    $VLLM_ARGS \
    $ENV_ARGS \
    $TDX_ARGS \
    -v "$CERTS_DIR:/app/certs:ro" \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    "$FULL_IMAGE" \
    python -m uvicorn main:app --host 0.0.0.0 --port 443 --ssl-keyfile /app/certs/key.pem --ssl-certfile /app/certs/cert.pem

# Wait for container to start
sleep 3

# ==============================================================================
# Health check
# ==============================================================================
log_info "Checking container health..."

if $CONTAINER_RUNTIME ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    # Verify the image digest is correctly set
    RUNTIME_DIGEST=$(curl -sk https://localhost:443/ping 2>/dev/null | grep -o '"image_digest":"[^"]*"' | cut -d'"' -f4 || echo "")

    if [[ "$RUNTIME_DIGEST" == "$IMAGE_DIGEST" ]]; then
        log_info "Container started successfully!"
        log_info "Image digest verified: ${IMAGE_DIGEST}"
    else
        log_warn "Container started but image digest mismatch"
        log_warn "Expected: ${IMAGE_DIGEST}"
        log_warn "Got: ${RUNTIME_DIGEST:-<empty>}"
    fi

    echo ""
    log_info "============================================"
    log_info "Deployment complete!"
    log_info "============================================"
    echo ""
    echo "Container: $CONTAINER_NAME"
    echo "Image: $FULL_IMAGE"
    echo "API endpoint: https://localhost:443"
    echo "Health check: curl -k https://localhost:443/ping"
    echo ""
    echo "View logs: $CONTAINER_RUNTIME logs -f $CONTAINER_NAME"
else
    log_error "Container failed to start!"
    $CONTAINER_RUNTIME logs "$CONTAINER_NAME"
    exit 1
fi
