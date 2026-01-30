#!/bin/bash
if [ -z "${BASH_VERSION:-}" ]; then
    echo "ERROR: This script must be run with bash. Please run as 'bash $0' or './$0'" >&2
    exit 1
fi
#
# Attestation API Deployment Script
#
# This script downloads, verifies, and deploys the attestation API
# with full provenance and SBOM verification.
#
# Usage: ./deploy.sh <version> [--skip-vuln-scan]
#
# Prerequisites:
#   - curl, tar, python3, python3-venv
#   - cosign (will be installed if missing)
#   - slsa-verifier (will be installed if missing)
#   - grype (optional, for vulnerability scanning)
#
set -e
set -u
if [ -n "${BASH_VERSION:-}" ]; then
    set -o pipefail
fi

# Configuration - UPDATE THESE FOR YOUR ENVIRONMENT
GITHUB_ORG="${GITHUB_ORG:-ionet-official}"
GITHUB_REPO="${GITHUB_REPO:-cc-attestation-agent-api}"
DEPLOY_DIR="${DEPLOY_DIR:-/opt/ionet/cc-attestation-agent-api}"
SERVICE_USER="${SERVICE_USER:-root}"
SERVICE_GROUP="${SERVICE_GROUP:-root}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}==>${NC} $1"; }
log_warn() { echo -e "${YELLOW}==> WARNING:${NC} $1"; }
log_error() { echo -e "${RED}==> ERROR:${NC} $1" >&2; }

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
    echo "  DEPLOY_DIR       Deployment directory (default: /opt/ionet/cc-attestation-agent-api)"
    echo "  SERVICE_USER     User to run the service (default: root)"
    echo "  SERVICE_GROUP    Group for the service (default: root)"
    exit 1
fi

for arg in "$@"; do
    if [[ "$arg" == "--skip-vuln-scan" ]]; then
        SKIP_VULN_SCAN=true
    fi
done

# Normalize version (ensure v prefix)
VERSION="${VERSION#v}"
VERSION_TAG="v${VERSION}"

# URLs
BASE_URL="https://github.com/${GITHUB_ORG}/${GITHUB_REPO}/releases/download/${VERSION_TAG}"
ARTIFACT_NAME="attestation-api-${VERSION}"

# Create temporary working directory
WORK_DIR=$(mktemp -d)
cleanup() {
    log_info "Cleaning up temporary files..."
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

cd "$WORK_DIR"

# ==============================================================================
# Download artifacts
# ==============================================================================
log_info "Downloading artifacts for version ${VERSION_TAG}..."

download_file() {
    local url="$1"
    local output="$2"
    if ! curl -fsSL -o "$output" "$url"; then
        log_error "Failed to download: $url"
        return 1
    fi
    log_info "Downloaded: $output"
}

download_file "${BASE_URL}/${ARTIFACT_NAME}.tar.gz" "app.tar.gz"
download_file "${BASE_URL}/${ARTIFACT_NAME}.bundle" "app.bundle"
download_file "${BASE_URL}/${ARTIFACT_NAME}.sbom-attestation.bundle" "sbom-attestation.bundle"
download_file "${BASE_URL}/checksums.sha256" "checksums.sha256"
download_file "${BASE_URL}/sbom.cdx.json" "sbom.cdx.json"
download_file "${BASE_URL}/code-hash.txt" "code-hash.txt"

if ! download_file "${BASE_URL}/${ARTIFACT_NAME}.tar.gz.intoto.jsonl" "provenance.intoto.jsonl" 2>/dev/null; then
    log_warn "SLSA provenance file not found, skipping provenance verification"
    SKIP_PROVENANCE=true
else
    SKIP_PROVENANCE=false
fi

# ==============================================================================
# Verify checksum
# ==============================================================================
log_info "Verifying SHA256 checksum..."

# Extract expected hash for our file
EXPECTED_HASH=$(grep "${ARTIFACT_NAME}.tar.gz" checksums.sha256 | awk '{print $1}')
ACTUAL_HASH=$(sha256sum app.tar.gz | awk '{print $1}')

if [[ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]]; then
    log_error "Checksum verification failed!"
    log_error "Expected: $EXPECTED_HASH"
    log_error "Actual:   $ACTUAL_HASH"
    exit 1
fi
log_info "Checksum verified successfully"

# ==============================================================================
# Install verification tools if needed
# ==============================================================================
install_cosign() {
    log_info "Installing cosign..."
    COSIGN_VERSION="v2.2.4"
    curl -fsSL -o cosign "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
    chmod +x cosign
    sudo mv cosign /usr/local/bin/
}

SLSA_VERSION="v2.7.1"

install_slsa_verifier() {
    log_info "Installing slsa-verifier ${SLSA_VERSION}..."
    curl -fsSL -o slsa-verifier "https://github.com/slsa-framework/slsa-verifier/releases/download/${SLSA_VERSION}/slsa-verifier-linux-amd64"
    chmod +x slsa-verifier
    sudo mv slsa-verifier /usr/local/bin/
}

install_grype() {
    log_info "Installing grype..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
}

if ! command -v cosign &> /dev/null; then
    install_cosign
fi

if command -v slsa-verifier &> /dev/null; then
    CURRENT_SLSA_VERSION=$(slsa-verifier version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "0.0.0")
    REQUIRED_SLSA_VERSION="${SLSA_VERSION#v}"
    if [[ "$(printf '%s\n' "$REQUIRED_SLSA_VERSION" "$CURRENT_SLSA_VERSION" | sort -V | head -1)" != "$REQUIRED_SLSA_VERSION" ]]; then
        log_info "Upgrading slsa-verifier from v${CURRENT_SLSA_VERSION} to ${SLSA_VERSION}..."
        install_slsa_verifier
    fi
else
    install_slsa_verifier
fi

# ==============================================================================
# Verify Sigstore signature
# ==============================================================================
log_info "Verifying artifact signature with Sigstore..."

cosign verify-blob app.tar.gz \
    --bundle app.bundle \
    --certificate-identity-regexp ".*" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    || { log_error "Signature verification failed!"; exit 1; }

log_info "Artifact signature verified successfully"

# ==============================================================================
# Verify SBOM attestation
# ==============================================================================
log_info "Verifying SBOM attestation..."

cosign verify-blob-attestation app.tar.gz \
    --bundle sbom-attestation.bundle \
    --type cyclonedx \
    --certificate-identity-regexp ".*" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    || { log_error "SBOM attestation verification failed!"; exit 1; }

log_info "SBOM attestation verified successfully"

# ==============================================================================
# Verify SLSA provenance
# ==============================================================================
if [[ "$SKIP_PROVENANCE" != "true" ]]; then
    log_info "Verifying SLSA provenance..."

    slsa-verifier verify-artifact app.tar.gz \
        --provenance-path provenance.intoto.jsonl \
        --source-uri "github.com/${GITHUB_ORG}/${GITHUB_REPO}" \
        || { log_error "SLSA provenance verification failed!"; exit 1; }

    log_info "SLSA provenance verified successfully"
else
    log_warn "Skipping SLSA provenance verification"
fi

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
        log_info "Scanning SBOM for vulnerabilities..."

        # Scan and fail on critical vulnerabilities only
        if ! grype sbom:sbom.cdx.json --fail-on critical; then
            log_error "Critical vulnerabilities detected!"
            log_error "Review the vulnerabilities above and decide whether to proceed."
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
# Create service user if needed
# ==============================================================================
if ! id "$SERVICE_USER" &>/dev/null; then
    log_info "Creating service user: $SERVICE_USER"
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# ==============================================================================
# Deploy application
# ==============================================================================
log_info "Deploying to ${DEPLOY_DIR}..."

# Backup existing deployment if present
if [[ -d "$DEPLOY_DIR" ]]; then
    BACKUP_DIR="${DEPLOY_DIR}.backup.$(date +%Y%m%d%H%M%S)"
    log_info "Backing up existing deployment to ${BACKUP_DIR}"

    # Remove immutable attribute from files before backup (if set)
    for file in main.py _version.py; do
        if [[ -f "$DEPLOY_DIR/$file" ]]; then
            sudo chattr -i "$DEPLOY_DIR/$file" 2>/dev/null || true
        fi
    done

    sudo mv "$DEPLOY_DIR" "$BACKUP_DIR"
fi

# Create deployment directory
sudo mkdir -p "$DEPLOY_DIR"

# Extract application
sudo tar -xzf app.tar.gz -C "$DEPLOY_DIR"

# Copy SBOM and code hash for reference
sudo cp sbom.cdx.json "$DEPLOY_DIR/"
sudo cp code-hash.txt "$DEPLOY_DIR/"

# Set ownership
sudo chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "$DEPLOY_DIR"

# ==============================================================================
# Create integrity checksums for runtime verification
# ==============================================================================
log_info "Creating integrity checksums..."

# Generate checksums for critical files (used by systemd pre-start check)
cd "$DEPLOY_DIR"
sudo sha256sum main.py _version.py > .integrity-checksums
sudo chown root:root .integrity-checksums
sudo chmod 444 .integrity-checksums

log_info "Integrity checksums saved to ${DEPLOY_DIR}/.integrity-checksums"

# ==============================================================================
# Set up Python virtual environment
# ==============================================================================
log_info "Setting up Python virtual environment..."

cd "$DEPLOY_DIR"
sudo -u "$SERVICE_USER" python3 -m venv venv
sudo -u "$SERVICE_USER" ./venv/bin/pip install --upgrade pip
sudo -u "$SERVICE_USER" ./venv/bin/pip install -r requirements.lock.txt

# ==============================================================================
# Set immutable attribute on critical files
# ==============================================================================
log_info "Setting immutable attribute on critical files..."

# Make critical files immutable to prevent tampering
# Only root can remove this attribute with chattr -i
for file in main.py _version.py; do
    sudo chattr +i "$DEPLOY_DIR/$file"
done

log_info "Files protected: main.py, _version.py (use 'sudo chattr -i' to modify)"

# ==============================================================================
# Install/update systemd service
# ==============================================================================
log_info "Installing systemd service..."

sudo cp /dev/stdin /etc/systemd/system/cc-attestation.service << EOF
[Unit]
Description=FastAPI Confidential Computing Attestation Service
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${DEPLOY_DIR}

# Verify file integrity before starting - fails if files have been tampered with
ExecStartPre=/bin/bash -c 'cd ${DEPLOY_DIR} && sha256sum -c .integrity-checksums'

ExecStart=/bin/bash -c 'export VLLM_API_KEY=\${VLLM_API_KEY:-dummy_key}; ${DEPLOY_DIR}/venv/bin/uvicorn main:app --host 0.0.0.0 --port 443 --ssl-keyfile certs/key.pem --ssl-certfile certs/cert.pem'
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=-/etc/default/cc-attestation

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/sys/kernel/config/tsm ${DEPLOY_DIR}

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable cc-attestation.service

# ==============================================================================
# Start/restart service
# ==============================================================================
log_info "Starting cc-attestation service..."

sudo systemctl restart cc-attestation.service

# Wait a moment and check status
sleep 2

if sudo systemctl is-active --quiet cc-attestation.service; then
    log_info "Service started successfully!"
    echo ""
    log_info "============================================"
    log_info "Deployment complete!"
    log_info "============================================"
    echo ""
    echo "Service status:"
    sudo systemctl status cc-attestation.service --no-pager
    echo ""
    echo "API endpoint: https://localhost:443"
    echo "Health check: curl -k https://localhost:443/ping"
else
    log_error "Service failed to start!"
    sudo systemctl status cc-attestation.service --no-pager
    exit 1
fi
