#!/bin/bash
if [ -z "${BASH_VERSION:-}" ]; then
    echo "ERROR: This script must be run with bash. Please run as 'bash $0' or './$0'" >&2
    exit 1
fi
#
# Attestation API Artifact Verification Script
#
# This script downloads and verifies the integrity, signature, and provenance of
# release artifacts WITHOUT deploying them.
#
# Usage: ./verify.sh <version> [--skip-vuln-scan]
#
# Prerequisites:
#   - curl
#   - cosign (will be installed if missing)
#   - slsa-verifier (will be installed if missing)
#   - grype (optional, for vulnerability scanning)
#

set -e
set -u
if [ -n "${BASH_VERSION:-}" ]; then
    set -o pipefail
fi

GITHUB_ORG="${GITHUB_ORG:-ionet-official}"
GITHUB_REPO="${GITHUB_REPO:-cc-attestation-agent-api}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_step() { echo -e "${BLUE}[....] $1${NC}"; }

# Parse arguments
VERSION="${1:-}"
SKIP_VULN_SCAN=false

if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version> [--skip-vuln-scan]"
    echo ""
    echo "Arguments:"
    echo "  version          Version to verify (e.g., v1.0.0 or 1.0.0)"
    echo "  --skip-vuln-scan Skip vulnerability scanning"
    echo ""
    echo "Environment variables:"
    echo "  GITHUB_ORG       GitHub organization (default: ionet-official)"
    echo "  GITHUB_REPO      GitHub repository (default: cc-attestation-agent-api)"
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
    log_step "Cleaning up temporary files..."
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

cd "$WORK_DIR"

# ==============================================================================
# Download artifacts
# ==============================================================================
log_step "Downloading artifacts for version ${VERSION_TAG}..."

download_file() {
    local url="$1"
    local output="$2"
    if ! curl -fsSL -o "$output" "$url"; then
        log_error "Failed to download: $url"
        return 1
    fi
    echo "  Downloaded: $output"
}

download_file "${BASE_URL}/${ARTIFACT_NAME}.tar.gz" "app.tar.gz"
download_file "${BASE_URL}/${ARTIFACT_NAME}.bundle" "app.bundle"
download_file "${BASE_URL}/${ARTIFACT_NAME}.sbom-attestation.bundle" "sbom-attestation.bundle"
download_file "${BASE_URL}/checksums.sha256" "checksums.sha256"
download_file "${BASE_URL}/sbom.cdx.json" "sbom.cdx.json"

if ! download_file "${BASE_URL}/${ARTIFACT_NAME}.tar.gz.intoto.jsonl" "provenance.intoto.jsonl" 2>/dev/null; then
    log_warn "SLSA provenance file not found, skipping provenance verification"
    SKIP_PROVENANCE=true
else
    SKIP_PROVENANCE=false
fi

echo ""
echo "=========================================="
echo "  Artifact Verification Report"
echo "=========================================="
echo ""
echo "Version: ${VERSION_TAG}"
echo "Artifact: ${ARTIFACT_NAME}.tar.gz"
echo ""

PASSED=0
FAILED=0
SKIPPED=0

# ==============================================================================
# Install verification tools if needed
# ==============================================================================
install_cosign() {
    log_step "Installing cosign..."
    COSIGN_VERSION="v2.2.4"
    curl -fsSL -o cosign "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
    chmod +x cosign
    sudo mv cosign /usr/local/bin/
}

install_slsa_verifier() {
    log_step "Installing slsa-verifier..."
    SLSA_VERSION="v2.5.1"
    curl -fsSL -o slsa-verifier "https://github.com/slsa-framework/slsa-verifier/releases/download/${SLSA_VERSION}/slsa-verifier-linux-amd64"
    chmod +x slsa-verifier
    sudo mv slsa-verifier /usr/local/bin/
}

install_grype() {
    log_step "Installing grype..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
}

if ! command -v cosign &> /dev/null; then
    install_cosign
fi

if ! command -v slsa-verifier &> /dev/null; then
    install_slsa_verifier
fi

# ==============================================================================
# 1. Checksum verification
# ==============================================================================
log_step "Verifying SHA256 checksum..."

EXPECTED_HASH=$(grep "${ARTIFACT_NAME}.tar.gz" checksums.sha256 | awk '{print $1}')
ACTUAL_HASH=$(sha256sum app.tar.gz | awk '{print $1}')

if [[ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]]; then
    log_error "Checksum verification failed!"
    echo "  Expected: $EXPECTED_HASH"
    echo "  Actual:   $ACTUAL_HASH"
    ((FAILED++))
else
    echo "  SHA256: $ACTUAL_HASH"
    log_info "Checksum verified"
    ((PASSED++))
fi

# ==============================================================================
# 2. Signature verification
# ==============================================================================
log_step "Verifying Sigstore signature..."

if cosign verify-blob app.tar.gz \
    --bundle app.bundle \
    --certificate-identity-regexp ".*" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    2>/dev/null; then
    log_info "Sigstore signature verified"
    ((PASSED++))
else
    log_error "Sigstore signature verification failed"
    ((FAILED++))
fi

# ==============================================================================
# 3. SBOM attestation verification
# ==============================================================================
log_step "Verifying SBOM attestation..."

if cosign verify-blob-attestation app.tar.gz \
    --bundle sbom-attestation.bundle \
    --type cyclonedx \
    --certificate-identity-regexp ".*" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    2>/dev/null; then
    log_info "SBOM attestation verified"
    ((PASSED++))
else
    log_error "SBOM attestation verification failed"
    ((FAILED++))
fi

# ==============================================================================
# 4. SLSA provenance verification
# ==============================================================================
if [[ "$SKIP_PROVENANCE" != "true" ]]; then
    log_step "Verifying SLSA provenance..."

    if slsa-verifier verify-artifact app.tar.gz \
        --provenance-path provenance.intoto.jsonl \
        --source-uri "github.com/${GITHUB_ORG}/${GITHUB_REPO}" \
        2>/dev/null; then
        log_info "SLSA provenance verified"
        ((PASSED++))
    else
        log_error "SLSA provenance verification failed"
        ((FAILED++))
    fi
else
    log_warn "SLSA provenance not available, skipping"
    ((SKIPPED++))
fi

# ==============================================================================
# 5. Vulnerability scanning
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
        log_step "Scanning SBOM for vulnerabilities..."

        VULN_OUTPUT=$(grype sbom:sbom.cdx.json --output table 2>&1) || true

        # Check for critical vulnerabilities only
        if echo "$VULN_OUTPUT" | grep -qE "Critical"; then
            log_error "Critical vulnerabilities found:"
            echo "$VULN_OUTPUT" | grep -E "Critical" | head -10
            ((FAILED++))
        else
            log_info "No critical vulnerabilities found"
            ((PASSED++))
        fi
    else
        ((SKIPPED++))
    fi
else
    log_warn "Skipping vulnerability scan (--skip-vuln-scan)"
    ((SKIPPED++))
fi

# ==============================================================================
# Summary
# ==============================================================================
echo ""
echo "=========================================="
echo "  Verification Summary"
echo "=========================================="
echo ""
echo -e "  ${GREEN}Passed:${NC}  $PASSED"
echo -e "  ${RED}Failed:${NC}  $FAILED"
echo -e "  ${YELLOW}Skipped:${NC} $SKIPPED"
echo ""

if [[ $FAILED -gt 0 ]]; then
    echo -e "${RED}VERIFICATION FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}VERIFICATION PASSED${NC}"
    exit 0
fi
