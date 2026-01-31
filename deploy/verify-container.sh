#!/bin/bash
if [ -z "${BASH_VERSION:-}" ]; then
    echo "ERROR: This script must be run with bash. Please run as 'bash $0' or './$0'" >&2
    exit 1
fi
#
# Container Image Verification Script
#
# This script verifies the integrity, signature, SBOM attestation, and
# scans for vulnerabilities of a container image WITHOUT deploying it.
#
# Usage: ./verify-container.sh <version> [--skip-vuln-scan]
#
# Prerequisites:
#   - Docker or Podman (for pulling image)
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
REGISTRY="${REGISTRY:-ghcr.io}"
IMAGE_NAME="${REGISTRY}/${GITHUB_ORG}/${GITHUB_REPO}"

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
    echo "  REGISTRY         Container registry (default: ghcr.io)"
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

PASSED=0
FAILED=0
SKIPPED=0

# ==============================================================================
# Get image digest from release
# ==============================================================================
log_step "Fetching image digest for version ${VERSION_TAG}..."

RELEASE_URL="https://github.com/${GITHUB_ORG}/${GITHUB_REPO}/releases/download/${VERSION_TAG}"
IMAGE_DIGEST=$(curl -fsSL "${RELEASE_URL}/image-digest.txt" 2>/dev/null | tr -d '[:space:]')

if [[ -z "$IMAGE_DIGEST" ]]; then
    log_error "Failed to fetch image digest from release"
    exit 1
fi

FULL_IMAGE="${IMAGE_NAME}@${IMAGE_DIGEST}"

echo ""
echo "=========================================="
echo "  Container Image Verification Report"
echo "=========================================="
echo ""
echo "Version: ${VERSION_TAG}"
echo "Image: ${FULL_IMAGE}"
echo "Digest: ${IMAGE_DIGEST}"
echo ""

# ==============================================================================
# Install verification tools if needed
# ==============================================================================
install_cosign() {
    log_step "Installing cosign..."
    COSIGN_VERSION="v2.2.4"
    curl -fsSL -o /tmp/cosign "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
    chmod +x /tmp/cosign
    sudo mv /tmp/cosign /usr/local/bin/
}

install_slsa_verifier() {
    log_step "Installing slsa-verifier..."
    SLSA_VERIFIER_VERSION="v2.6.0"
    curl -fsSL -o /tmp/slsa-verifier "https://github.com/slsa-framework/slsa-verifier/releases/download/${SLSA_VERIFIER_VERSION}/slsa-verifier-linux-amd64"
    chmod +x /tmp/slsa-verifier
    sudo mv /tmp/slsa-verifier /usr/local/bin/
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
# 1. Signature verification
# ==============================================================================
log_step "Verifying image signature with Sigstore..."

if cosign verify "$FULL_IMAGE" \
    --certificate-identity-regexp ".*" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    2>/dev/null; then
    log_info "Image signature verified"
    ((PASSED++))
else
    log_error "Image signature verification failed"
    ((FAILED++))
fi

# ==============================================================================
# 2. SBOM attestation verification
# ==============================================================================
log_step "Verifying SBOM attestation..."

if cosign verify-attestation "$FULL_IMAGE" \
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
# 3. SLSA provenance verification (Level 3)
# ==============================================================================
log_step "Verifying SLSA provenance..."

if slsa-verifier verify-image "$FULL_IMAGE" \
    --source-uri "github.com/${GITHUB_ORG}/${GITHUB_REPO}" \
    2>/dev/null; then
    log_info "SLSA provenance verified (Level 3)"
    ((PASSED++))
else
    log_error "SLSA provenance verification failed"
    ((FAILED++))
fi

# ==============================================================================
# 4. Vulnerability scanning
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
        log_step "Scanning image for vulnerabilities..."

        # Show all vulnerabilities
        grype "$FULL_IMAGE" --output table 2>&1 || true

        # Fail if critical vulnerabilities are found
        if ! grype "$FULL_IMAGE" --fail-on critical 2>/dev/null; then
            log_error "Critical vulnerabilities detected!"
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
    echo ""
    echo "The container image failed one or more verification checks."
    echo "Do NOT deploy this image until the issues are resolved."
    exit 1
else
    echo -e "${GREEN}VERIFICATION PASSED${NC}"
    echo ""
    echo "The container image is verified and safe to deploy."
    echo ""
    echo "To deploy:"
    echo "  ./deploy-container.sh ${VERSION_TAG}"
    exit 0
fi
