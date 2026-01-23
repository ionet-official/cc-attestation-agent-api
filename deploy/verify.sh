#!/bin/bash
#
# Attestation API Artifact Verification Script
#
# This script verifies the integrity, signature, and provenance of
# a downloaded artifact WITHOUT deploying it.
#
# Usage: ./verify.sh <artifact.tar.gz> [options]
#
# Options:
#   --bundle <path>       Path to signature bundle (default: <artifact>.bundle)
#   --sbom-bundle <path>  Path to SBOM attestation bundle
#   --provenance <path>   Path to SLSA provenance file
#   --sbom <path>         Path to SBOM file for vulnerability scanning
#   --source-uri <uri>    GitHub source URI for provenance verification
#

set -euo pipefail

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

# Default values
ARTIFACT=""
BUNDLE=""
SBOM_BUNDLE=""
PROVENANCE=""
SBOM=""
SOURCE_URI=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --bundle)
            BUNDLE="$2"
            shift 2
            ;;
        --sbom-bundle)
            SBOM_BUNDLE="$2"
            shift 2
            ;;
        --provenance)
            PROVENANCE="$2"
            shift 2
            ;;
        --sbom)
            SBOM="$2"
            shift 2
            ;;
        --source-uri)
            SOURCE_URI="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 <artifact.tar.gz> [options]"
            echo ""
            echo "Options:"
            echo "  --bundle <path>       Path to signature bundle"
            echo "  --sbom-bundle <path>  Path to SBOM attestation bundle"
            echo "  --provenance <path>   Path to SLSA provenance file"
            echo "  --sbom <path>         Path to SBOM file"
            echo "  --source-uri <uri>    GitHub source URI"
            exit 0
            ;;
        *)
            if [[ -z "$ARTIFACT" ]]; then
                ARTIFACT="$1"
            else
                echo "Unknown argument: $1"
                exit 1
            fi
            shift
            ;;
    esac
done

if [[ -z "$ARTIFACT" ]]; then
    echo "Error: No artifact specified"
    echo "Usage: $0 <artifact.tar.gz> [options]"
    exit 1
fi

if [[ ! -f "$ARTIFACT" ]]; then
    echo "Error: Artifact not found: $ARTIFACT"
    exit 1
fi

# Derive default paths if not specified
ARTIFACT_BASE="${ARTIFACT%.tar.gz}"
[[ -z "$BUNDLE" ]] && BUNDLE="${ARTIFACT_BASE}.bundle"
[[ -z "$SBOM_BUNDLE" ]] && SBOM_BUNDLE="${ARTIFACT_BASE}.sbom-attestation.bundle"

echo ""
echo "=========================================="
echo "  Artifact Verification Report"
echo "=========================================="
echo ""
echo "Artifact: $ARTIFACT"
echo ""

PASSED=0
FAILED=0
SKIPPED=0

# ==============================================================================
# 1. Checksum verification
# ==============================================================================
log_step "Calculating SHA256 checksum..."
CHECKSUM=$(sha256sum "$ARTIFACT" | awk '{print $1}')
echo "  SHA256: $CHECKSUM"
log_info "Checksum calculated"
((PASSED++))

# ==============================================================================
# 2. Signature verification
# ==============================================================================
if [[ -f "$BUNDLE" ]]; then
    log_step "Verifying Sigstore signature..."

    if cosign verify-blob "$ARTIFACT" \
        --bundle "$BUNDLE" \
        --certificate-identity-regexp ".*" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        2>/dev/null; then
        log_info "Sigstore signature verified"
        ((PASSED++))
    else
        log_error "Sigstore signature verification failed"
        ((FAILED++))
    fi
else
    log_warn "Signature bundle not found: $BUNDLE"
    ((SKIPPED++))
fi

# ==============================================================================
# 3. SBOM attestation verification
# ==============================================================================
if [[ -f "$SBOM_BUNDLE" ]]; then
    log_step "Verifying SBOM attestation..."

    if cosign verify-blob-attestation "$ARTIFACT" \
        --bundle "$SBOM_BUNDLE" \
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
else
    log_warn "SBOM attestation bundle not found: $SBOM_BUNDLE"
    ((SKIPPED++))
fi

# ==============================================================================
# 4. SLSA provenance verification
# ==============================================================================
if [[ -n "$PROVENANCE" && -f "$PROVENANCE" ]]; then
    log_step "Verifying SLSA provenance..."

    SLSA_ARGS=("verify-artifact" "$ARTIFACT" "--provenance-path" "$PROVENANCE")
    if [[ -n "$SOURCE_URI" ]]; then
        SLSA_ARGS+=("--source-uri" "$SOURCE_URI")
    fi

    if slsa-verifier "${SLSA_ARGS[@]}" 2>/dev/null; then
        log_info "SLSA provenance verified"
        ((PASSED++))
    else
        log_error "SLSA provenance verification failed"
        ((FAILED++))
    fi
else
    log_warn "SLSA provenance not provided or not found"
    ((SKIPPED++))
fi

# ==============================================================================
# 5. Vulnerability scanning
# ==============================================================================
if [[ -n "$SBOM" && -f "$SBOM" ]]; then
    if command -v grype &> /dev/null; then
        log_step "Scanning SBOM for vulnerabilities..."

        VULN_OUTPUT=$(grype sbom:"$SBOM" --output table 2>&1) || true

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
        log_warn "grype not installed, skipping vulnerability scan"
        ((SKIPPED++))
    fi
elif [[ -n "$SBOM" ]]; then
    log_warn "SBOM file not found: $SBOM"
    ((SKIPPED++))
else
    log_warn "No SBOM provided for vulnerability scanning"
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
