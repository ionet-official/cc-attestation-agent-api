# Remote Attestation Service

FastAPI service for remote attestation of confidential VMs with Intel TDX and NVIDIA H200 GPUs. Runs inside the confidential VM and provides cryptographic proof of hardware integrity to external verifiers.

## Hardware Requirements

- Intel CPU with TDX (Trust Domain Extensions)
- NVIDIA H200 GPUs (8x) with Confidential Computing support
- TDX-enabled confidential VM

## What It Does

Provides two main API endpoints:

1. **Remote Attestation** (`/attestation`): Generates attestation quotes from both CPU and GPU
   - **CPU**: Collects Intel TDX quote via TSM interface (`/sys/kernel/config/tsm/report`)
   - **GPU**: Collects H200 attestation reports using NVIDIA Attestation SDK
   - **Output**: Returns signed quotes with certificate chains for external verification

2. **Confidential Completion** (`/completion`): Proxies LLM inference requests with cryptographic signing
   - **Proxy**: Forwards chat completion requests to local vLLM service
   - **Signing**: Computes SHA-256 hashes of request/response and signs with ECDSA
   - **Output**: Returns vLLM response with signature headers for verification

## API

**GET** `/ping`

Health check endpoint. Returns service version and code hash for integrity verification.

Response:
```json
{
  "status": "ok",
  "version": "1.0.0",
  "code_hash": "abc123...",
  "image_digest": "sha256:def456..."
}
```

- `version`: `"dev"` when running locally without a build
- `code_hash`: SHA256 hash of deployed code files (for non-container deployments)
- `image_digest`: Container image digest (only present when running in a container)

**POST** `/attestation`

Request:
```json
{
  "nonce": "optional-hex-string"  // Optional 32-byte hex (64 chars)
}
```

Response:
```json
{
  "nonce": "used-nonce-hex",
  "cpu": {
    "quote": "hex-encoded-tdx-quote"
  },
  "gpu": {
    "arch": "HOPPER",
    "evidence_list": [
      {
        "evidence": "base64-attestation-report",
        "certificate": "base64-certificate-chain"
      }
    ]
  },
  "signing_address": "0x...",
  "code_hash": "abc123...",
  "image_digest": "sha256:def456..."
}
```

- `code_hash`: SHA256 hash of deployed code (for non-container deployments)
- `image_digest`: Container image digest - the definitive tamperproof evidence when running in a container

**POST** `/completion`

Proxy endpoint for vLLM chat completions with cryptographic signing. Forwards requests to a local vLLM service and returns signed responses.

Request:
```json
{
  "messages": [{"role": "user", "content": "Hello"}],
  "model": "optional-model-name",
  "temperature": 0.7,
  "max_tokens": 100,
  "stream": false,
  "top_p": 1.0,
  "frequency_penalty": 0.0,
  "presence_penalty": 0.0,
  "stop": null,
  "n": 1,
  "logprobs": false
}
```

Response:
- Body: Standard OpenAI-compatible chat completion response from vLLM
- Headers:
  - `text`: Signing text in format `{request_hash}:{response_hash}`
  - `signature`: ECDSA signature (hex-encoded)
  - `signing_address`: Public key used for verification
  - `signing_algo`: `ecdsa`
  - `code_hash`: SHA256 hash of deployed code for integrity verification

For streaming responses (`stream: true`), the signature is sent as a final SSE event:
```
event: signature
data: {"text": "...", "signature": "...", "signing_address": "...", "signing_algo": "ecdsa", "code_hash": "...", "image_digest": "..."}
```

When running in a container, `image_digest` is included in both headers and signature events.

Environment Variables:
- `VLLM_API_KEY`: API key for authenticating with local vLLM service

**Note:** ECDSA signing keys are automatically generated on application startup. The public key is returned in the `signing_address` response header for verification.

## Local Development

```bash
pip install -r requirements-dev.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Production Deployment

This project supports two deployment methods:
1. **Container-based (Recommended)**: Uses signed container images with digest verification
2. **Direct deployment**: Extracts Python files with integrity checksums

---

## Container Deployment (Recommended)

Container deployment provides stronger tamperproof guarantees through immutable image digests.

### Quick Install (Container)

```bash
# Download the container deploy script
curl -fsSL -o deploy.sh https://github.com/ionet-official/cc-attestation-agent-api/releases/latest/download/deploy-container.sh
chmod +x deploy.sh

# Get the latest version and deploy
VERSION=$(curl -fsSL https://api.github.com/repos/ionet-official/cc-attestation-agent-api/releases/latest | grep -oP '"tag_name": "\K[^"]+')
sudo ./deploy.sh "$VERSION"
```

### Container Build Pipeline

The GitHub Actions workflow (`.github/workflows/build-container.yml`) automatically:

1. **Builds container image** with locked dependencies
2. **Pushes to GitHub Container Registry** (ghcr.io)
3. **Signs the image** using Sigstore/cosign
4. **Generates SBOM** using Syft (CycloneDX format)
5. **Attests SBOM** linking it to the image digest
6. **Scans for vulnerabilities** using Grype
7. **Publishes release** with image digest and verification instructions

### Container Verification

```bash
IMAGE="ghcr.io/ionet-official/cc-attestation-agent-api@sha256:..."

# Verify image signature
cosign verify "$IMAGE" \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

# Verify SBOM attestation
cosign verify-attestation "$IMAGE" \
  --type cyclonedx \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

### Runtime Image Digest Verification

The container runs with `IMAGE_DIGEST` environment variable set to the signed image digest. Remote verifiers can confirm the running container matches the signed image:

```bash
# Get expected digest from release
EXPECTED=$(curl -sL https://github.com/ionet-official/cc-attestation-agent-api/releases/download/v1.0.0/image-digest.txt)

# Get runtime digest from API
ACTUAL=$(curl -s http://localhost:8000/ping | jq -r '.image_digest')

# Compare
[ "$EXPECTED" = "$ACTUAL" ] && echo "Verified" || echo "TAMPERED"
```

The `image_digest` is included in `/ping`, `/attestation`, and `/completion` responses.

### Why Container Deployment?

| Aspect | Container | Direct Deployment |
|--------|-----------|-------------------|
| **Tamperproof evidence** | Image digest (immutable) | Code hash (file-based) |
| **Modification possible** | No (image is immutable) | Yes (requires chattr -i) |
| **Verification** | Single digest check | Multiple file checksums |
| **Dependencies** | Locked in image | Locked in requirements.lock.txt |
| **Portability** | Any container runtime | Requires Python + venv |

---

## Direct Deployment

For environments without container support, direct deployment is available.

### Build Pipeline

The GitHub Actions workflow (`.github/workflows/build-and-attest.yml`) automatically:

1. **Generates locked requirements** with hashes using pip-tools
2. **Creates SBOM** in CycloneDX format
3. **Audits dependencies** for known vulnerabilities
4. **Generates code hash** for runtime integrity verification
5. **Signs artifacts** using Sigstore/cosign
6. **Creates SBOM attestation** linking the SBOM to the artifact
7. **Generates SLSA provenance** (Level 3)
8. **Publishes a GitHub Release** with all artifacts and verification instructions

### Quick Install

```bash
# Download the deploy script from the latest release
curl -fsSL -o deploy.sh https://github.com/ionet-official/cc-attestation-agent-api/releases/latest/download/deploy.sh
chmod +x deploy.sh

# Get the latest version and deploy
VERSION=$(curl -fsSL https://api.github.com/repos/ionet-official/cc-attestation-agent-api/releases/latest | grep -oP '"tag_name": "\K[^"]+')
sudo ./deploy.sh "$VERSION"
```

Or as a one-liner:

```bash
curl -fsSL https://github.com/ionet-official/cc-attestation-agent-api/releases/latest/download/deploy.sh | sudo bash -s -- $(curl -fsSL https://api.github.com/repos/ionet-official/cc-attestation-agent-api/releases/latest | grep -oP '"tag_name": "\K[^"]+')
```

### Deploying to a VM

For manual deployment or specific versions:

```bash
# Set your GitHub org/repo (optional, defaults shown)
export GITHUB_ORG="ionet-official"
export GITHUB_REPO="cc-attestation-agent-api"

# Deploy a specific version
sudo ./deploy.sh v1.0.0
```

The deployment script:
- Downloads the artifact and all attestations
- Verifies the Sigstore signature
- Verifies the SBOM attestation
- Verifies SLSA provenance
- Scans the SBOM for vulnerabilities
- Installs the application with a systemd service
- Creates integrity checksums for runtime verification
- Sets immutable attribute on critical files (`chattr +i`)

### Manual Verification

You can verify artifacts without deploying:

```bash
# Verify signature
cosign verify-blob attestation-api-1.0.0.tar.gz \
  --bundle attestation-api-1.0.0.bundle \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

# Verify SBOM attestation
cosign verify-blob-attestation attestation-api-1.0.0.tar.gz \
  --bundle attestation-api-1.0.0.sbom-attestation.bundle \
  --type cyclonedx \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

# Verify SLSA provenance
slsa-verifier verify-artifact attestation-api-1.0.0.tar.gz \
  --provenance-path attestation-api-1.0.0.tar.gz.intoto.jsonl \
  --source-uri github.com/ionet-official/cc-attestation-agent-api
```

Or use the verification script:

```bash
# Download and run verify script
curl -fsSL -o verify.sh https://github.com/ionet-official/cc-attestation-agent-api/releases/latest/download/verify.sh
chmod +x verify.sh
./verify.sh v1.0.0
```

### Runtime Integrity Verification

After deployment, the service includes protections against tampering:

**1. Immutable Files**

Critical files (`main.py`, `_version.py`) are marked immutable with `chattr +i`. Only root can modify them after removing the attribute:

```bash
# To update (requires root)
sudo chattr -i /opt/attestation-api/main.py
# ... make changes ...
sudo chattr +i /opt/attestation-api/main.py
```

**2. Pre-Start Integrity Check**

The systemd service verifies file checksums before starting. If files have been tampered with, the service fails to start:

```bash
# Check service status after tampering attempt
sudo systemctl status attestation-api
# Will show: "sha256sum: main.py: FAILED"
```

**3. Runtime Code Hash Verification**

Remote verifiers can confirm the deployed code matches the signed release:

```bash
# Get expected hash from release
curl -sL https://github.com/ionet-official/cc-attestation-agent-api/releases/download/v1.0.0/code-hash.txt

# Get runtime hash from API
curl -s http://localhost:8000/ping | jq -r '.code_hash'

# Or in one command
EXPECTED=$(curl -sL https://github.com/.../code-hash.txt)
ACTUAL=$(curl -s http://localhost:8000/ping | jq -r '.code_hash')
[ "$EXPECTED" = "$ACTUAL" ] && echo "Verified" || echo "TAMPERED"
```

The `code_hash` is also included in `/attestation` responses, allowing verifiers to confirm code integrity as part of the attestation flow.

## Dependencies

- `fastapi`, `uvicorn`: Web framework and server
- `pyopenssl`: Certificate handling
- `nv-attestation-sdk`: NVIDIA GPU attestation

## Use Case

External clients send a nonce to prove freshness. Service returns cryptographically signed quotes that clients verify against Intel/NVIDIA roots of trust. This proves the workload runs on genuine confidential hardware before sending sensitive data.

## Security

This deployment process provides:

| Verification | Container | Direct | What It Proves |
|--------------|:---------:|:------:|----------------|
| **Sigstore signature** | ✓ | ✓ | Artifact hasn't been tampered with since build |
| **SBOM attestation** | ✓ | ✓ | Exact dependencies at build time, linked to artifact |
| **SLSA provenance** | - | ✓ | Built from specific commit, by specific workflow |
| **Vulnerability scan** | ✓ | ✓ | No known CVEs in dependencies at deploy time |
| **Immutable files** | - | ✓ | Critical code files cannot be modified without root |
| **Pre-start check** | - | ✓ | Service won't start if files have been tampered with |
| **Runtime code hash** | ✓ | ✓ | Remote verifiers can confirm deployed code matches signed release |
| **Image digest** | ✓ | - | Immutable container identity - cannot be modified after build |
