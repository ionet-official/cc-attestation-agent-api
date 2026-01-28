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

Health check endpoint.

Response:
```json
{
  "status": "ok"
}
```

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
  }
}
```

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

Environment Variables:
- `VLLM_API_KEY`: API key for authenticating with local vLLM service

**Note:** ECDSA signing keys are automatically generated on application startup. The public key is returned in the `signing_address` response header for verification.

## Local Development

```bash
pip install -r requirements-dev.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Production Deployment

This project uses a secure deployment pipeline with SBOM generation, artifact signing, and provenance attestation.

### Build Pipeline

The GitHub Actions workflow (`.github/workflows/build-and-attest.yml`) automatically:

1. **Generates locked requirements** with hashes using pip-tools
2. **Creates SBOM** in CycloneDX format
3. **Audits dependencies** for known vulnerabilities
4. **Signs artifacts** using Sigstore/cosign
5. **Creates SBOM attestation** linking the SBOM to the artifact
6. **Generates SLSA provenance** (Level 3)
7. **Publishes a GitHub Release** with all artifacts and verification instructions

### Deploying to a VM

```bash
# Set your GitHub org/repo
export GITHUB_ORG="ionet-official"
export GITHUB_REPO="cc-attestation-agent-api"

# Deploy a specific version
./deploy/deploy.sh v1.0.0
```

The deployment script:
- Downloads the artifact and all attestations
- Verifies the Sigstore signature
- Verifies the SBOM attestation
- Verifies SLSA provenance
- Scans the SBOM for vulnerabilities
- Installs the application with a systemd service

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
./deploy/verify.sh attestation-api-1.0.0.tar.gz \
  --sbom sbom.cdx.json \
  --provenance attestation-api-1.0.0.tar.gz.intoto.jsonl
```

## Dependencies

- `fastapi`, `uvicorn`: Web framework and server
- `pyopenssl`: Certificate handling
- `nv-attestation-sdk`: NVIDIA GPU attestation

## Use Case

External clients send a nonce to prove freshness. Service returns cryptographically signed quotes that clients verify against Intel/NVIDIA roots of trust. This proves the workload runs on genuine confidential hardware before sending sensitive data.

## Security

This deployment process provides:

| Verification | What It Proves |
|--------------|----------------|
| **Sigstore signature** | Artifact hasn't been tampered with since build |
| **SBOM attestation** | Exact dependencies at build time, linked to artifact |
| **SLSA provenance** | Built from specific commit, by specific workflow |
| **Vulnerability scan** | No known CVEs in dependencies at deploy time |
