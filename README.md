# Remote Attestation Service

FastAPI service for remote attestation of confidential VMs with Intel TDX and NVIDIA H200 GPUs. Runs inside the confidential VM and provides cryptographic proof of hardware integrity to external verifiers.

## Hardware Requirements

- Intel CPU with TDX (Trust Domain Extensions)
- NVIDIA H200 GPUs (8x) with Confidential Computing support
- TDX-enabled confidential VM

## What It Does

Provides a single API endpoint that generates attestation quotes from both CPU and GPU:

- **CPU**: Collects Intel TDX quote via TSM interface (`/sys/kernel/config/tsm/report`)
- **GPU**: Collects H200 attestation reports using NVIDIA Attestation SDK
- **Output**: Returns signed quotes with certificate chains for external verification

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

## Installation & Usage

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Dependencies

- `fastapi`, `uvicorn`: Web framework and server
- `pyopenssl`: Certificate handling
- `nv-attestation-sdk`: NVIDIA GPU attestation

## Use Case

External clients send a nonce to prove freshness. Service returns cryptographically signed quotes that clients verify against Intel/NVIDIA roots of trust. This proves the workload runs on genuine confidential hardware before sending sensitive data.
