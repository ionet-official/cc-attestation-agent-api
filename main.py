"""
Attestation Agent API for confidential computing environments.

Provides endpoints for CPU/GPU attestation and proxied LLM completions
with ECDSA signatures for response integrity verification.
"""
try:
    from _version import __version__
except ImportError:
    __version__ = "dev"

import os
import uuid
import base64
import hashlib
import json
from pathlib import Path
from typing import Optional, Dict, Any

from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import httpx


def compute_code_hash() -> str:
    """
    Compute SHA256 hash of deployed code files for integrity verification.

    This hash can be compared against the expected hash from the signed release
    to verify that the deployed code has not been tampered with.
    """
    code_files = ["main.py", "_version.py"]
    hasher = hashlib.sha256()

    script_dir = Path(__file__).parent

    for filename in sorted(code_files):
        filepath = script_dir / filename
        if filepath.exists():
            hasher.update(f"{filename}:".encode())
            hasher.update(filepath.read_bytes())
            hasher.update(b"\n")

    return hasher.hexdigest()


# Compute code hash once at module load time
CODE_HASH = compute_code_hash()

# Image digest is set at container build time and passed via environment variable
# Format: sha256:<hex> (e.g., sha256:abc123...)
# This provides tamperproof evidence as the digest is derived from the signed container image
IMAGE_DIGEST = os.getenv("IMAGE_DIGEST", "")

try:
    from OpenSSL import crypto
    from verifier.cc_admin import collect_gpu_evidence
except ImportError:
    collect_gpu_evidence = None
    print("WARNING: NVIDIA Attestation SDK not found. GPU attestation will fail.")

app = FastAPI()

TSM_REPORT_PATH = "/sys/kernel/config/tsm/report"
GPU_ARCH = "HOPPER"

GENERATED_PRIVATE_KEY: Optional[str] = None
GENERATED_PUBLIC_KEY: Optional[str] = None


@app.on_event("startup")
def generate_keys_on_startup():
    """Generate Ethereum account with ECDSA key pair on application startup."""
    global GENERATED_PRIVATE_KEY, GENERATED_PUBLIC_KEY

    try:
        account = Account.create()

        GENERATED_PRIVATE_KEY = account.key.hex()
        GENERATED_PUBLIC_KEY = account.address

        print("=" * 60)
        print("Keys generated successfully on startup")
        print(f"Public address: {GENERATED_PUBLIC_KEY}")
        print(f"Code hash: {CODE_HASH}")
        if IMAGE_DIGEST:
            print(f"Image digest: {IMAGE_DIGEST}")
        print("=" * 60)
    except Exception as e:
        print(f"ERROR: Failed to generate keys on startup: {str(e)}")


class AttestationRequest(BaseModel):
    """Request model for attestation endpoint."""

    nonce: Optional[str] = None


class CompletionRequest(BaseModel):
    """Request model for OpenAI-compatible chat completions."""

    messages: Optional[list] = None
    model: Optional[str] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    stream: Optional[bool] = False
    top_p: Optional[float] = None
    frequency_penalty: Optional[float] = None
    presence_penalty: Optional[float] = None
    stop: Optional[Any] = None
    n: Optional[int] = None
    logprobs: Optional[bool] = None

    class Config:
        """Pydantic config to allow extra fields for forward compatibility."""

        extra = "allow"


def format_certificate_chain_to_pem(cert_chains):
    pem_parts = []
    if hasattr(cert_chains, '__dict__'):
        cert_dict = vars(cert_chains)
        for chain_key, chain_value in cert_dict.items():
            if isinstance(chain_value, list):
                for cert in chain_value:
                    if hasattr(cert, '__class__') and 'X509' in str(cert.__class__):
                        pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8')
                        pem_parts.append(pem.strip())
    return '\n'.join(pem_parts)


def prepare_nonce(nonce_input: Optional[str] = None) -> tuple[bytes, str]:
    try:
        if not nonce_input:
            nonce_bytes = os.urandom(32)
        else:
            clean_hex = nonce_input.lower().replace("0x", "")
            try:
                user_bytes = bytes.fromhex(clean_hex)
            except ValueError:
                raise ValueError("Invalid hex string provided.")

            if len(user_bytes) > 32:
                raise ValueError("Nonce too long. Maximum 32 bytes (64 hex characters) allowed.")

            nonce_bytes = user_bytes.ljust(32, b'\x00')

        nonce_hex = nonce_bytes.hex()
        return nonce_bytes, nonce_hex

    except Exception as e:
        raise Exception(f"Nonce Error: {str(e)}")


def get_cpu_quote(nonce_bytes: bytes) -> str:
    request_id = str(uuid.uuid4())
    report_dir = os.path.join(TSM_REPORT_PATH, f"report_{request_id}")

    try:
        if os.path.exists(TSM_REPORT_PATH):
            os.makedirs(report_dir, exist_ok=True)

            with open(os.path.join(report_dir, "inblob"), "wb") as f:
                f.write(nonce_bytes)

            with open(os.path.join(report_dir, "outblob"), "rb") as f:
                cpu_quote_binary = f.read()
                cpu_quote_hex = cpu_quote_binary.hex()

            os.rmdir(report_dir)
            return cpu_quote_hex
        else:
            return "Error: TDX Interface not found (/sys/kernel/config/tsm)"

    except Exception as e:
        if os.path.exists(report_dir):
            try:
                os.rmdir(report_dir)
            except OSError:
                pass
        return f"Error generating CPU quote: {str(e)}"


def get_gpu_evidence(nonce_hex: str):
    if collect_gpu_evidence is None:
        return {"error": "NVIDIA SDK not installed"}

    try:
        evidence_list = collect_gpu_evidence(
            nonce=nonce_hex,
            no_gpu_mode=False,
            ppcie_mode=False
        )

        if not evidence_list:
            return {"status": "No GPU found with CC support"}

        api_evidence_list = []
        for evidence in evidence_list:
            attestation_report = None
            certificate_chain_pem = None

            if hasattr(evidence, 'AttestationReport'):
                attestation_report = base64.b64encode(evidence.AttestationReport).decode('utf-8')

            if hasattr(evidence, 'CertificateChains'):
                pem_string = format_certificate_chain_to_pem(evidence.CertificateChains)
                certificate_chain_pem = base64.b64encode(pem_string.encode('utf-8')).decode('utf-8')

            if attestation_report and certificate_chain_pem:
                api_evidence_list.append({
                    "evidence": attestation_report,
                    "certificate": certificate_chain_pem
                })

        return {
            "nonce": nonce_hex,
            "arch": GPU_ARCH,
            "evidence_list": api_evidence_list,
            "claims_version": "3.0"
        }

    except Exception as e:
        return {"error": str(e)}


def compute_hash(data: Dict[str, Any]) -> str:
    """Compute SHA-256 hash of JSON data."""
    json_str = json.dumps(data, separators=(',', ':'))
    hash_obj = hashlib.sha256(json_str.encode())
    return hash_obj.hexdigest()


def sign_message(message: str, private_key_hex: str) -> str:
    """Sign a message using ECDSA with the private key, Ethereum-compatible."""
    private_key_bytes = bytes.fromhex(private_key_hex)
    account = Account.from_key(private_key_bytes)
    message_hash = encode_defunct(text=message)
    signed_message = account.sign_message(message_hash)
    return signed_message.signature.hex()


@app.get("/ping")
def ping():
    response = {"status": "ok", "version": __version__, "code_hash": CODE_HASH}
    if IMAGE_DIGEST:
        response["image_digest"] = IMAGE_DIGEST
    return response


@app.post("/attestation")
def create_attestation_quote(payload: AttestationRequest):
    try:
        nonce_32_bytes, nonce_hex = prepare_nonce(payload.nonce)
        cpu_nonce_bytes = nonce_32_bytes.ljust(64, b'\x00')

        cpu_quote_hex = get_cpu_quote(cpu_nonce_bytes)
        gpu_payload = get_gpu_evidence(nonce_hex)

        response = {
            "nonce": nonce_hex,
            "cpu": {"quote": cpu_quote_hex},
            "gpu": gpu_payload,
            "signing_address": GENERATED_PUBLIC_KEY,
            "code_hash": CODE_HASH
        }
        if IMAGE_DIGEST:
            response["image_digest"] = IMAGE_DIGEST
        return response

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/completion")
async def create_completion(payload: CompletionRequest):
    """Proxy endpoint with ECDSA signing for vLLM chat completions."""
    try:
        private_key = GENERATED_PRIVATE_KEY
        public_key = GENERATED_PUBLIC_KEY
        vllm_api_key = os.getenv("VLLM_API_KEY")

        if not private_key or not public_key:
            raise HTTPException(
                status_code=500,
                detail="Keys not available. Ensure keys are generated on startup or set via environment variables."
            )

        if not vllm_api_key:
            raise HTTPException(
                status_code=500,
                detail="Missing required environment variable: VLLM_API_KEY"
            )

        request_body = payload.model_dump(exclude_none=True)
        request_hash = compute_hash(request_body)

        vllm_url = "http://localhost:8000/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {vllm_api_key}",
            "Content-Type": "application/json"
        }

        # Handle streaming responses
        if payload.stream:
            async def stream_with_signature():
                accumulated_chunks = []

                async with httpx.AsyncClient() as client:
                    async with client.stream(
                        "POST",
                        vllm_url,
                        json=request_body,
                        headers=headers,
                        timeout=300.0
                    ) as response:
                        response.raise_for_status()

                        async for chunk in response.aiter_bytes():
                            # Forward chunk to client
                            yield chunk
                            # Accumulate for signature
                            accumulated_chunks.append(chunk)

                # After streaming completes, compute signature
                full_response = b"".join(accumulated_chunks).decode("utf-8")

                # Parse accumulated SSE data to reconstruct response object
                # SSE format: "data: {json}\n\n"
                response_lines = []
                for line in full_response.split("\n"):
                    if line.startswith("data: ") and not line.startswith("data: [DONE]"):
                        response_lines.append(line[6:])  # Remove "data: " prefix

                # Combine all chunks into a single response object for hashing
                response_hash = compute_hash({"chunks": response_lines})
                signing_text = f"{request_hash}:{response_hash}"
                signature = sign_message(signing_text, private_key)

                # Send signature as custom SSE event
                signature_event = {
                    "text": signing_text,
                    "signature": signature,
                    "signing_address": public_key,
                    "signing_algo": "ecdsa",
                    "code_hash": CODE_HASH
                }
                if IMAGE_DIGEST:
                    signature_event["image_digest"] = IMAGE_DIGEST
                yield f"event: signature\ndata: {json.dumps(signature_event)}\n\n".encode()

            return StreamingResponse(
                stream_with_signature(),
                media_type="text/event-stream"
            )

        # Handle non-streaming responses
        else:
            request_body["stream"] = False

            async with httpx.AsyncClient() as client:
                vllm_response = await client.post(
                    vllm_url,
                    json=request_body,
                    headers=headers,
                    timeout=300.0
                )
                vllm_response.raise_for_status()
                response_body = vllm_response.json()

            response_hash = compute_hash(response_body)
            signing_text = f"{request_hash}:{response_hash}"
            signature = sign_message(signing_text, private_key)

            response_headers = {
                "text": signing_text,
                "signature": signature,
                "signing_address": public_key,
                "signing_algo": "ecdsa",
                "code_hash": CODE_HASH
            }
            if IMAGE_DIGEST:
                response_headers["image_digest"] = IMAGE_DIGEST

            return Response(
                content=json.dumps(response_body),
                media_type="application/json",
                headers=response_headers
            )

    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"vLLM service error: {e.response.text}"
        )
    except httpx.RequestError as e:
        raise HTTPException(
            status_code=503,
            detail=f"Failed to connect to vLLM service: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
