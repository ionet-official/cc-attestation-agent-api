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
from typing import Optional, Dict, Any

from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import httpx


# Image digest is set at container build time and passed via environment variable
# Format: sha256:<hex> (e.g., sha256:abc123...)
# This provides tamperproof evidence as the digest is derived from the signed container image
IMAGE_DIGEST = os.getenv("IMAGE_DIGEST", "")

# vLLM provenance - queried directly from container runtime on startup
VLLM_PROVENANCE: Optional[Dict[str, Any]] = None


def query_vllm_container_digest(container_name: str = "vllm-server") -> Optional[str]:
    """
    Query Docker/Podman socket directly to get the image digest of vLLM container.
    This cannot be spoofed via environment variables.
    """
    import socket
    import urllib.parse

    docker_socket = os.getenv("DOCKER_SOCKET", "/var/run/docker.sock")

    if not os.path.exists(docker_socket):
        print(f"WARNING: Docker socket not found at {docker_socket}")
        return None

    try:
        # Connect to Docker socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(docker_socket)

        # Request container info (use HTTP/1.0 to avoid chunked encoding)
        request = f"GET /containers/{container_name}/json HTTP/1.0\r\nHost: localhost\r\n\r\n"
        sock.send(request.encode())

        # Read entire response
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        sock.close()

        # Parse response
        response_str = response.decode()
        if "200 OK" not in response_str:
            print(f"WARNING: Container {container_name} not found")
            return None

        # Extract JSON body
        json_start = response_str.find("{")
        if json_start == -1:
            return None

        container_info = json.loads(response_str[json_start:])

        # Get image digest - this is the actual digest, not spoofable
        image = container_info.get("Image", "")  # Local image ID

        # Get the repo digest from image inspection
        image_id = container_info.get("Image", "")

        # Query the image to get RepoDigests (use HTTP/1.0 to avoid chunked encoding)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(docker_socket)
        request = f"GET /images/{image_id}/json HTTP/1.0\r\nHost: localhost\r\n\r\n"
        sock.send(request.encode())

        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()

        response_str = response.decode()
        json_start = response_str.find("{")
        if json_start != -1:
            image_info = json.loads(response_str[json_start:])
            repo_digests = image_info.get("RepoDigests", [])
            if repo_digests:
                # Extract sha256:... from full reference
                for digest in repo_digests:
                    if "@sha256:" in digest:
                        return "sha256:" + digest.split("@sha256:")[1]
                    elif "sha256:" in digest:
                        return digest

        # Fallback to image ID if no repo digest
        return image_id if image_id.startswith("sha256:") else None

    except Exception as e:
        print(f"WARNING: Failed to query container runtime: {e}")
        return None


def query_vllm_models() -> Optional[Dict[str, Any]]:
    """Query vLLM /v1/models endpoint to get loaded model information."""
    import urllib.request
    import urllib.error

    vllm_url = os.getenv("VLLM_URL", "http://localhost:8001")
    vllm_api_key = os.getenv("VLLM_API_KEY", "")

    try:
        req = urllib.request.Request(f"{vllm_url}/v1/models")
        if vllm_api_key:
            req.add_header("Authorization", f"Bearer {vllm_api_key}")
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            return data
    except Exception as e:
        print(f"WARNING: Failed to query vLLM models: {e}")
        return None


def collect_vllm_provenance(
    max_retries: int = 3,
    retry_interval: int = 30
) -> Optional[Dict[str, Any]]:
    """
    Collect vLLM provenance information from container runtime and vLLM API.

    Retries up to max_retries times with retry_interval seconds between attempts.
    Returns None only if all retries are exhausted.
    """
    import time

    container_name = os.getenv("VLLM_CONTAINER_NAME", "vllm-server")

    for attempt in range(1, max_retries + 1):
        print(f"Collecting vLLM provenance (attempt {attempt}/{max_retries})...")
        provenance = {}

        # Get container image digest directly from Docker
        image_digest = query_vllm_container_digest(container_name)
        if image_digest:
            provenance["image_digest"] = image_digest

        # Get model info from vLLM API
        models_info = query_vllm_models()
        if models_info and "data" in models_info:
            models = models_info["data"]
            if models:
                model = models[0]  # Primary model
                provenance["model_id"] = model.get("id", "")
                provenance["model_owned_by"] = model.get("owned_by", "")

        # Check if we got both container digest and model info
        if provenance.get("image_digest") and provenance.get("model_id"):
            print(f"vLLM provenance collected successfully on attempt {attempt}")
            return provenance

        # Log what's missing
        if not provenance.get("image_digest"):
            print(f"WARNING: Could not get vLLM container digest (container '{container_name}' not found?)")
        if not provenance.get("model_id"):
            print(f"WARNING: Could not get vLLM model info (vLLM API not responding?)")

        if attempt < max_retries:
            print(f"Retrying in {retry_interval} seconds...")
            time.sleep(retry_interval)

    return None

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
    global GENERATED_PRIVATE_KEY, GENERATED_PUBLIC_KEY, VLLM_PROVENANCE

    try:
        account = Account.create()

        GENERATED_PRIVATE_KEY = account.key.hex()
        GENERATED_PUBLIC_KEY = account.address

        print("=" * 60)
        print("Keys generated successfully on startup")
        print(f"Public address: {GENERATED_PUBLIC_KEY}")
        if IMAGE_DIGEST:
            print(f"Image digest: {IMAGE_DIGEST}")

        # Collect vLLM provenance directly from container runtime
        # Retries 3 times at 30 second intervals
        # Skip in development/testing mode
        skip_vllm_check = os.getenv("SKIP_VLLM_PROVENANCE", "").lower() in ("1", "true", "yes")

        if skip_vllm_check:
            print("SKIP_VLLM_PROVENANCE is set - skipping vLLM provenance collection")
            VLLM_PROVENANCE = None
        else:
            VLLM_PROVENANCE = collect_vllm_provenance(max_retries=3, retry_interval=30)

        if skip_vllm_check:
            print("=" * 60)
            print("WARNING: Running without vLLM provenance (development mode)")
            print("=" * 60)
        elif VLLM_PROVENANCE:
            print("=" * 60)
            print("vLLM provenance collected successfully")
            print(f"vLLM image digest: {VLLM_PROVENANCE.get('image_digest', 'N/A')}")
            print(f"vLLM model: {VLLM_PROVENANCE.get('model_id', 'N/A')}")
            print("=" * 60)
        else:
            print("=" * 60)
            print("ERROR: Failed to collect vLLM provenance after 3 attempts")
            print("")
            print("Please ensure:")
            print("  1. vLLM container 'vllm-server' is running")
            print("  2. Docker socket is mounted (-v /var/run/docker.sock:/var/run/docker.sock:ro)")
            print("  3. vLLM API is accessible at http://localhost:8001")
            print("")
            print("The attestation API cannot start without vLLM provenance.")
            print("=" * 60)
            import sys
            sys.exit(1)

    except Exception as e:
        print(f"ERROR: Failed during startup: {str(e)}")
        import sys
        sys.exit(1)


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
    response = {"status": "ok", "version": __version__}
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
            "signing_address": GENERATED_PUBLIC_KEY
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

        vllm_url = "http://localhost:8001/v1/chat/completions"
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
                    "signing_algo": "ecdsa"
                }
                if IMAGE_DIGEST:
                    signature_event["image_digest"] = IMAGE_DIGEST
                if VLLM_PROVENANCE:
                    signature_event["vllm"] = VLLM_PROVENANCE
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
                "signing_algo": "ecdsa"
            }
            if IMAGE_DIGEST:
                response_headers["image_digest"] = IMAGE_DIGEST
            if VLLM_PROVENANCE:
                response_headers["vllm_image_digest"] = VLLM_PROVENANCE.get("image_digest", "")
                response_headers["vllm_model_id"] = VLLM_PROVENANCE.get("model_id", "")

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
