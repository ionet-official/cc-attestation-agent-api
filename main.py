import os
import uuid
import base64
import hashlib
import json
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
import httpx
from ecdsa import SigningKey, SECP256k1

try:
    from OpenSSL import crypto
    from verifier.cc_admin import collect_gpu_evidence
except ImportError:
    collect_gpu_evidence = None
    print("WARNING: NVIDIA Attestation SDK not found. GPU attestation will fail.")

app = FastAPI()

TSM_REPORT_PATH = "/sys/kernel/config/tsm/report"
GPU_ARCH = "HOPPER"


class AttestationRequest(BaseModel):
    nonce: Optional[str] = None


class CompletionRequest(BaseModel):
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
    """Sign a message using ECDSA with the private key."""
    private_key_bytes = bytes.fromhex(private_key_hex)
    signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    signature = signing_key.sign(message.encode())
    return signature.hex()


@app.get("/ping")
def ping():
    return {"status": "ok"}


@app.post("/attestation")
def create_attestation_quote(payload: AttestationRequest):
    try:
        nonce_32_bytes, nonce_hex = prepare_nonce(payload.nonce)
        cpu_nonce_bytes = nonce_32_bytes.ljust(64, b'\x00')

        cpu_quote_hex = get_cpu_quote(cpu_nonce_bytes)
        gpu_payload = get_gpu_evidence(nonce_hex)

        return {
            "nonce": nonce_hex,
            "cpu": {"quote": cpu_quote_hex},
            "gpu": gpu_payload
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/completion")
async def create_completion(payload: CompletionRequest):
    """Proxy endpoint with ECDSA signing for vLLM chat completions."""
    try:
        private_key = os.getenv("PRIVATE_KEY")
        public_key = os.getenv("PUBLIC_KEY")
        vllm_api_key = os.getenv("VLLM_API_KEY")

        if not private_key or not public_key or not vllm_api_key:
            raise HTTPException(
                status_code=500,
                detail="Missing required environment variables: PRIVATE_KEY, PUBLIC_KEY, or VLLM_API_KEY"
            )

        request_body = payload.model_dump(exclude_none=True)
        request_body["stream"] = False
        request_hash = compute_hash(request_body)

        vllm_url = "http://localhost:8000/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {vllm_api_key}",
            "Content-Type": "application/json"
        }

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

        return Response(
            content=json.dumps(response_body),
            media_type="application/json",
            headers={
                "text": signing_text,
                "signature": signature,
                "signing_address": public_key,
                "signing_algo": "ecdsa"
            }
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
