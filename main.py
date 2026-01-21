import os
import uuid
import base64
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

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
