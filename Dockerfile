# Runtime stage - Python 3.13 for CVE-2025-13836 fix
FROM python:3.13-slim

# Labels for container metadata
LABEL org.opencontainers.image.source="https://github.com/ionet-official/cc-attestation-agent-api"
LABEL org.opencontainers.image.description="Attestation Agent API for confidential computing environments"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Create non-root user for security
RUN useradd --system --no-create-home --shell /usr/sbin/nologin attestation

WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Single layer for all installations to minimize size:
# 1. Apply security updates (fixes CVE-2025-15467 in OpenSSL)
# 2. Install all Python dependencies
# 3. Clean up everything in one layer
RUN apt-get update && \
    apt-get upgrade -y && \
    # Pre-install Python 3.13 compatible versions
    # nv-local-gpu-verifier pins signxml==3.2.0 which requires lxml<5.0.0
    # We install newer versions first for Python 3.13 compatibility
    pip install --no-cache-dir "lxml>=5.0.0" "signxml>=4.0.0" && \
    # Install main dependencies
    pip install --no-cache-dir httpx ecdsa eth_account eth-account fastapi uvicorn pydantic pyopenssl && \
    # Install nv packages without deps to avoid signxml downgrade
    pip install --no-cache-dir --no-deps nv-attestation-sdk nv-local-gpu-verifier && \
    # Install remaining nv dependencies (requests needed by nv-attestation-sdk)
    pip install --no-cache-dir nvidia-ml-py pyjwt asn1 xmlschema elementpath enum-compat requests && \
    # Cleanup to reduce image size
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /root/.cache/pip && \
    find /usr/local -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local -type f -name "*.pyc" -delete 2>/dev/null || true

# Copy application code
COPY main.py .
COPY _version.py* ./

# Set ownership to non-root user
RUN chown -R attestation:attestation /app

# Switch to non-root user
USER attestation

# Expose port (443 for HTTPS in production, 8001 for local testing)
EXPOSE 443 8001

# Health check (uses HTTP for internal check, SSL termination handled by runtime)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/ping')" || exit 1

# Default command (override with SSL options in production)
# Production: python -m uvicorn main:app --host 0.0.0.0 --port 443 --ssl-keyfile /app/certs/key.pem --ssl-certfile /app/certs/cert.pem
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
