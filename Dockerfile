# Runtime stage - Python 3.13 for CVE-2025-13836 fix
FROM python:3.13-slim

# Labels for container metadata
LABEL org.opencontainers.image.source="https://github.com/ionet-official/cc-attestation-agent-api"
LABEL org.opencontainers.image.description="Attestation Agent API for confidential computing environments"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Apply security updates (fixes CVE-2025-15467 in OpenSSL)
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd --system --no-create-home --shell /usr/sbin/nologin attestation

WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Upgrade pip to latest version
RUN pip install --no-cache-dir --upgrade pip

# Install dependencies with Python 3.13 compatible versions
# Pre-install Python 3.13 compatible versions before nv-attestation-sdk
# nv-local-gpu-verifier pins signxml==3.2.0 which requires lxml<5.0.0
# We install newer versions first and hope they're compatible
RUN pip install --no-cache-dir "lxml==6.0.0" "signxml>=4.0.0"

# Install remaining dependencies (--no-deps for nv packages to avoid signxml downgrade)
RUN pip install --no-cache-dir httpx ecdsa eth_account eth-account fastapi uvicorn pydantic pyopenssl && \
    pip install --no-cache-dir --no-deps nv-attestation-sdk nv-local-gpu-verifier && \
    pip install --no-cache-dir nvidia-ml-py pyjwt asn1 xmlschema elementpath enum-compat

# Copy application code
COPY main.py .
COPY _version.py* ./

# Set ownership to non-root user
RUN chown -R attestation:attestation /app

# Switch to non-root user
USER attestation

# Expose port (443 for HTTPS in production, 8000 for local testing)
EXPOSE 443 8000

# Health check (uses HTTP for internal check, SSL termination handled by runtime)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/ping')" || exit 1

# Default command (override with SSL options in production)
# Production: python -m uvicorn main:app --host 0.0.0.0 --port 443 --ssl-keyfile /app/certs/key.pem --ssl-certfile /app/certs/cert.pem
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
