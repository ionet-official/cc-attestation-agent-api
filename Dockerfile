# Build stage - generate locked requirements
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN pip install --no-cache-dir pip-tools

# Copy requirements and generate locked versions with hashes
COPY requirements.txt .
RUN pip-compile requirements.txt \
    --generate-hashes \
    --output-file requirements.lock.txt

# Runtime stage
FROM python:3.11-slim

# Labels for container metadata
LABEL org.opencontainers.image.source="https://github.com/ionet-official/cc-attestation-agent-api"
LABEL org.opencontainers.image.description="Attestation Agent API for confidential computing environments"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Create non-root user for security
RUN useradd --system --no-create-home --shell /usr/sbin/nologin attestation

WORKDIR /app

# Copy locked requirements from builder
COPY --from=builder /build/requirements.lock.txt .

# Install dependencies with hash verification
RUN pip install --no-cache-dir -r requirements.lock.txt

# Copy application code
COPY main.py .
COPY _version.py* ./

# Set ownership to non-root user
RUN chown -R attestation:attestation /app

# Switch to non-root user
USER attestation

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/ping')" || exit 1

# Run the application
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
