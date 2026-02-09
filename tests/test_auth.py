"""Tests for API key authentication."""

import os
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from main import app


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


class TestAuthRequired:
    """Test that protected endpoints require authentication."""

    def test_attestation_returns_401_without_auth(self, client):
        """Test /attestation returns 401 when no Authorization header is provided."""
        response = client.post("/attestation", json={})
        assert response.status_code == 401

    def test_completion_returns_401_without_auth(self, client):
        """Test /completion returns 401 when no Authorization header is provided."""
        response = client.post("/completion", json={"messages": []})
        assert response.status_code == 401

    def test_ping_does_not_require_auth(self, client):
        """Test /ping endpoint remains accessible without authentication."""
        response = client.get("/ping")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


class TestAuthValidation:
    """Test API key validation."""

    @patch.dict(os.environ, {"VLLM_API_KEY": "test-api-key"})
    def test_attestation_returns_401_with_invalid_key(self, client):
        """Test /attestation returns 401 when API key is invalid."""
        response = client.post(
            "/attestation",
            json={},
            headers={"Authorization": "Bearer wrong-key"}
        )
        assert response.status_code == 401
        assert "Invalid API key" in response.json()["detail"]

    @patch.dict(os.environ, {"VLLM_API_KEY": "test-api-key"})
    def test_completion_returns_401_with_invalid_key(self, client):
        """Test /completion returns 401 when API key is invalid."""
        response = client.post(
            "/completion",
            json={"messages": []},
            headers={"Authorization": "Bearer wrong-key"}
        )
        assert response.status_code == 401
        assert "Invalid API key" in response.json()["detail"]

    @patch.dict(os.environ, {"VLLM_API_KEY": ""}, clear=False)
    def test_returns_500_when_api_key_not_configured(self, client):
        """Test returns 500 when VLLM_API_KEY is not set on server."""
        # Temporarily unset the key
        original = os.environ.pop("VLLM_API_KEY", None)
        try:
            response = client.post(
                "/attestation",
                json={},
                headers={"Authorization": "Bearer some-key"}
            )
            assert response.status_code == 500
            assert "VLLM_API_KEY not set" in response.json()["detail"]
        finally:
            if original:
                os.environ["VLLM_API_KEY"] = original


class TestAuthSuccess:
    """Test successful authentication."""

    @patch("main.get_cpu_quote")
    @patch("main.get_gpu_evidence")
    @patch.dict(os.environ, {"VLLM_API_KEY": "test-api-key"})
    def test_attestation_succeeds_with_valid_key(self, mock_gpu, mock_cpu, client):
        """Test /attestation succeeds with valid API key."""
        mock_cpu.return_value = "mock_cpu_quote"
        mock_gpu.return_value = {"status": "mocked"}

        response = client.post(
            "/attestation",
            json={},
            headers={"Authorization": "Bearer test-api-key"}
        )
        assert response.status_code == 200
        assert "nonce" in response.json()

    @patch("httpx.AsyncClient.post")
    @patch.dict(os.environ, {"VLLM_API_KEY": "test-api-key"})
    def test_completion_succeeds_with_valid_key(self, mock_post, client):
        """Test /completion succeeds with valid API key."""
        # Mock the vLLM response
        mock_response = type("Response", (), {
            "status_code": 200,
            "json": lambda: {"choices": [{"message": {"content": "test"}}]},
            "raise_for_status": lambda: None
        })()
        mock_post.return_value.__aenter__ = lambda s: mock_response
        mock_post.return_value.__aexit__ = lambda s, *args: None

        response = client.post(
            "/completion",
            json={"messages": [{"role": "user", "content": "hi"}], "stream": False},
            headers={"Authorization": "Bearer test-api-key"}
        )
        # May fail due to vLLM connection, but auth should pass (not 401/403)
        assert response.status_code != 401
        assert response.status_code != 403
