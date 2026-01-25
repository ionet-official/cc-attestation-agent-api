import os
import json
import hashlib
from unittest.mock import patch, AsyncMock
import pytest
from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse
from ecdsa import VerifyingKey, SECP256k1

from main import app, compute_hash, sign_message


@pytest.fixture
def test_keys():
    """Generate test ECDSA key pair."""
    from ecdsa import SigningKey, SECP256k1

    private_key_obj = SigningKey.generate(curve=SECP256k1)
    public_key_obj = private_key_obj.get_verifying_key()

    return {
        "private_key": private_key_obj.to_string().hex(),
        "public_key": public_key_obj.to_string().hex()
    }


@pytest.fixture
def mock_env(test_keys, monkeypatch):
    """Set up test environment variables."""
    monkeypatch.setenv("PRIVATE_KEY", test_keys["private_key"])
    monkeypatch.setenv("PUBLIC_KEY", test_keys["public_key"])
    monkeypatch.setenv("VLLM_API_KEY", "test-api-key")


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def sample_request():
    """Sample OpenAI-compatible request."""
    return {
        "messages": [
            {"role": "user", "content": "Hello, world!"}
        ],
        "model": "test-model",
        "temperature": 0.7,
        "max_tokens": 100
    }


@pytest.fixture
def sample_vllm_response():
    """Sample vLLM response."""
    return {
        "id": "chatcmpl-123",
        "object": "chat.completion",
        "created": 1234567890,
        "model": "test-model",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Hello! How can I help you today?"
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 20,
            "total_tokens": 30
        }
    }


class TestCompletionEndpoint:
    """Tests for POST /completion endpoint."""

    def test_ping(self, client):
        """Test ping endpoint."""
        response = client.get("/ping")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    @patch("httpx.AsyncClient")
    def test_completion_success(
        self, mock_client_class, client, mock_env, sample_request, sample_vllm_response, test_keys
    ):
        """Test successful completion with signature verification."""
        from httpx import Request

        mock_request = Request("POST", "http://localhost:8000/v1/chat/completions")
        mock_response = HttpxResponse(
            status_code=200,
            json=sample_vllm_response,
            headers={"content-type": "application/json"},
            request=mock_request
        )

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_class.return_value = mock_client

        response = client.post("/completion", json=sample_request)

        assert response.status_code == 200
        assert "text" in response.headers
        assert "signature" in response.headers
        assert "signing_address" in response.headers
        assert "signing_algo" in response.headers
        assert response.headers["signing_algo"] == "ecdsa"
        assert response.headers["signing_address"] == test_keys["public_key"]

        response_body = response.json()
        assert response_body == sample_vllm_response

        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        sent_body = call_args.kwargs["json"]
        assert sent_body["stream"] is False

        request_hash = compute_hash(sent_body)
        response_hash = compute_hash(sample_vllm_response)
        expected_text = f"{request_hash}:{response_hash}"

        assert response.headers["text"] == expected_text

        signing_text = response.headers["text"]
        signature_hex = response.headers["signature"]
        public_key_hex = response.headers["signing_address"]

        public_key_bytes = bytes.fromhex(public_key_hex)
        verifying_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
        signature_bytes = bytes.fromhex(signature_hex)

        try:
            verifying_key.verify(signature_bytes, signing_text.encode())
            signature_valid = True
        except:
            signature_valid = False

        assert signature_valid, "Signature verification failed"

    @patch("httpx.AsyncClient")
    def test_completion_forces_stream_false(
        self, mock_client_class, client, mock_env, sample_vllm_response
    ):
        """Test that stream is forced to False even if requested."""
        from httpx import Request

        mock_request = Request("POST", "http://localhost:8000/v1/chat/completions")
        mock_response = HttpxResponse(
            status_code=200,
            json=sample_vllm_response,
            headers={"content-type": "application/json"},
            request=mock_request
        )

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_class.return_value = mock_client

        request_with_stream = {
            "messages": [{"role": "user", "content": "Test"}],
            "stream": True
        }

        response = client.post("/completion", json=request_with_stream)
        assert response.status_code == 200

        call_args = mock_client.post.call_args
        sent_body = call_args.kwargs["json"]
        assert sent_body["stream"] is False

    def test_completion_missing_env_vars(self, client, monkeypatch):
        """Test error when environment variables are missing."""
        monkeypatch.delenv("PRIVATE_KEY", raising=False)
        monkeypatch.delenv("PUBLIC_KEY", raising=False)
        monkeypatch.delenv("VLLM_API_KEY", raising=False)

        response = client.post("/completion", json={"messages": []})
        assert response.status_code == 500
        assert "Missing required environment variables" in response.json()["detail"]

    @patch("httpx.AsyncClient")
    def test_completion_vllm_error(self, mock_client_class, client, mock_env):
        """Test propagation of vLLM service errors."""
        from httpx import HTTPStatusError, Request

        error_response = HttpxResponse(
            status_code=500,
            text="Internal Server Error",
            headers={}
        )

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=HTTPStatusError(
            "Server error",
            request=Request("POST", "http://test"),
            response=error_response
        ))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_class.return_value = mock_client

        response = client.post(
            "/completion",
            json={"messages": [{"role": "user", "content": "Test"}]}
        )

        assert response.status_code == 500
        assert "vLLM service error" in response.json()["detail"]

    @patch("httpx.AsyncClient")
    def test_completion_connection_error(self, mock_client_class, client, mock_env):
        """Test handling of connection errors to vLLM."""
        from httpx import RequestError, Request

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=RequestError(
            "Connection failed",
            request=Request("POST", "http://test")
        ))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_class.return_value = mock_client

        response = client.post(
            "/completion",
            json={"messages": [{"role": "user", "content": "Test"}]}
        )

        assert response.status_code == 503
        assert "Failed to connect to vLLM service" in response.json()["detail"]

    @patch("httpx.AsyncClient")
    def test_completion_optional_fields(
        self, mock_client_class, client, mock_env, sample_vllm_response
    ):
        """Test that optional OpenAI fields are properly handled."""
        from httpx import Request

        mock_request = Request("POST", "http://localhost:8000/v1/chat/completions")
        mock_response = HttpxResponse(
            status_code=200,
            json=sample_vllm_response,
            headers={"content-type": "application/json"},
            request=mock_request
        )

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_class.return_value = mock_client

        request_with_optional = {
            "messages": [{"role": "user", "content": "Test"}],
            "model": "gpt-4",
            "temperature": 0.8,
            "max_tokens": 150,
            "top_p": 0.9,
            "frequency_penalty": 0.5,
            "presence_penalty": 0.5,
            "stop": ["\n"],
            "n": 1
        }

        response = client.post("/completion", json=request_with_optional)
        assert response.status_code == 200

        call_args = mock_client.post.call_args
        sent_body = call_args.kwargs["json"]
        assert sent_body["model"] == "gpt-4"
        assert sent_body["temperature"] == 0.8
        assert sent_body["max_tokens"] == 150


class TestHashingAndSigning:
    """Tests for hashing and signing utilities."""

    def test_compute_hash_consistency(self):
        """Test that hashing is consistent."""
        data = {
            "messages": [{"role": "user", "content": "Test"}],
            "model": "test-model"
        }

        hash1 = compute_hash(data)
        hash2 = compute_hash(data)

        assert hash1 == hash2
        assert len(hash1) == 64

    def test_compute_hash_format(self):
        """Test that hash uses correct JSON formatting with separators."""
        data = {
            "messages": [{"content": "Test", "role": "user"}],
            "model": "test-model"
        }

        hash_result = compute_hash(data)
        assert len(hash_result) == 64
        assert hash_result.isalnum()
        assert hash_result.islower()

        json_str = json.dumps(data, separators=(',', ':'))
        assert ':' in json_str
        assert ', ' not in json_str

    def test_sign_and_verify(self, test_keys):
        """Test signing and verification with ECDSA."""
        message = "test:message:to:sign"
        signature = sign_message(message, test_keys["private_key"])

        assert len(signature) > 0
        assert signature == signature.lower()

        public_key_bytes = bytes.fromhex(test_keys["public_key"])
        verifying_key = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
        signature_bytes = bytes.fromhex(signature)

        try:
            verifying_key.verify(signature_bytes, message.encode())
            valid = True
        except:
            valid = False

        assert valid
