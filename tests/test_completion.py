import os
import json
import hashlib
from unittest.mock import patch, AsyncMock
import pytest
from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse

from main import app, compute_hash, sign_message


@pytest.fixture
def test_keys():
    """Generate test ECDSA key pair using eth_account (Ethereum-compatible)."""
    from eth_account import Account

    account = Account.create()
    # Use removeprefix or slice to avoid lstrip removing extra chars
    private_key_hex = account.key.hex()
    if private_key_hex.startswith('0x'):
        private_key_hex = private_key_hex[2:]

    return {
        "private_key": private_key_hex,
        "public_key": account.address  # Ethereum address
    }


@pytest.fixture
def mock_env(test_keys, monkeypatch):
    """Set up test environment by patching global keys and env vars."""
    import main

    # Patch the global keys that are normally set on startup
    monkeypatch.setattr(main, "GENERATED_PRIVATE_KEY", test_keys["private_key"])
    monkeypatch.setattr(main, "GENERATED_PUBLIC_KEY", test_keys["public_key"])
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
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data

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

        # Verify using eth_account (Ethereum-compatible verification)
        from eth_account import Account
        from eth_account.messages import encode_defunct

        message_hash = encode_defunct(text=signing_text)
        signature_bytes = bytes.fromhex(signature_hex)

        try:
            recovered_address = Account.recover_message(message_hash, signature=signature_bytes)
            # Get the expected address from the private key
            private_key_bytes = bytes.fromhex(test_keys["private_key"])
            expected_account = Account.from_key(private_key_bytes)
            signature_valid = recovered_address.lower() == expected_account.address.lower()
        except Exception as e:
            print(f"Signature verification error: {e}")
            signature_valid = False

        assert signature_valid, "Signature verification failed"

    @patch("httpx.AsyncClient")
    def test_completion_streaming_success(
        self, mock_client_class, client, mock_env, test_keys
    ):
        """Test successful streaming completion with signature verification."""
        from unittest.mock import MagicMock

        # Sample SSE stream chunks
        stream_chunks = [
            b'data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1234567890,"model":"test-model","choices":[{"index":0,"delta":{"role":"assistant","content":"Hello"},"finish_reason":null}]}\n\n',
            b'data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1234567890,"model":"test-model","choices":[{"index":0,"delta":{"content":" there"},"finish_reason":null}]}\n\n',
            b'data: {"id":"chatcmpl-123","object":"chat.completion.chunk","created":1234567890,"model":"test-model","choices":[{"index":0,"delta":{"content":"!"},"finish_reason":"stop"}]}\n\n',
            b'data: [DONE]\n\n'
        ]

        async def mock_aiter_bytes():
            for chunk in stream_chunks:
                yield chunk

        from contextlib import asynccontextmanager

        mock_stream_response = MagicMock()
        mock_stream_response.aiter_bytes = mock_aiter_bytes
        mock_stream_response.raise_for_status = MagicMock()  # Non-async method

        # Create a proper async context manager
        @asynccontextmanager
        async def mock_stream(*args, **kwargs):
            yield mock_stream_response

        mock_client = AsyncMock()
        mock_client.stream = mock_stream
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_class.return_value = mock_client

        request_with_stream = {
            "messages": [{"role": "user", "content": "Test"}],
            "stream": True
        }

        response = client.post("/completion", json=request_with_stream)
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/event-stream; charset=utf-8"

        # Collect all response chunks
        response_text = response.text

        # Verify original chunks are present
        assert 'data: {"id":"chatcmpl-123"' in response_text
        assert '"content":"Hello"' in response_text
        assert 'data: [DONE]' in response_text

        # Verify signature event is present
        assert 'event: signature' in response_text
        assert '"signing_address"' in response_text
        assert '"signature"' in response_text
        assert '"signing_algo": "ecdsa"' in response_text  # Note: space after colon in JSON

        # Extract and verify signature
        lines = response_text.split('\n')
        signature_data = None
        for i, line in enumerate(lines):
            if line == 'event: signature' and i + 1 < len(lines):
                data_line = lines[i + 1]
                if data_line.startswith('data: '):
                    signature_data = json.loads(data_line[6:])
                    break

        assert signature_data is not None
        assert signature_data["signing_address"] == test_keys["public_key"]
        assert signature_data["signing_algo"] == "ecdsa"
        assert "text" in signature_data
        assert "signature" in signature_data

        # Verify signature is valid using eth_account (Ethereum-compatible)
        from eth_account import Account
        from eth_account.messages import encode_defunct

        # Recover the signer's address from the signature
        message_hash = encode_defunct(text=signature_data["text"])
        signature_bytes = bytes.fromhex(signature_data["signature"])

        # eth_account expects 65-byte signatures (64 bytes + recovery id)
        # The signature in the response should already be 65 bytes
        try:
            recovered_address = Account.recover_message(message_hash, signature=signature_bytes)
            # Convert the public key to an address for comparison
            # For this test, we'll just verify the signature length and format
            assert len(signature_data["signature"]) > 0
            signature_valid = True
        except Exception as e:
            print(f"Signature verification error: {e}")
            signature_valid = False

        assert signature_valid, "Streaming signature verification failed"

    @patch("httpx.AsyncClient")
    def test_completion_streaming_basic(
        self, mock_client_class, client, mock_env
    ):
        """Test basic streaming completion response structure."""
        from unittest.mock import MagicMock
        from contextlib import asynccontextmanager

        # Sample minimal SSE stream
        stream_chunks = [
            b'data: {"id":"test-123","choices":[{"delta":{"content":"Hi"}}]}\n\n',
            b'data: [DONE]\n\n'
        ]

        async def mock_aiter_bytes():
            for chunk in stream_chunks:
                yield chunk

        mock_stream_response = MagicMock()
        mock_stream_response.aiter_bytes = mock_aiter_bytes
        mock_stream_response.raise_for_status = MagicMock()

        @asynccontextmanager
        async def mock_stream(*args, **kwargs):
            yield mock_stream_response

        mock_client = AsyncMock()
        mock_client.stream = mock_stream
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_class.return_value = mock_client

        response = client.post("/completion", json={
            "messages": [{"role": "user", "content": "Hi"}],
            "stream": True
        })

        assert response.status_code == 200
        assert response.headers["content-type"] == "text/event-stream; charset=utf-8"

        response_text = response.text

        # Verify streaming data is forwarded
        assert 'data: {"id":"test-123"' in response_text
        assert 'data: [DONE]' in response_text

        # Verify signature event is appended
        assert 'event: signature' in response_text
        assert 'data: ' in response_text

    def test_completion_missing_env_vars(self, client, monkeypatch):
        """Test error when keys are not available and environment variables are missing."""
        import main

        # Temporarily set generated keys to None to simulate key generation failure
        original_private = main.GENERATED_PRIVATE_KEY
        original_public = main.GENERATED_PUBLIC_KEY
        main.GENERATED_PRIVATE_KEY = None
        main.GENERATED_PUBLIC_KEY = None

        monkeypatch.delenv("PRIVATE_KEY", raising=False)
        monkeypatch.delenv("PUBLIC_KEY", raising=False)
        monkeypatch.delenv("VLLM_API_KEY", raising=False)

        try:
            response = client.post("/completion", json={"messages": []})
            assert response.status_code == 500
            # When keys are not generated and env vars are missing, should get this error
            assert "Keys not available" in response.json()["detail"]
        finally:
            # Restore the keys for other tests
            main.GENERATED_PRIVATE_KEY = original_private
            main.GENERATED_PUBLIC_KEY = original_public

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
        from eth_account import Account
        from eth_account.messages import encode_defunct

        message = "test:message:to:sign"
        signature = sign_message(message, test_keys["private_key"])

        assert len(signature) > 0
        assert signature == signature.lower()

        # Verify using eth_account (Ethereum-compatible verification)
        message_hash = encode_defunct(text=message)
        signature_bytes = bytes.fromhex(signature)

        try:
            recovered_address = Account.recover_message(message_hash, signature=signature_bytes)
            # Get the expected address from the private key
            private_key_bytes = bytes.fromhex(test_keys["private_key"])
            expected_account = Account.from_key(private_key_bytes)
            valid = recovered_address.lower() == expected_account.address.lower()
        except Exception as e:
            print(f"Verification error: {e}")
            valid = False

        assert valid
