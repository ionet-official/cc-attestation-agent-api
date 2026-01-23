import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from main import app, prepare_nonce


client = TestClient(app)


class TestPingEndpoint:
    def test_ping_returns_ok(self):
        response = client.get("/ping")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestPrepareNonce:
    def test_generates_random_nonce_when_none_provided(self):
        nonce_bytes, nonce_hex = prepare_nonce(None)
        assert len(nonce_bytes) == 32
        assert len(nonce_hex) == 64
        assert nonce_bytes.hex() == nonce_hex

    def test_generates_random_nonce_when_empty_string(self):
        nonce_bytes, nonce_hex = prepare_nonce("")
        assert len(nonce_bytes) == 32
        assert len(nonce_hex) == 64

    def test_accepts_valid_hex_nonce(self):
        input_hex = "deadbeef"
        nonce_bytes, nonce_hex = prepare_nonce(input_hex)
        assert nonce_bytes[:4] == bytes.fromhex(input_hex)
        assert len(nonce_bytes) == 32

    def test_accepts_hex_with_0x_prefix(self):
        nonce_bytes, nonce_hex = prepare_nonce("0xdeadbeef")
        assert nonce_bytes[:4] == bytes.fromhex("deadbeef")

    def test_pads_short_nonce_to_32_bytes(self):
        nonce_bytes, nonce_hex = prepare_nonce("ab")
        assert len(nonce_bytes) == 32
        assert nonce_bytes[0] == 0xab
        assert nonce_bytes[1:] == b'\x00' * 31

    def test_accepts_full_32_byte_nonce(self):
        full_hex = "a" * 64
        nonce_bytes, nonce_hex = prepare_nonce(full_hex)
        assert len(nonce_bytes) == 32
        assert nonce_hex == full_hex

    def test_rejects_nonce_longer_than_32_bytes(self):
        too_long = "a" * 66
        with pytest.raises(Exception, match="Nonce too long"):
            prepare_nonce(too_long)

    def test_rejects_invalid_hex_string(self):
        with pytest.raises(Exception, match="Invalid hex string"):
            prepare_nonce("not-valid-hex")


class TestAttestationEndpoint:
    @patch("main.get_cpu_quote")
    @patch("main.get_gpu_evidence")
    def test_attestation_with_provided_nonce(self, mock_gpu, mock_cpu):
        mock_cpu.return_value = "mock_cpu_quote"
        mock_gpu.return_value = {"status": "mocked"}

        response = client.post(
            "/attestation",
            json={"nonce": "deadbeef"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "nonce" in data
        assert "cpu" in data
        assert "gpu" in data
        assert data["cpu"]["quote"] == "mock_cpu_quote"

    @patch("main.get_cpu_quote")
    @patch("main.get_gpu_evidence")
    def test_attestation_generates_nonce_when_none_provided(self, mock_gpu, mock_cpu):
        mock_cpu.return_value = "mock_cpu_quote"
        mock_gpu.return_value = {"status": "mocked"}

        response = client.post("/attestation", json={})

        assert response.status_code == 200
        data = response.json()
        assert "nonce" in data
        assert len(data["nonce"]) == 64

    def test_attestation_rejects_invalid_nonce(self):
        response = client.post(
            "/attestation",
            json={"nonce": "invalid-hex-string"}
        )

        assert response.status_code == 500
        assert "Invalid hex string" in response.json()["detail"]

    def test_attestation_rejects_too_long_nonce(self):
        response = client.post(
            "/attestation",
            json={"nonce": "a" * 66}
        )

        assert response.status_code == 500
        assert "Nonce too long" in response.json()["detail"]
