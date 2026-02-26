"""Tests for RFC 3161 Timestamp Authority module (mocked — no network)."""

from unittest.mock import patch, MagicMock

from trust_layer.timestamps import submit_hash, verify_tsr


def test_submit_hash_success():
    """Mock openssl + httpx → TSR bytes returned."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"\x30\x82\x00\x01"  # fake TSR bytes

    with patch("trust_layer.timestamps.subprocess.run") as mock_run, \
         patch("trust_layer.timestamps.httpx.post", return_value=mock_resp), \
         patch("trust_layer.timestamps.Path.read_bytes", return_value=b"\x00" * 32), \
         patch("trust_layer.timestamps.Path.unlink"):
        mock_run.return_value = MagicMock(returncode=0)
        result = submit_hash("a" * 64)
        assert result == b"\x30\x82\x00\x01"


def test_submit_hash_freetsa_down():
    """FreeTSA returns 503 → None."""
    mock_resp = MagicMock()
    mock_resp.status_code = 503

    with patch("trust_layer.timestamps.subprocess.run") as mock_run, \
         patch("trust_layer.timestamps.httpx.post", return_value=mock_resp), \
         patch("trust_layer.timestamps.Path.read_bytes", return_value=b"\x00" * 32), \
         patch("trust_layer.timestamps.Path.unlink"):
        mock_run.return_value = MagicMock(returncode=0)
        result = submit_hash("a" * 64)
        assert result is None


def test_submit_hash_openssl_missing():
    """FileNotFoundError (openssl not installed) → None."""
    with patch("trust_layer.timestamps.subprocess.run", side_effect=FileNotFoundError("openssl")), \
         patch("trust_layer.timestamps.Path.unlink"):
        result = submit_hash("a" * 64)
        assert result is None


def test_submit_hash_network_error():
    """httpx exception → None."""
    import httpx as httpx_mod

    with patch("trust_layer.timestamps.subprocess.run") as mock_run, \
         patch("trust_layer.timestamps.httpx.post", side_effect=httpx_mod.ConnectError("fail")), \
         patch("trust_layer.timestamps.Path.read_bytes", return_value=b"\x00" * 32), \
         patch("trust_layer.timestamps.Path.unlink"):
        mock_run.return_value = MagicMock(returncode=0)
        result = submit_hash("a" * 64)
        assert result is None


def test_verify_tsr_graceful_failure():
    """subprocess fails → {verified: False}."""
    import subprocess
    with patch("trust_layer.timestamps.subprocess.run", side_effect=subprocess.CalledProcessError(1, "openssl")), \
         patch("trust_layer.timestamps.Path.unlink"):
        result = verify_tsr(b"\x00" * 10, "a" * 64)
        assert result["verified"] is False
