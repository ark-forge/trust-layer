"""Tests for RFC 3161 Timestamp Authority module (mocked — no network)."""

from unittest.mock import patch, MagicMock

from trust_layer.timestamps import submit_hash, verify_tsr

_FAKE_TSR = b"\x30\x82\x00\x01"
_HASH = "a" * 64

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_openssl_ok():
    return MagicMock(returncode=0)

def _resp(status, content=b""):
    r = MagicMock()
    r.status_code = status
    r.content = content
    return r


# ---------------------------------------------------------------------------
# submit_hash — pool failover
# ---------------------------------------------------------------------------

def test_submit_hash_primary_succeeds():
    """Primary TSA (FreeTSA) returns 200 → (tsr_bytes, 'freetsa.org')."""
    with patch("trust_layer.timestamps.subprocess.run", return_value=_mock_openssl_ok()), \
         patch("trust_layer.timestamps.httpx.post", return_value=_resp(200, _FAKE_TSR)), \
         patch("trust_layer.timestamps.Path.read_bytes", return_value=b"\x00" * 32), \
         patch("trust_layer.timestamps.Path.unlink"):
        result = submit_hash(_HASH)

    assert result is not None
    tsr_bytes, provider = result
    assert tsr_bytes == _FAKE_TSR
    assert provider == "freetsa.org"


def test_submit_hash_primary_fails_secondary_succeeds():
    """Primary (FreeTSA) returns 503 → secondary (DigiCert) returns 200."""
    responses = [_resp(503), _resp(200, _FAKE_TSR)]

    with patch("trust_layer.timestamps.subprocess.run", return_value=_mock_openssl_ok()), \
         patch("trust_layer.timestamps.httpx.post", side_effect=responses), \
         patch("trust_layer.timestamps.Path.read_bytes", return_value=b"\x00" * 32), \
         patch("trust_layer.timestamps.Path.unlink"):
        result = submit_hash(_HASH)

    assert result is not None
    tsr_bytes, provider = result
    assert tsr_bytes == _FAKE_TSR
    assert provider == "digicert.com"


def test_submit_hash_primary_secondary_fail_tertiary_succeeds():
    """Primary + secondary fail → tertiary (Sectigo) returns 200."""
    responses = [_resp(503), _resp(503), _resp(200, _FAKE_TSR)]

    with patch("trust_layer.timestamps.subprocess.run", return_value=_mock_openssl_ok()), \
         patch("trust_layer.timestamps.httpx.post", side_effect=responses), \
         patch("trust_layer.timestamps.Path.read_bytes", return_value=b"\x00" * 32), \
         patch("trust_layer.timestamps.Path.unlink"):
        result = submit_hash(_HASH)

    assert result is not None
    tsr_bytes, provider = result
    assert tsr_bytes == _FAKE_TSR
    assert provider == "sectigo.com"


def test_submit_hash_all_servers_down():
    """All 3 TSA servers return 503 → None."""
    with patch("trust_layer.timestamps.subprocess.run", return_value=_mock_openssl_ok()), \
         patch("trust_layer.timestamps.httpx.post", return_value=_resp(503)), \
         patch("trust_layer.timestamps.Path.read_bytes", return_value=b"\x00" * 32), \
         patch("trust_layer.timestamps.Path.unlink"):
        result = submit_hash(_HASH)

    assert result is None


def test_submit_hash_openssl_missing():
    """FileNotFoundError (openssl not installed) → None immediately, no network calls."""
    with patch("trust_layer.timestamps.subprocess.run", side_effect=FileNotFoundError("openssl")), \
         patch("trust_layer.timestamps.Path.unlink"), \
         patch("trust_layer.timestamps.httpx.post") as mock_post:
        result = submit_hash(_HASH)

    assert result is None
    mock_post.assert_not_called()


def test_submit_hash_network_error_falls_through():
    """Network error on primary → tries secondary and tertiary, all fail → None."""
    import httpx as httpx_mod

    with patch("trust_layer.timestamps.subprocess.run", return_value=_mock_openssl_ok()), \
         patch("trust_layer.timestamps.httpx.post",
               side_effect=httpx_mod.ConnectError("fail")), \
         patch("trust_layer.timestamps.Path.read_bytes", return_value=b"\x00" * 32), \
         patch("trust_layer.timestamps.Path.unlink"):
        result = submit_hash(_HASH)

    assert result is None


def test_submit_hash_network_error_then_success():
    """Network error on primary, secondary succeeds."""
    import httpx as httpx_mod

    def _post_side_effect(*args, **kwargs):
        if not hasattr(_post_side_effect, "called"):
            _post_side_effect.called = True
            raise httpx_mod.ConnectError("fail")
        return _resp(200, _FAKE_TSR)

    with patch("trust_layer.timestamps.subprocess.run", return_value=_mock_openssl_ok()), \
         patch("trust_layer.timestamps.httpx.post", side_effect=_post_side_effect), \
         patch("trust_layer.timestamps.Path.read_bytes", return_value=b"\x00" * 32), \
         patch("trust_layer.timestamps.Path.unlink"):
        result = submit_hash(_HASH)

    assert result is not None
    _, provider = result
    assert provider == "digicert.com"


# ---------------------------------------------------------------------------
# verify_tsr
# ---------------------------------------------------------------------------

def test_verify_tsr_graceful_failure():
    """subprocess fails → {verified: False}."""
    import subprocess
    with patch("trust_layer.timestamps.subprocess.run",
               side_effect=subprocess.CalledProcessError(1, "openssl")), \
         patch("trust_layer.timestamps.Path.unlink"):
        result = verify_tsr(b"\x00" * 10, _HASH)
    assert result["verified"] is False
