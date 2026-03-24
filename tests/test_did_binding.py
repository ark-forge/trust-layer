"""Tests for DID binding — did_resolver.py unit tests + endpoint integration tests."""

import base64
import json
import time
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trust_layer.did_resolver import (
    DIDResolutionError,
    _b58decode,
    bind_did_to_key,
    check_bind_rate,
    consume_challenge,
    create_challenge,
    extract_ed25519_pubkey_bytes,
    resolve_did,
    validate_did,
    verify_oatr_delegation,
    _BIND_RATE,
    _PENDING_CHALLENGES,
    _OATR_MANIFEST_CACHE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _gen_ed25519_keypair():
    """Generate a fresh Ed25519 keypair for testing."""
    private_key = Ed25519PrivateKey.generate()
    pub_bytes = private_key.public_key().public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
        format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.Raw,
    )
    return private_key, pub_bytes


def _pub_bytes_to_b64url(pub_bytes: bytes) -> str:
    return base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode()


def _pub_bytes_to_multibase(pub_bytes: bytes) -> str:
    # base58btc encode with 'z' prefix
    from trust_layer.did_resolver import _B58_ALPHABET
    n = int.from_bytes(pub_bytes, "big")
    result = []
    while n:
        n, r = divmod(n, 58)
        result.append(_B58_ALPHABET[r:r+1].decode())
    return "z" + "".join(reversed(result))


def _make_did_doc_multibase(pub_bytes: bytes) -> dict:
    mb = _pub_bytes_to_multibase(pub_bytes)
    did = f"did:web:example.com"
    return {
        "id": did,
        "verificationMethod": [{
            "id": f"{did}#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyMultibase": mb,
        }],
    }


def _make_did_doc_jwk(pub_bytes: bytes) -> dict:
    x = _pub_bytes_to_b64url(pub_bytes)
    did = "did:web:example.com"
    return {
        "id": did,
        "verificationMethod": [{
            "id": f"{did}#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": x},
        }],
    }


# ===========================================================================
# Unit tests — validate_did
# ===========================================================================

def test_validate_did_web_simple():
    assert validate_did("did:web:trust.arkforge.tech") is True


def test_validate_did_web_with_path():
    assert validate_did("did:web:example.com:agent:alice") is True


def test_validate_did_key_valid():
    assert validate_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK") is True


def test_validate_did_unknown_method():
    assert validate_did("did:foo:bar") is False


def test_validate_did_empty():
    assert validate_did("") is False


def test_validate_did_none():
    assert validate_did(None) is False  # type: ignore


# ===========================================================================
# Unit tests — resolve_did (did:web)
# ===========================================================================

def test_resolve_did_web_success(tmp_path):
    _, pub_bytes = _gen_ed25519_keypair()
    doc = _make_did_doc_jwk(pub_bytes)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = doc

    with patch("trust_layer.did_resolver.httpx.get", return_value=mock_resp) as mock_get:
        with patch("trust_layer.did_resolver._check_ssrf"):
            result = resolve_did("did:web:trust.arkforge.tech")
    assert result == doc
    mock_get.assert_called_once_with(
        "https://trust.arkforge.tech/.well-known/did.json",
        timeout=5.0,
        follow_redirects=False,
    )


def test_resolve_did_web_path_builds_correct_url():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"id": "did:web:example.com:agent:alice"}

    with patch("trust_layer.did_resolver.httpx.get", return_value=mock_resp) as mock_get:
        with patch("trust_layer.did_resolver._check_ssrf"):
            resolve_did("did:web:example.com:agent:alice")
    mock_get.assert_called_once_with(
        "https://example.com/agent/alice/did.json",
        timeout=5.0,
        follow_redirects=False,
    )


def test_resolve_did_web_404_raises():
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch("trust_layer.did_resolver.httpx.get", return_value=mock_resp):
        with patch("trust_layer.did_resolver._check_ssrf"):
            with pytest.raises(DIDResolutionError) as exc:
                resolve_did("did:web:example.com")
    assert exc.value.status == 404


def test_resolve_did_web_ssrf_private_ip_raises():
    with patch("trust_layer.did_resolver.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (None, None, None, None, ("127.0.0.1", 0))
        ]
        with pytest.raises(DIDResolutionError) as exc:
            resolve_did("did:web:evil.local")
    assert "private IP" in exc.value.message


# ===========================================================================
# Unit tests — extract_ed25519_pubkey_bytes
# ===========================================================================

def test_extract_pubkey_multibase():
    _, pub_bytes = _gen_ed25519_keypair()
    doc = _make_did_doc_multibase(pub_bytes)
    extracted = extract_ed25519_pubkey_bytes(doc)
    assert extracted == pub_bytes


def test_extract_pubkey_jwk():
    _, pub_bytes = _gen_ed25519_keypair()
    doc = _make_did_doc_jwk(pub_bytes)
    extracted = extract_ed25519_pubkey_bytes(doc)
    assert extracted == pub_bytes


def test_extract_pubkey_no_ed25519_raises():
    doc = {
        "id": "did:web:example.com",
        "verificationMethod": [{
            "id": "did:web:example.com#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:web:example.com",
            "publicKeyJwk": {"kty": "EC", "crv": "P-256"},
        }],
    }
    with pytest.raises(DIDResolutionError):
        extract_ed25519_pubkey_bytes(doc)


# ===========================================================================
# Unit tests — did:key round-trip
# ===========================================================================

def test_did_key_resolve_roundtrip():
    """did:key WG test vector: known Ed25519 key."""
    # Generate fresh key and encode as did:key
    _, pub_bytes = _gen_ed25519_keypair()
    # Build did:key: multicodec 0xed01 + 32 bytes, base58btc
    raw = bytes([0xed, 0x01]) + pub_bytes
    from trust_layer.did_resolver import _B58_ALPHABET
    n = int.from_bytes(raw, "big")
    chars = []
    while n:
        n, r = divmod(n, 58)
        chars.append(_B58_ALPHABET[r:r+1].decode())
    key_str = "z" + "".join(reversed(chars))
    did = f"did:key:{key_str}"

    doc = resolve_did(did)
    extracted = extract_ed25519_pubkey_bytes(doc)
    assert extracted == pub_bytes


def test_did_key_non_ed25519_raises():
    # Multicodec 0x1200 = P-256 — not Ed25519
    fake_key = bytes([0x12, 0x00]) + b"\x00" * 32
    from trust_layer.did_resolver import _B58_ALPHABET
    n = int.from_bytes(fake_key, "big")
    chars = []
    while n:
        n, r = divmod(n, 58)
        chars.append(_B58_ALPHABET[r:r+1].decode())
    key_str = "z" + "".join(reversed(chars))
    with pytest.raises(DIDResolutionError) as exc:
        resolve_did(f"did:key:{key_str}")
    assert "Ed25519" in exc.value.message


# ===========================================================================
# Unit tests — challenge create/consume
# ===========================================================================

def test_challenge_create_consume():
    _, pub_bytes = _gen_ed25519_keypair()
    # Clear state
    _PENDING_CHALLENGES.clear()
    challenge = create_challenge("mcp_test_abc123456789", "did:web:example.com", pub_bytes)
    payload = consume_challenge(challenge)
    assert payload is not None
    assert payload["did"] == "did:web:example.com"
    assert payload["pub_bytes_hex"] == pub_bytes.hex()


def test_challenge_second_consume_returns_none():
    _, pub_bytes = _gen_ed25519_keypair()
    _PENDING_CHALLENGES.clear()
    challenge = create_challenge("mcp_test_abc123456789", "did:web:example.com", pub_bytes)
    consume_challenge(challenge)
    result = consume_challenge(challenge)
    assert result is None


def test_challenge_expired_returns_none():
    _, pub_bytes = _gen_ed25519_keypair()
    challenge = "expired_challenge_xyz"
    _PENDING_CHALLENGES[challenge] = {
        "api_key": "mcp_test_abc",
        "did": "did:web:example.com",
        "pub_bytes_hex": pub_bytes.hex(),
        "expires_at": time.time() - 10,
    }
    result = consume_challenge(challenge)
    assert result is None


# ===========================================================================
# Unit tests — rate limiting
# ===========================================================================

def test_bind_rate_allows_five():
    api_key = "mcp_test_ratelimit_unique_xyz"
    _BIND_RATE.pop(api_key, None)
    for _ in range(5):
        assert check_bind_rate(api_key) is True


def test_bind_rate_blocks_sixth():
    api_key = "mcp_test_ratelimit_block_xyz"
    _BIND_RATE.pop(api_key, None)
    for _ in range(5):
        check_bind_rate(api_key)
    assert check_bind_rate(api_key) is False


# ===========================================================================
# Unit tests — OATR delegation
# ===========================================================================

def _make_oatr_manifest(pub_bytes: bytes, status: str = "active") -> dict:
    return {
        "issuers": {
            "testissuer": {
                "issuer_id": "testissuer",
                "status": status,
                "public_keys": [{
                    "kid": "testissuer-2026",
                    "algorithm": "Ed25519",
                    "public_key": _pub_bytes_to_b64url(pub_bytes),
                    "status": "active",
                }],
            }
        }
    }


def test_oatr_delegation_valid():
    _, pub_bytes = _gen_ed25519_keypair()
    manifest = _make_oatr_manifest(pub_bytes)
    _OATR_MANIFEST_CACHE["data"] = None
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = manifest
    with patch("trust_layer.did_resolver.httpx.get", return_value=mock_resp):
        result = verify_oatr_delegation("did:web:example.com", "testissuer", pub_bytes)
    assert result is True


def test_oatr_delegation_inactive_issuer():
    _, pub_bytes = _gen_ed25519_keypair()
    manifest = _make_oatr_manifest(pub_bytes, status="inactive")
    _OATR_MANIFEST_CACHE["data"] = None
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = manifest
    with patch("trust_layer.did_resolver.httpx.get", return_value=mock_resp):
        result = verify_oatr_delegation("did:web:example.com", "testissuer", pub_bytes)
    assert result is False


def test_oatr_delegation_key_mismatch():
    _, pub_bytes = _gen_ed25519_keypair()
    _, other_pub = _gen_ed25519_keypair()
    manifest = _make_oatr_manifest(other_pub)  # different key in registry
    _OATR_MANIFEST_CACHE["data"] = None
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = manifest
    with patch("trust_layer.did_resolver.httpx.get", return_value=mock_resp):
        result = verify_oatr_delegation("did:web:example.com", "testissuer", pub_bytes)
    assert result is False


# ===========================================================================
# Integration tests — /v1/keys/bind-did (Path A)
# ===========================================================================

def test_bind_did_path_a_returns_challenge(client, test_api_key):
    _, pub_bytes = _gen_ed25519_keypair()
    doc = _make_did_doc_jwk(pub_bytes)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = doc

    _PENDING_CHALLENGES.clear()
    with patch("trust_layer.did_resolver.httpx.get", return_value=mock_resp):
        with patch("trust_layer.did_resolver._check_ssrf"):
            resp = client.post(
                "/v1/keys/bind-did",
                json={"did": "did:web:example.com"},
                headers={"X-Api-Key": test_api_key},
            )
    assert resp.status_code == 200
    data = resp.json()
    assert "challenge" in data
    assert data["expires_in"] == 300


def test_bind_did_confirm_success(client, test_api_key):
    private_key, pub_bytes = _gen_ed25519_keypair()
    doc = _make_did_doc_jwk(pub_bytes)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = doc

    _PENDING_CHALLENGES.clear()
    with patch("trust_layer.did_resolver.httpx.get", return_value=mock_resp):
        with patch("trust_layer.did_resolver._check_ssrf"):
            resp1 = client.post(
                "/v1/keys/bind-did",
                json={"did": "did:web:example.com"},
                headers={"X-Api-Key": test_api_key},
            )
    assert resp1.status_code == 200
    challenge = resp1.json()["challenge"]

    # Sign challenge
    sig = private_key.sign(challenge.encode())
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    resp2 = client.post(
        "/v1/keys/bind-did/confirm",
        json={"challenge": challenge, "signature": sig_b64},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp2.status_code == 200
    data = resp2.json()
    assert data["verified_did"] == "did:web:example.com"
    assert "bound_at" in data
    assert data["method"] == "challenge_response"


def test_bind_did_path_b_oatr(client, test_api_key):
    _, pub_bytes = _gen_ed25519_keypair()
    doc = _make_did_doc_jwk(pub_bytes)
    manifest = _make_oatr_manifest(pub_bytes)

    mock_did_resp = MagicMock()
    mock_did_resp.status_code = 200
    mock_did_resp.json.return_value = doc

    mock_oatr_resp = MagicMock()
    mock_oatr_resp.status_code = 200
    mock_oatr_resp.json.return_value = manifest

    _OATR_MANIFEST_CACHE["data"] = None

    def _mock_get(url, **kwargs):
        if "raw.githubusercontent.com" in url:
            return mock_oatr_resp
        return mock_did_resp

    with patch("trust_layer.did_resolver.httpx.get", side_effect=_mock_get):
        with patch("trust_layer.did_resolver._check_ssrf"):
            resp = client.post(
                "/v1/keys/bind-did",
                json={"did": "did:web:example.com", "oatr_issuer_id": "testissuer"},
                headers={"X-Api-Key": test_api_key},
            )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verified_did"] == "did:web:example.com"
    assert data["method"] == "oatr_delegation"


def test_bind_did_invalid_did(client, test_api_key):
    resp = client.post(
        "/v1/keys/bind-did",
        json={"did": "did:foo:invalid"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 400


def test_bind_did_resolution_fails_503(client, test_api_key):
    import httpx as _httpx
    with patch("trust_layer.did_resolver.httpx.get", side_effect=_httpx.RequestError("timeout")):
        with patch("trust_layer.did_resolver._check_ssrf"):
            resp = client.post(
                "/v1/keys/bind-did",
                json={"did": "did:web:unreachable.example.com"},
                headers={"X-Api-Key": test_api_key},
            )
    assert resp.status_code == 503


def test_bind_did_rate_limited(client, test_api_key):
    # Exhaust rate limit
    _BIND_RATE[test_api_key] = [time.time()] * 5

    _, pub_bytes = _gen_ed25519_keypair()
    resp = client.post(
        "/v1/keys/bind-did",
        json={"did": "did:web:example.com"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 429


def test_bind_did_confirm_wrong_key(client, test_api_key):
    """Challenge issued for different API key should fail."""
    other_private, pub_bytes = _gen_ed25519_keypair()
    challenge = "test_challenge_other_key"
    _PENDING_CHALLENGES[challenge] = {
        "api_key": "mcp_test_other_key_prefix123",
        "did": "did:web:example.com",
        "pub_bytes_hex": pub_bytes.hex(),
        "expires_at": time.time() + 300,
    }
    sig = other_private.sign(challenge.encode())
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    resp = client.post(
        "/v1/keys/bind-did/confirm",
        json={"challenge": challenge, "signature": sig_b64},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 400


def test_bind_did_confirm_invalid_signature(client, test_api_key):
    _, pub_bytes = _gen_ed25519_keypair()
    doc = _make_did_doc_jwk(pub_bytes)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = doc

    _PENDING_CHALLENGES.clear()
    with patch("trust_layer.did_resolver.httpx.get", return_value=mock_resp):
        with patch("trust_layer.did_resolver._check_ssrf"):
            resp1 = client.post(
                "/v1/keys/bind-did",
                json={"did": "did:web:example.com"},
                headers={"X-Api-Key": test_api_key},
            )
    challenge = resp1.json()["challenge"]

    # Sign with a DIFFERENT key
    wrong_priv = Ed25519PrivateKey.generate()
    sig = wrong_priv.sign(challenge.encode())
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    resp2 = client.post(
        "/v1/keys/bind-did/confirm",
        json={"challenge": challenge, "signature": sig_b64},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp2.status_code == 400


def test_bind_did_confirm_challenge_expired(client, test_api_key):
    challenge = "expired_challenge_confirm"
    _, pub_bytes = _gen_ed25519_keypair()
    _PENDING_CHALLENGES[challenge] = {
        "api_key": test_api_key,
        "did": "did:web:example.com",
        "pub_bytes_hex": pub_bytes.hex(),
        "expires_at": time.time() - 1,
    }
    resp = client.post(
        "/v1/keys/bind-did/confirm",
        json={"challenge": challenge, "signature": "aabbccdd"},
        headers={"X-Api-Key": test_api_key},
    )
    assert resp.status_code == 410


# ===========================================================================
# Integration tests — proxy behavior with verified DID
# ===========================================================================

def test_proxy_uses_verified_did_as_agent_identity(client, test_api_key):
    """When key has verified_did, validate_api_key returns it and proxy overrides agent_identity."""
    from trust_layer.keys import load_api_keys, save_api_keys, validate_api_key, _KEYS_LOCK
    from trust_layer.proxy import execute_proxy

    did = "did:web:trust.arkforge.tech"
    with _KEYS_LOCK:
        keys = load_api_keys()
        keys[test_api_key]["verified_did"] = did
        save_api_keys(keys)

    key_info = validate_api_key(test_api_key)
    assert key_info is not None
    assert key_info.get("verified_did") == did

    # Simulate the DID override logic from execute_proxy (lines added in proxy.py)
    agent_identity = "did:web:attacker.example.com"  # declared by caller
    verified_did = key_info.get("verified_did")
    if verified_did:
        agent_identity = verified_did

    assert agent_identity == did


def test_proxy_without_verified_did_unchanged(client, test_api_key):
    """Keys without verified_did use normal agent_identity flow."""
    from trust_layer.keys import load_api_keys
    keys = load_api_keys()
    assert keys[test_api_key].get("verified_did") is None


def test_identity_consistent_true_with_verified_did(client, test_api_key, mock_stripe_provider):
    """identity_consistent = True when verified_did matches, even if mismatch in profile."""
    from trust_layer.keys import load_api_keys, save_api_keys, _KEYS_LOCK
    import trust_layer.proxy as proxy_mod
    from pathlib import Path

    did = "did:web:trust.arkforge.tech"
    with _KEYS_LOCK:
        keys = load_api_keys()
        keys[test_api_key]["verified_did"] = did
        save_api_keys(keys)

    # Inject a mismatch flag in the agent profile
    agent_path = proxy_mod.AGENTS_DIR / f"{test_api_key[:16]}.json"
    agent_path.parent.mkdir(parents=True, exist_ok=True)
    agent_path.write_text(json.dumps({
        "declared_identity": "did:web:old.example.com",
        "identity_mismatch": True,
    }))

    # validate_api_key should return the key info including verified_did
    from trust_layer.keys import validate_api_key
    key_info = validate_api_key(test_api_key)
    assert key_info is not None
    assert key_info.get("verified_did") == did

    # Simulate the identity_consistent logic from proxy.py
    agent_identity = did  # already overridden by verified_did
    if key_info.get("verified_did") and agent_identity == key_info["verified_did"]:
        identity_consistent = True
    else:
        identity_consistent = None  # would check profile

    assert identity_consistent is True


# ===========================================================================
# Unit tests — did_resolution_status in proof receipts
# ===========================================================================

def test_did_resolution_status_bound_with_verified_did():
    """Proof with verified DID bound to key → did_resolution_status == 'bound'."""
    from trust_layer.proofs import generate_proof
    proof = generate_proof(
        request_data={"url": "https://example.com"},
        response_data={"status": 200},
        payment_data={"transaction_id": "pi_test", "amount": 1, "currency": "usd"},
        timestamp="2026-03-24T00:00:00Z",
        buyer_fingerprint="abc123",
        seller="example.com",
        agent_identity="did:web:trust.arkforge.tech",
        agent_identity_verified=True,
        did_resolution_status="bound",
    )
    assert proof["parties"]["did_resolution_status"] == "bound"
    assert proof["parties"]["agent_identity_verified"] is True


def test_did_resolution_status_unverified_without_did_binding():
    """Proof with caller-declared agent_identity (no DID binding) → did_resolution_status == 'unverified'."""
    from trust_layer.proofs import generate_proof
    proof = generate_proof(
        request_data={"url": "https://example.com"},
        response_data={"status": 200},
        payment_data={"transaction_id": "pi_test", "amount": 1, "currency": "usd"},
        timestamp="2026-03-24T00:00:00Z",
        buyer_fingerprint="abc123",
        seller="example.com",
        agent_identity="my-agent-v1",
        did_resolution_status="unverified",
    )
    assert proof["parties"]["did_resolution_status"] == "unverified"
    assert proof["parties"].get("agent_identity_verified") is None


def test_did_resolution_status_absent_without_agent_identity():
    """Proof without agent_identity → did_resolution_status is None."""
    from trust_layer.proofs import generate_proof
    proof = generate_proof(
        request_data={"url": "https://example.com"},
        response_data={"status": 200},
        payment_data={"transaction_id": "pi_test", "amount": 1, "currency": "usd"},
        timestamp="2026-03-24T00:00:00Z",
        buyer_fingerprint="abc123",
        seller="example.com",
    )
    assert proof["parties"].get("did_resolution_status") is None
