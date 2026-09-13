"""Tests for Sigstore Rekor transparency log module."""

import base64
import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from trust_layer.rekor import (
    _build_entry,
    _submit_once,
    submit_to_rekor,
    verify_rekor_entry,
)


@pytest.fixture
def ec_keypair():
    """Generate a fresh ECDSA P-256 key pair for testing."""
    key = ec.generate_private_key(ec.SECP256R1())
    return key


# --- _build_entry tests ---

def test_build_entry_structure(ec_keypair):
    """_build_entry must produce a valid hashedrekord v0.0.1 with sha256."""
    chain_hash = "a" * 64
    entry = _build_entry(chain_hash, ec_keypair)

    assert entry["apiVersion"] == "0.0.1"
    assert entry["kind"] == "hashedrekord"
    spec = entry["spec"]
    # ECDSA P-256 with SHA-256
    assert spec["data"]["hash"]["algorithm"] == "sha256"
    # Value must be SHA-256 of the chain_hash UTF-8 bytes
    expected_sha256 = hashlib.sha256(chain_hash.encode("utf-8")).hexdigest()
    assert spec["data"]["hash"]["value"] == expected_sha256


def test_build_entry_signature_is_standard_base64(ec_keypair):
    """Signature in entry must be standard base64, DER-encoded ECDSA (70-72 bytes)."""
    chain_hash = "b" * 64
    entry = _build_entry(chain_hash, ec_keypair)

    sig_b64 = entry["spec"]["signature"]["content"]
    # Must be decodable as standard base64
    raw = base64.b64decode(sig_b64)
    # ECDSA P-256 DER signature is 70-72 bytes (variable-length DER encoding)
    assert 68 <= len(raw) <= 72
    # DER sequence starts with 0x30
    assert raw[0] == 0x30


def test_build_entry_public_key_is_pem(ec_keypair):
    """Public key in entry must be base64-encoded PEM SPKI."""
    chain_hash = "c" * 64
    entry = _build_entry(chain_hash, ec_keypair)

    pub_b64 = entry["spec"]["signature"]["publicKey"]["content"]
    # Must be decodable
    pem = base64.b64decode(pub_b64).decode("ascii")
    assert "BEGIN PUBLIC KEY" in pem
    assert "END PUBLIC KEY" in pem


def test_build_entry_signature_verifies(ec_keypair):
    """The signature in the entry must verify against the artifact."""
    chain_hash = "d" * 64
    entry = _build_entry(chain_hash, ec_keypair)

    sig_b64 = entry["spec"]["signature"]["content"]
    sig_der = base64.b64decode(sig_b64)

    # Verify locally using the public key
    artifact_bytes = chain_hash.encode("utf-8")
    pub_key = ec_keypair.public_key()
    # Should not raise
    pub_key.verify(sig_der, artifact_bytes, ec.ECDSA(hashes.SHA256()))


# --- _submit_once tests ---

def test_submit_once_success(ec_keypair):
    """_submit_once returns parsed entry dict on HTTP 200/201."""
    chain_hash = "d" * 64

    fake_response = MagicMock()
    fake_response.status_code = 201
    fake_response.json.return_value = {
        "abc123uuid": {
            "logIndex": 9999,
            "integratedTime": 1709500000,
            "body": "...",
        }
    }

    with patch("trust_layer.rekor.httpx.post", return_value=fake_response):
        result = _submit_once(chain_hash, ec_keypair)

    assert result is not None
    assert "abc123uuid" in result
    assert result["abc123uuid"]["logIndex"] == 9999


def test_submit_once_409_conflict_returns_existing_entry(ec_keypair):
    """_submit_once on HTTP 409 returns existing entry from response body."""
    chain_hash = "e0" * 32

    fake_response = MagicMock()
    fake_response.status_code = 409
    fake_response.json.return_value = {
        "existing_uuid_xyz": {
            "logIndex": 5000,
            "integratedTime": 1709400000,
        }
    }

    with patch("trust_layer.rekor.httpx.post", return_value=fake_response):
        result = _submit_once(chain_hash, ec_keypair)

    assert result is not None
    assert "existing_uuid_xyz" in result
    assert result["existing_uuid_xyz"]["logIndex"] == 5000


def test_submit_once_409_no_body_returns_sentinel(ec_keypair):
    """_submit_once on HTTP 409 with no parseable body returns a sentinel dict (entry anchored)."""
    chain_hash = "f0" * 32

    fake_response = MagicMock()
    fake_response.status_code = 409
    fake_response.json.side_effect = Exception("no json")

    with patch("trust_layer.rekor.httpx.post", return_value=fake_response):
        result = _submit_once(chain_hash, ec_keypair)

    assert result is not None
    assert "_already_exists" in result
    assert result["_already_exists"]["status"] == "conflict_entry_exists"


def test_submit_once_http_error_returns_none(ec_keypair):
    """_submit_once returns None on non-200/201 status."""
    chain_hash = "e" * 64

    fake_response = MagicMock()
    fake_response.status_code = 500

    with patch("trust_layer.rekor.httpx.post", return_value=fake_response):
        result = _submit_once(chain_hash, ec_keypair)

    assert result is None


def test_submit_once_timeout_returns_none(ec_keypair):
    """_submit_once returns None on timeout."""
    import httpx
    chain_hash = "f" * 64

    with patch("trust_layer.rekor.httpx.post", side_effect=httpx.TimeoutException("timeout")):
        result = _submit_once(chain_hash, ec_keypair)

    assert result is None


# --- submit_to_rekor tests ---

def test_submit_to_rekor_success():
    """submit_to_rekor returns verified dict on success."""
    chain_hash = "a1b2" * 16

    fake_response = MagicMock()
    fake_response.status_code = 201
    fake_response.json.return_value = {
        "24296fb_uuid_abc": {
            "logIndex": 12345678,
            "integratedTime": 1709500000,
        }
    }

    # Provide a test EC key to avoid filesystem access
    test_ec_key = ec.generate_private_key(ec.SECP256R1())
    with patch("trust_layer.rekor.httpx.post", return_value=fake_response):
        with patch("trust_layer.rekor._get_or_create_rekor_ec_key", return_value=test_ec_key):
            result = submit_to_rekor(chain_hash)

    assert result["status"] == "verified"
    assert result["provider"] == "sigstore-rekor"
    assert result["log_index"] == 12345678
    assert result["integrated_time"] == 1709500000
    assert "log_url" in result
    assert "verify_url" in result
    assert "12345678" in result["verify_url"]


def test_submit_to_rekor_failure():
    """submit_to_rekor returns failed dict when all retries fail."""
    chain_hash = "0" * 64

    fake_response = MagicMock()
    fake_response.status_code = 503

    test_ec_key = ec.generate_private_key(ec.SECP256R1())
    with patch("trust_layer.rekor.httpx.post", return_value=fake_response):
        with patch("trust_layer.rekor._get_or_create_rekor_ec_key", return_value=test_ec_key):
            with patch("trust_layer.rekor.time.sleep"):  # skip backoff
                result = submit_to_rekor(chain_hash)

    assert result["status"] == "failed"
    assert result["provider"] == "sigstore-rekor"
    assert "error" in result


# --- verify_rekor_entry tests ---

def _fixture_entry():
    """A real Rekor entry, captured 2026-09-13, with the proof it anchors."""
    base = Path(__file__).parent / "fixtures" / "verify_proof"
    proof = json.loads((base / "proof_rekor.json").read_text())
    entry = json.loads((base / "rekor_entry.json").read_text())
    log_key = (base / "rekor_log_pubkey.pem").read_bytes()
    chain = proof["hashes"]["chain"].replace("sha256:", "")
    return entry, log_key, chain


def _patched_get(entry, log_key):
    """Serve the log entry and the log public key from the fixtures."""
    def fake_get(url, **kwargs):
        r = MagicMock()
        r.status_code = 200
        if url.endswith("/publicKey"):
            r.content = log_key
        else:
            r.json.return_value = entry
        return r
    return fake_get


def test_verify_rekor_entry_verifies_a_real_entry():
    entry, log_key, chain = _fixture_entry()
    with patch("trust_layer.rekor.httpx.get", side_effect=_patched_get(entry, log_key)):
        result = verify_rekor_entry("uuid", chain)
    assert result["verified"] is True
    assert all(result["checks"].values())


def test_verify_rekor_entry_rejects_a_mismatched_chain_hash():
    """The defect this replaced: HTTP 200 alone was treated as verified, so a genuine
    entry for somebody else's artefact passed. An entry must be bound to THIS proof."""
    entry, log_key, _ = _fixture_entry()
    with patch("trust_layer.rekor.httpx.get", side_effect=_patched_get(entry, log_key)):
        result = verify_rekor_entry("uuid", "ab" * 32)
    assert result["verified"] is False
    assert result["checks"]["artifact_matches_chain_hash"] is False
    assert result["checks"]["entry_signature"] is False


def test_verify_rekor_entry_unbound_is_not_evidence():
    """Without a chain hash the entry cannot be tied to any proof, so it is not
    reported as verified even though the log-side checks all pass."""
    entry, log_key, _ = _fixture_entry()
    with patch("trust_layer.rekor.httpx.get", side_effect=_patched_get(entry, log_key)):
        result = verify_rekor_entry("uuid")
    assert result["verified"] is False
    assert result["checks"]["inclusion_proof"] is True
    assert result["checks"]["artifact_matches_chain_hash"] is None


def test_verify_rekor_entry_rejects_a_corrupted_inclusion_proof():
    entry, log_key, chain = _fixture_entry()
    entry = json.loads(json.dumps(entry))
    next(iter(entry.values()))["verification"]["inclusionProof"]["hashes"][0] = "00" * 32
    with patch("trust_layer.rekor.httpx.get", side_effect=_patched_get(entry, log_key)):
        result = verify_rekor_entry("uuid", chain)
    assert result["verified"] is False
    assert result["checks"]["inclusion_proof"] is False


def test_verify_rekor_entry_rejects_another_entry_kind():
    entry, log_key, chain = _fixture_entry()
    base = Path(__file__).parent / "fixtures" / "verify_proof"
    other = json.loads((base / "rekor_unrelated.json").read_text())
    with patch("trust_layer.rekor.httpx.get", side_effect=_patched_get(other, log_key)):
        result = verify_rekor_entry("uuid", chain)
    assert result["verified"] is False
    assert result["checks"]["kind"] is False


def test_verify_rekor_entry_not_found():
    """verify_rekor_entry returns verified=False on HTTP 404."""
    fake_response = MagicMock()
    fake_response.status_code = 404

    with patch("trust_layer.rekor.httpx.get", return_value=fake_response):
        result = verify_rekor_entry("nonexistent_uuid")

    assert result["verified"] is False


def test_submit_to_rekor_disabled(monkeypatch):
    """submit_to_rekor returns disabled dict when REKOR_ENABLED=False."""
    import trust_layer.config as cfg
    monkeypatch.setattr(cfg, "REKOR_ENABLED", False)
    # Reload REKOR_ENABLED into rekor module
    import trust_layer.rekor as rekor_mod
    monkeypatch.setattr(rekor_mod, "REKOR_ENABLED", False)
    result = submit_to_rekor("a" * 64)
    assert result["status"] == "disabled"
    assert result["provider"] == "sigstore-rekor"
