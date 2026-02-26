"""Tests for Ed25519 signing module."""

import pytest
from pathlib import Path

from trust_layer.crypto import (
    generate_keypair,
    load_signing_key,
    sign_proof,
    verify_proof_signature,
    get_public_key_b64url,
)


@pytest.fixture
def keypair(tmp_path):
    """Generate a test keypair in a separate subdirectory."""
    crypto_dir = tmp_path / "crypto_test"
    crypto_dir.mkdir()
    key_path = crypto_dir / ".signing_key.pem"
    pubkey = generate_keypair(key_path)
    private_key = load_signing_key(key_path)
    return private_key, pubkey, key_path


def test_generate_keypair(tmp_path):
    key_path = tmp_path / "test_key.pem"
    pubkey = generate_keypair(key_path)
    assert pubkey.startswith("ed25519:")
    assert len(pubkey) > 10
    assert "=" not in pubkey  # no padding
    assert key_path.exists()


def test_generate_keypair_refuses_overwrite(tmp_path):
    key_path = tmp_path / "test_key.pem"
    generate_keypair(key_path)
    with pytest.raises(FileExistsError):
        generate_keypair(key_path)


def test_load_signing_key(keypair):
    private_key, pubkey, key_path = keypair
    loaded = load_signing_key(key_path)
    assert get_public_key_b64url(loaded) == pubkey


def test_load_signing_key_missing(tmp_path):
    with pytest.raises(RuntimeError, match="not found"):
        load_signing_key(tmp_path / "nonexistent.pem")


def test_sign_and_verify(keypair):
    private_key, pubkey, _ = keypair
    chain_hash = "a" * 64  # simulated SHA-256 hex
    sig = sign_proof(private_key, chain_hash)
    assert sig.startswith("ed25519:")
    assert "=" not in sig
    assert verify_proof_signature(pubkey, chain_hash, sig) is True


def test_verify_invalid_signature(keypair):
    private_key, pubkey, _ = keypair
    chain_hash = "b" * 64
    sig = sign_proof(private_key, chain_hash)
    # Verify against wrong data
    assert verify_proof_signature(pubkey, "c" * 64, sig) is False


def test_verify_bad_format():
    assert verify_proof_signature("bad_format", "aaa", "bad_sig") is False
    assert verify_proof_signature("ed25519:xx", "aaa", "not_ed25519:xx") is False


def test_get_public_key_b64url(keypair):
    private_key, pubkey, _ = keypair
    result = get_public_key_b64url(private_key)
    assert result == pubkey
    assert result.startswith("ed25519:")
    # Ed25519 public key is 32 bytes -> 43 chars base64url
    b64_part = result[len("ed25519:"):]
    assert len(b64_part) == 43
