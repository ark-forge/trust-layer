"""Tests for proof generation and verification."""

from trust_layer.proofs import (
    canonical_json,
    sha256_hex,
    generate_proof_id,
    generate_proof,
    store_proof,
    load_proof,
    verify_proof_integrity,
    get_public_proof,
)


def test_canonical_json_deterministic():
    """Same data in different order must produce same JSON."""
    a = canonical_json({"z": 1, "a": 2, "m": 3})
    b = canonical_json({"a": 2, "m": 3, "z": 1})
    assert a == b
    assert a == '{"a":2,"m":3,"z":1}'


def test_canonical_json_no_spaces():
    result = canonical_json({"key": "value", "nested": {"a": 1}})
    assert " " not in result


def test_sha256_hex():
    h = sha256_hex("hello")
    assert len(h) == 64
    # Known SHA-256 of "hello"
    assert h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_generate_proof_id_format():
    pid = generate_proof_id()
    assert pid.startswith("prf_")
    parts = pid.split("_")
    assert len(parts) == 4  # prf, date, time, hex


def test_generate_proof_chain():
    request_data = {"target": "https://example.com", "payload": {"key": "value"}}
    response_data = {"result": "ok"}
    payment_data = {"transaction_id": "pi_test_123", "amount": 0.50, "currency": "eur", "status": "succeeded"}
    timestamp = "2026-02-25T15:00:00Z"

    proof = generate_proof(request_data, response_data, payment_data, timestamp)

    assert "hashes" in proof
    assert proof["hashes"]["request"].startswith("sha256:")
    assert proof["hashes"]["response"].startswith("sha256:")
    assert proof["hashes"]["chain"].startswith("sha256:")

    # Chain must be reproducible
    proof2 = generate_proof(request_data, response_data, payment_data, timestamp)
    assert proof["hashes"]["chain"] == proof2["hashes"]["chain"]


def test_store_and_load_proof():
    proof_id = "prf_20260225_150000_abc123"
    proof_data = {"proof_id": proof_id, "hashes": {"chain": "sha256:test"}}

    store_proof(proof_id, proof_data)
    loaded = load_proof(proof_id)
    assert loaded is not None
    assert loaded["proof_id"] == proof_id


def test_load_nonexistent_proof():
    assert load_proof("prf_nonexistent") is None


def test_verify_proof_integrity():
    request_data = {"target": "https://example.com"}
    response_data = {"result": "ok"}
    payment_data = {"transaction_id": "pi_verify_test"}
    timestamp = "2026-02-25T16:00:00Z"

    proof = generate_proof(request_data, response_data, payment_data, timestamp)
    proof["timestamp"] = timestamp

    assert verify_proof_integrity(proof) is True

    # Tamper with chain hash
    tampered = dict(proof)
    tampered["hashes"] = dict(proof["hashes"])
    tampered["hashes"]["chain"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    assert verify_proof_integrity(tampered) is False


def test_get_public_proof_strips_sensitive():
    proof = {
        "proof_id": "prf_test",
        "hashes": {"request": "sha256:aaa", "response": "sha256:bbb", "chain": "sha256:ccc"},
        "payment": {
            "transaction_id": "pi_test",
            "amount": 0.50,
            "currency": "eur",
            "status": "succeeded",
            "receipt_url": "https://stripe.com/receipt",
            "provider": "stripe",
            "raw": {"should_not_appear": True},
        },
        "timestamp": "2026-02-25T15:00:00Z",
        "timestamp_authority": {"status": "verified", "provider": "freetsa.org"},
    }
    public = get_public_proof(proof)
    assert "raw" not in public.get("payment", {})
    assert public["payment"]["transaction_id"] == "pi_test"
