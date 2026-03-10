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
        "spec_version": "1.0",
        "hashes": {"request": "sha256:aaa", "response": "sha256:bbb", "chain": "sha256:ccc"},
        "certification_fee": {
            "transaction_id": "pi_test",
            "amount": 0.50,
            "currency": "eur",
            "status": "succeeded",
            "receipt_url": "https://stripe.com/receipt",
            "method": "stripe",
            "raw": {"should_not_appear": True},
        },
        "timestamp": "2026-02-25T15:00:00Z",
        "timestamp_authority": {"status": "verified", "provider": "freetsa.org"},
    }
    public = get_public_proof(proof)
    assert "raw" not in public.get("certification_fee", {})
    assert public["certification_fee"]["transaction_id"] == "pi_test"


# --- New tests for spec_version, upstream_timestamp, signature fields ---

def test_generate_proof_includes_spec_version():
    """spec_version must be present in every proof — current: 1.2 (canonical JSON chain hash)."""
    proof = generate_proof(
        {"target": "https://example.com"}, {"result": "ok"},
        {"transaction_id": "pi_spec"}, "2026-02-26T10:00:00Z",
    )
    assert proof.get("spec_version") == "1.2"


def test_chain_hash_canonical_json_no_preimage_ambiguity():
    """Spec 1.2: two different inputs must NOT produce the same chain hash.

    Regression test for the preimage ambiguity fixed in spec 1.2.
    With legacy concatenation:
        payment_id="pi_abc" + timestamp="2026-03-10" == payment_id="pi_abc2026" + timestamp="-03-10"
    With canonical JSON this collision is impossible (field boundaries are explicit).
    """
    base = {
        "request_data": {"target": "https://example.com"},
        "response_data": {"result": "ok"},
        "timestamp_a": "2026-03-10",
        "timestamp_b": "-03-10",
    }
    proof_a = generate_proof(
        base["request_data"], base["response_data"],
        {"transaction_id": "pi_abc"}, base["timestamp_a"],
    )
    proof_b = generate_proof(
        base["request_data"], base["response_data"],
        {"transaction_id": "pi_abc2026"}, base["timestamp_b"],
    )
    assert proof_a["hashes"]["chain"] != proof_b["hashes"]["chain"]


def test_chain_hash_without_upstream_timestamp():
    """Proof without upstream_timestamp uses original formula — backward compat."""
    request_data = {"target": "https://example.com"}
    response_data = {"result": "ok"}
    payment_data = {"transaction_id": "pi_compat"}
    timestamp = "2026-02-26T10:00:00Z"

    proof = generate_proof(request_data, response_data, payment_data, timestamp,
                           buyer_fingerprint="bf_test", seller="example.com")
    assert verify_proof_integrity(proof) is True
    # upstream_timestamp should not be in proof dict
    assert "upstream_timestamp" not in proof


def test_chain_hash_with_upstream_timestamp():
    """Proof with upstream_timestamp includes it in chain hash."""
    request_data = {"target": "https://example.com"}
    response_data = {"result": "ok"}
    payment_data = {"transaction_id": "pi_upstream"}
    timestamp = "2026-02-26T10:00:00Z"
    upstream_ts = "Thu, 26 Feb 2026 10:00:01 GMT"

    proof_with = generate_proof(request_data, response_data, payment_data, timestamp,
                                buyer_fingerprint="bf_test", seller="example.com",
                                upstream_timestamp=upstream_ts)
    proof_without = generate_proof(request_data, response_data, payment_data, timestamp,
                                   buyer_fingerprint="bf_test", seller="example.com")

    # Chain hashes must differ
    assert proof_with["hashes"]["chain"] != proof_without["hashes"]["chain"]
    # upstream_timestamp in proof dict
    assert proof_with.get("upstream_timestamp") == upstream_ts
    # Both must verify
    assert verify_proof_integrity(proof_with) is True
    assert verify_proof_integrity(proof_without) is True


def test_verify_proof_integrity_old_format_still_works():
    """Legacy proofs (no upstream_timestamp, no spec_version) still verify."""
    from trust_layer.proofs import sha256_hex, canonical_json
    # Build a legacy proof manually (as stored before this change)
    request_data = {"target": "https://legacy.com"}
    response_data = {"data": 42}
    payment_data = {"transaction_id": "pi_legacy"}
    timestamp = "2025-12-01T00:00:00Z"

    req_hash = sha256_hex(canonical_json(request_data))
    resp_hash = sha256_hex(canonical_json(response_data))
    chain_input = req_hash + resp_hash + "pi_legacy" + timestamp + "" + ""
    chain_hash = sha256_hex(chain_input)

    legacy_proof = {
        "hashes": {
            "request": f"sha256:{req_hash}",
            "response": f"sha256:{resp_hash}",
            "chain": f"sha256:{chain_hash}",
        },
        "certification_fee": {"transaction_id": "pi_legacy"},
        "parties": {"buyer_fingerprint": "", "seller": ""},
        "timestamp": timestamp,
        # No spec_version, no upstream_timestamp
    }
    assert verify_proof_integrity(legacy_proof) is True


def test_get_public_proof_includes_new_fields():
    """Public proof includes spec_version, upstream_timestamp, signature, pubkey."""
    proof = {
        "proof_id": "prf_new",
        "spec_version": "1.0",
        "hashes": {"request": "sha256:a", "response": "sha256:b", "chain": "sha256:c"},
        "certification_fee": {"transaction_id": "pi_x", "amount": 1, "currency": "eur", "status": "succeeded",
                     "receipt_url": "url", "method": "stripe"},
        "timestamp": "2026-02-26T10:00:00Z",
        "upstream_timestamp": "Thu, 26 Feb 2026 10:00:01 GMT",
        "arkforge_signature": "ed25519:fakesig",
        "arkforge_pubkey": "ed25519:fakepub",
    }
    public = get_public_proof(proof)
    assert public["spec_version"] == "1.0"
    assert public["upstream_timestamp"] == "Thu, 26 Feb 2026 10:00:01 GMT"
    assert public["arkforge_signature"] == "ed25519:fakesig"
    assert public["arkforge_pubkey"] == "ed25519:fakepub"



def test_get_public_proof_includes_transparency_log():
    """get_public_proof must include transparency_log field."""
    tlog = {
        "provider": "sigstore-rekor",
        "status": "verified",
        "uuid": "abc123",
        "log_index": 99,
        "integrated_time": 1709500000,
        "log_url": "https://rekor.sigstore.dev/api/v1/log/entries/abc123",
        "verify_url": "https://search.sigstore.dev/?logIndex=99",
    }
    proof = {
        "proof_id": "prf_rekor_test",
        "hashes": {"request": "sha256:a", "response": "sha256:b", "chain": "sha256:c"},
        "transparency_log": tlog,
    }
    public = get_public_proof(proof)
    assert public["transparency_log"] == tlog


def test_get_public_proof_transparency_log_none():
    """get_public_proof returns transparency_log=None when field is absent."""
    proof = {"proof_id": "prf_no_rekor", "hashes": {}}
    public = get_public_proof(proof)
    assert public["transparency_log"] is None
