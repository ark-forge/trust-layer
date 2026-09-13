"""Per-field commitments and selective disclosure — spec 3.0.

The interesting assertions here are the negatives. A commitment scheme that has
never refused a forged opening measures nothing: for every property claimed
(binding, hiding, domain separation, per-field nonces) there is a witness that
must fail.
"""

import json

import pytest

from trust_layer.commitments import (
    NONCE_BYTES,
    build_commitments,
    commit,
    commitments_root,
    disclosure_bundle,
    verify_disclosure,
)
from trust_layer.merkle import leaf_hash, merkle_root
from trust_layer.proofs import (
    canonical_json,
    generate_proof,
    get_full_proof,
    get_public_proof,
    verify_proof_integrity,
)

CHAIN_DATA = {
    "request_hash": "a" * 64,
    "response_hash": "b" * 64,
    "transaction_id": "pi_3PfakeXXXX",
    "timestamp": "2026-09-13T10:00:00+00:00",
    "buyer_fingerprint": "c" * 64,
    "seller": "api.example.com",
}


def test_root_is_merkle_of_sorted_field_commitments():
    commitments, _, root = build_commitments(CHAIN_DATA)
    leaves = [leaf_hash(bytes.fromhex(commitments[f].replace("sha256:", "")))
              for f in sorted(commitments)]
    assert root == merkle_root(leaves).hex()


def test_nonces_are_per_field_and_per_proof():
    """A shared nonce would let one disclosure brute-force low-entropy neighbours."""
    _, nonces_a, root_a = build_commitments(CHAIN_DATA)
    commitments_b, nonces_b, root_b = build_commitments(CHAIN_DATA)
    assert len(set(nonces_a.values())) == len(nonces_a)          # per field
    assert not set(nonces_a.values()) & set(nonces_b.values())   # per proof
    assert root_a != root_b
    assert all(len(bytes.fromhex(n)) == NONCE_BYTES for n in nonces_a.values())


def test_equal_values_in_two_proofs_do_not_produce_equal_commitments():
    a, _, _ = build_commitments(CHAIN_DATA)
    b, _, _ = build_commitments(CHAIN_DATA)
    assert a["seller"] != b["seller"]


def test_disclosure_accepts_the_true_value():
    commitments, nonces, _ = build_commitments(CHAIN_DATA)
    assert verify_disclosure("seller", nonces["seller"], "api.example.com", commitments["seller"])


def test_disclosure_refuses_a_forged_value():
    commitments, nonces, _ = build_commitments(CHAIN_DATA)
    assert not verify_disclosure("seller", nonces["seller"], "evil.example.com", commitments["seller"])


def test_disclosure_refuses_a_commitment_moved_between_fields():
    """Domain separation: the field name is in the preimage."""
    data = dict(CHAIN_DATA, request_hash="same", response_hash="same")
    commitments, nonces, _ = build_commitments(data)
    assert verify_disclosure("request_hash", nonces["request_hash"], "same", commitments["request_hash"])
    assert not verify_disclosure("response_hash", nonces["request_hash"], "same", commitments["request_hash"])


def test_disclosure_refuses_a_wrong_nonce():
    commitments, nonces, _ = build_commitments(CHAIN_DATA)
    assert not verify_disclosure("seller", nonces["timestamp"], "api.example.com", commitments["seller"])


def test_disclosure_refuses_a_type_confusion():
    """canonical_json, not str(): 100 and "100" must not open the same commitment."""
    data = dict(CHAIN_DATA, amount=100)
    commitments, nonces, _ = build_commitments(data)
    assert verify_disclosure("amount", nonces["amount"], 100, commitments["amount"])
    assert not verify_disclosure("amount", nonces["amount"], "100", commitments["amount"])


def test_disclosure_refuses_malformed_input():
    commitments, nonces, _ = build_commitments(CHAIN_DATA)
    assert not verify_disclosure("seller", "zz", "api.example.com", commitments["seller"])
    assert not verify_disclosure("seller", nonces["seller"], "api.example.com", "sha256:beef")
    assert not verify_disclosure("seller", nonces["seller"][:32], "api.example.com", commitments["seller"])


def test_commit_refuses_a_short_nonce():
    with pytest.raises(ValueError):
        commit("seller", b"\x00" * 16, "x")


def test_empty_commitments_have_no_root():
    with pytest.raises(ValueError):
        commitments_root({})


def test_generated_proof_is_spec_3_and_self_verifies():
    proof = generate_proof({"t": 1}, {"r": "ok"},
                           {"transaction_id": "pi_x"}, "2026-09-13T10:00:00+00:00",
                           buyer_fingerprint="f" * 64, seller="api.example.com")
    assert proof["spec_version"] == "3.0"
    assert proof["hashes"]["chain"] == f"sha256:{commitments_root(proof['commitments'])}"
    assert verify_proof_integrity(proof)


def test_integrity_fails_when_a_commitment_is_altered():
    proof = generate_proof({"t": 1}, {"r": "ok"}, {"transaction_id": "pi_x"},
                           "2026-09-13T10:00:00+00:00", seller="s")
    proof["commitments"]["seller"] = "sha256:" + "0" * 64
    assert not verify_proof_integrity(proof)


def test_integrity_fails_when_a_value_is_altered_under_its_commitment():
    """Internally we hold nonces and values, so a swapped value is caught."""
    proof = generate_proof({"t": 1}, {"r": "ok"}, {"transaction_id": "pi_x"},
                           "2026-09-13T10:00:00+00:00", seller="s")
    proof["_chain_data"]["seller"] = "other"
    assert not verify_proof_integrity(proof)


def test_public_proof_publishes_commitments_and_no_preimage():
    proof = generate_proof({"t": 1}, {"r": "ok"},
                           {"transaction_id": "pi_secret_value"}, "2026-09-13T10:00:00+00:00",
                           buyer_fingerprint="f" * 64, seller="api.example.com")
    public = get_public_proof(proof)
    blob = json.dumps(public)
    assert public["commitments"]
    assert "pi_secret_value" not in blob
    assert "f" * 64 not in blob
    assert "commitment_nonces" not in public and "_commitment_nonces" not in blob
    # and the chain hash is recomputable from what IS published
    assert commitments_root(public["commitments"]) == public["hashes"]["chain"].replace("sha256:", "")


def test_public_proof_keys_are_purely_additive():
    """Spec 3.0 changes nothing that was public; it makes what is public sufficient."""
    proof = generate_proof({"t": 1}, {"r": "ok"}, {"transaction_id": "pi_x"},
                           "2026-09-13T10:00:00+00:00", seller="s")
    before = {
        "proof_id", "is_demo", "spec_version", "hashes", "timestamp_authority", "timestamp",
        "upstream_timestamp", "verification_algorithm", "arkforge_signature", "arkforge_pubkey",
        "identity_consistent", "views_count", "transaction_success", "upstream_status_code",
        "disputed", "dispute_id", "transparency_log", "agent_identity",
        "agent_identity_verified", "did_resolution_status", "seller", "provider_payment",
    }
    assert before <= set(get_public_proof(proof))


def test_owner_gets_the_disclosure_material():
    proof = generate_proof({"t": 1}, {"r": "ok"}, {"transaction_id": "pi_x"},
                           "2026-09-13T10:00:00+00:00", seller="api.example.com")
    full = get_full_proof(proof)
    nonces, chain_data = full["commitment_nonces"], full["chain_data"]
    bundle = disclosure_bundle(nonces, chain_data, ["seller"])
    assert set(bundle["disclosed"]) == {"seller"}
    item = bundle["disclosed"]["seller"]
    assert verify_disclosure("seller", item["nonce"], item["value"], proof["commitments"]["seller"])
    # Disclosing one field reveals nothing about the others
    assert "pi_x" not in json.dumps(bundle)
