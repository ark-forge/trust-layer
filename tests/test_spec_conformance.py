"""Conformance tests against the ArkForge Proof Specification.

Reads test vectors from the local proof-spec repo (preferred) or GitHub,
and validates that the Trust Layer implementation produces identical results.

If this test fails, either the spec or the implementation has drifted.
"""

import json
import hashlib
import urllib.request
from pathlib import Path

import pytest

from trust_layer.commitments import commit, commitments_root
from trust_layer.merkle import inclusion_root, leaf_hash, merkle_root
from trust_layer.proofs import canonical_json, sha256_hex

# Local proof-spec repo (preferred — always in sync)
VECTORS_LOCAL = Path(__file__).parent.parent.parent / "proof-spec" / "test-vectors.json"

# Fallback: GitHub raw URL
VECTORS_URL = "https://raw.githubusercontent.com/ark-forge/proof-spec/main/test-vectors.json"


def _load_vectors():
    """Load test vectors from local proof-spec repo, fall back to GitHub."""
    if VECTORS_LOCAL.exists():
        return json.loads(VECTORS_LOCAL.read_text())
    try:
        with urllib.request.urlopen(VECTORS_URL, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception:
        pass
    # Inline fallback (last known good — minimal_transaction only)
    return {
        "vectors": [
            {
                "name": "minimal_transaction",
                "input": {
                    "request": {"repo_url": "https://github.com/example/app"},
                    "response": {"files_scanned": 42, "frameworks": ["openai"]},
                    "payment_intent_id": "pi_test_abc123",
                    "timestamp": "2026-01-15T12:00:00Z",
                    "api_key": "mcp_test_example_key",
                    "seller": "arkforge.fr",
                },
                "expected": {
                    "canonical_request": "{\"repo_url\":\"https://github.com/example/app\"}",
                    "canonical_response": "{\"files_scanned\":42,\"frameworks\":[\"openai\"]}",
                    "request_hash": "0987aa49eb45583406b66c77ea6f35498bd318b81040bec9c54ab439114abe42",
                    "response_hash": "bad7c7f7f632182e9d746c9a4a02aea5f526a6a76c5108c4a98a7c4823fdbef2",
                    "buyer_fingerprint": "7c8f263e06d5ce4681f750ad64ede882a4ebd87de60f9ae0e6b06f0300645a11",
                    "chain_hash": "2f8bf97e19c9743ca386830a2219be84ff5411ae83f54e5aaf390f7d2215c431",
                },
            }
        ]
    }


_vectors_data = _load_vectors()

# The batch-anchor vector has no request/response and no api_key: it covers the tree
# over several chain hashes, not one proof's fields.
_PROOF_VECTORS = [v for v in _vectors_data["vectors"] if v.get("algorithm") != "batch_merkle"]
_BATCH_VECTORS = [v for v in _vectors_data["vectors"] if v.get("algorithm") == "batch_merkle"]


@pytest.mark.parametrize(
    "vector", _PROOF_VECTORS, ids=[v["name"] for v in _PROOF_VECTORS],
)
def test_canonical_json_and_hashes(vector):
    """Verify canonical JSON + request/response hashes match spec vectors."""
    inp = vector["input"]
    expected = vector["expected"]

    canonical_req = canonical_json(inp["request"])
    canonical_resp = canonical_json(inp["response"])

    assert canonical_req == expected["canonical_request"], f"Canonical request mismatch for {vector['name']}"
    assert canonical_resp == expected["canonical_response"], f"Canonical response mismatch for {vector['name']}"

    assert sha256_hex(canonical_req) == expected["request_hash"]
    assert sha256_hex(canonical_resp) == expected["response_hash"]


@pytest.mark.parametrize(
    "vector", _PROOF_VECTORS, ids=[v["name"] for v in _PROOF_VECTORS],
)
def test_buyer_fingerprint(vector):
    """Verify buyer fingerprint derivation."""
    api_key = vector["input"]["api_key"]
    expected_fp = vector["expected"]["buyer_fingerprint"]
    assert sha256_hex(api_key) == expected_fp


@pytest.mark.parametrize(
    "vector", _PROOF_VECTORS, ids=[v["name"] for v in _PROOF_VECTORS],
)
def test_chain_hash(vector):
    """Verify full chain hash computation matches spec."""
    inp = vector["input"]
    expected = vector["expected"]

    request_hash = sha256_hex(canonical_json(inp["request"]))
    response_hash = sha256_hex(canonical_json(inp["response"]))
    buyer_fingerprint = sha256_hex(inp["api_key"])

    algorithm = vector.get("algorithm", "legacy")

    if algorithm == "commitments":
        # Spec 3.0: the vector fixes the nonces so the result is reproducible.
        chain_data = {
            "request_hash": request_hash,
            "response_hash": response_hash,
            "transaction_id": inp["payment_intent_id"],
            "timestamp": inp["timestamp"],
            "buyer_fingerprint": buyer_fingerprint,
            "seller": inp["seller"],
        }
        if inp.get("upstream_timestamp"):
            chain_data["upstream_timestamp"] = inp["upstream_timestamp"]
        if inp.get("receipt_content_hash"):
            chain_data["receipt_content_hash"] = inp["receipt_content_hash"]
        assert chain_data == expected["chain_data"], f"Committed field set drifted for {vector['name']}"

        commitments = {f: commit(f, bytes.fromhex(inp["nonces"][f]), v).hex()
                       for f, v in chain_data.items()}
        assert commitments == expected["commitments"], f"Commitment mismatch for {vector['name']}"
        chain_hash = commitments_root(commitments)
    elif algorithm == "canonical_json":
        chain_data = {
            "buyer_fingerprint": buyer_fingerprint,
            "request_hash": request_hash,
            "response_hash": response_hash,
            "seller": inp["seller"],
            "timestamp": inp["timestamp"],
            "transaction_id": inp["payment_intent_id"],
        }
        if inp.get("upstream_timestamp"):
            chain_data["upstream_timestamp"] = inp["upstream_timestamp"]
        if inp.get("receipt_content_hash"):
            chain_data["receipt_content_hash"] = inp["receipt_content_hash"]
        chain_hash = sha256_hex(canonical_json(chain_data))
    else:
        chain_input = (
            request_hash
            + response_hash
            + inp["payment_intent_id"]
            + inp["timestamp"]
            + buyer_fingerprint
            + inp["seller"]
        )
        if inp.get("upstream_timestamp"):
            chain_input += inp["upstream_timestamp"]
        if inp.get("receipt_content_hash"):
            chain_input += inp["receipt_content_hash"]
        chain_hash = sha256_hex(chain_input)

    assert chain_hash == expected["chain_hash"], f"Chain hash mismatch for {vector['name']}"


@pytest.mark.parametrize(
    "vector", _BATCH_VECTORS, ids=[v["name"] for v in _BATCH_VECTORS],
)
def test_batch_anchor_tree(vector):
    """Spec 3.0 section 2.2: the batch root and every inclusion path.

    Same primitive one level up from the chain hash, so drift here would break the
    link between an individual proof and the hash that is actually anchored.
    """
    expected = vector["expected"]
    leaves = [leaf_hash(bytes.fromhex(c)) for c in vector["input"]["chain_hashes"]]

    assert len(leaves) == expected["tree_size"]
    assert merkle_root(leaves).hex() == expected["root"], "Batch root drifted from the spec"

    for item in expected["inclusion"]:
        i = item["leaf_index"]
        path = [bytes.fromhex(h) for h in item["audit_path"]]
        root, consumed = inclusion_root(leaves[i], i, expected["tree_size"], path)
        assert root.hex() == expected["root"], f"Inclusion path for leaf {i} misses the root"
        assert consumed == len(path), f"Inclusion path for leaf {i} carries unused siblings"
