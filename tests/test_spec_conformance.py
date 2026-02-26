"""Conformance tests against ArkForge Proof Specification v1.

Reads test vectors from the proof-spec repo and validates that
the Trust Layer implementation produces identical results.

If this test fails, either the spec or the implementation has drifted.
"""

import json
import hashlib
import urllib.request

import pytest

from trust_layer.proofs import canonical_json, sha256_hex

# Test vectors URL — pinned to main branch
VECTORS_URL = "https://raw.githubusercontent.com/ark-forge/proof-spec/main/test-vectors.json"

# Fallback: local copy for offline testing
VECTORS_LOCAL = None


def _load_vectors():
    """Load test vectors from GitHub, fall back to inline."""
    try:
        with urllib.request.urlopen(VECTORS_URL, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception:
        pass
    # Inline fallback (last known good)
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
                    "request_hash": "0987aa49eb45583406b66c77ea6f35498bd318b81040bec9c54ab439114abe42",
                    "response_hash": "bad7c7f7f632182e9d746c9a4a02aea5f526a6a76c5108c4a98a7c4823fdbef2",
                    "buyer_fingerprint": "7c8f263e06d5ce4681f750ad64ede882a4ebd87de60f9ae0e6b06f0300645a11",
                    "chain_hash": "2f8bf97e19c9743ca386830a2219be84ff5411ae83f54e5aaf390f7d2215c431",
                },
            }
        ]
    }


_vectors_data = _load_vectors()


@pytest.mark.parametrize(
    "vector",
    _vectors_data["vectors"],
    ids=[v["name"] for v in _vectors_data["vectors"]],
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
    "vector",
    _vectors_data["vectors"],
    ids=[v["name"] for v in _vectors_data["vectors"]],
)
def test_buyer_fingerprint(vector):
    """Verify buyer fingerprint derivation."""
    api_key = vector["input"]["api_key"]
    expected_fp = vector["expected"]["buyer_fingerprint"]
    assert sha256_hex(api_key) == expected_fp


@pytest.mark.parametrize(
    "vector",
    _vectors_data["vectors"],
    ids=[v["name"] for v in _vectors_data["vectors"]],
)
def test_chain_hash(vector):
    """Verify full chain hash computation matches spec."""
    inp = vector["input"]
    expected = vector["expected"]

    request_hash = sha256_hex(canonical_json(inp["request"]))
    response_hash = sha256_hex(canonical_json(inp["response"]))
    buyer_fingerprint = sha256_hex(inp["api_key"])

    chain_input = (
        request_hash
        + response_hash
        + inp["payment_intent_id"]
        + inp["timestamp"]
        + buyer_fingerprint
        + inp["seller"]
    )
    chain_hash = sha256_hex(chain_input)

    assert chain_hash == expected["chain_hash"], f"Chain hash mismatch for {vector['name']}"
