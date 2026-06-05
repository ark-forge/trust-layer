"""Tests for POST /v1/verdict/tier-upgrade (CTEF Row 8)."""

import base64
import hashlib
import json

import pytest

from trust_layer.crypto import generate_keypair, load_signing_key, verify_jws
from trust_layer.ctef import build_tier_upgrade_verdict, GATEWAY_DID, KEY_ID


# ---------------------------------------------------------------------------
# Unit — ctef module
# ---------------------------------------------------------------------------

@pytest.fixture
def test_key(tmp_path):
    path = tmp_path / "test_key.pem"
    generate_keypair(path)
    return load_signing_key(path)


def _pub_b64(key):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    raw = key.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _make_verdict(key, **kwargs):
    defaults = dict(
        requester_did="did:web:requester.example",
        current_tier="T1",
        requested_tier="T2",
        facet="scope.scheduling.write",
        limit=1,
        actual=0,
        session_id="session:test-001",
        policy_ref="sha256:" + "a" * 64,
    )
    defaults.update(kwargs)
    return build_tier_upgrade_verdict(private_key=key, **defaults)


def test_build_verdict_keys(test_key):
    r = _make_verdict(test_key)
    assert set(r) == {"ctef_envelope", "envelope_sha256", "envelope_jcs_bytes", "verdict_jws"}


def test_ctef_envelope_structure(test_key):
    r = _make_verdict(test_key)
    env = r["ctef_envelope"]
    assert env["claim_type"] == "authority"
    assert env["claim_subtype"] == "tier_upgrade"
    assert env["issuer"] == GATEWAY_DID
    proof = env["tier_upgrade_proof"]
    assert proof["from_tier"] == "T1"
    assert proof["to_tier"] == "T2"
    assert proof["approval_evidence"]["approver_did"] == GATEWAY_DID
    assert proof["approval_evidence"]["verdict_jws"] == r["verdict_jws"]


def test_jcs_hash_matches(test_key):
    r = _make_verdict(test_key)
    canonical = json.dumps(
        r["ctef_envelope"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == r["envelope_sha256"]
    assert len(canonical) == r["envelope_jcs_bytes"]


def test_jws_signature_verifiable(test_key):
    r = _make_verdict(test_key)
    payload = verify_jws(_pub_b64(test_key), r["verdict_jws"])
    assert payload["certified"] is True
    assert payload["issuer_did"] == GATEWAY_DID
    assert payload["requester_did"] == "did:web:requester.example"
    assert payload["scope_boundary"] == "session:test-001"
    assert payload["constraint_evaluation"]["delta"] == 1


def test_kid_binding(test_key):
    r = _make_verdict(test_key)
    h_b64 = r["verdict_jws"].split(".")[0]
    pad = 4 - len(h_b64) % 4
    header = json.loads(base64.urlsafe_b64decode(h_b64 + ("=" * pad if pad != 4 else "")))
    assert header["alg"] == "EdDSA"
    assert header["kid"] == KEY_ID
    assert header["kid"].startswith(GATEWAY_DID)


def test_tampered_signature_rejected(test_key):
    from cryptography.exceptions import InvalidSignature
    r = _make_verdict(test_key)
    parts = r["verdict_jws"].split(".")
    # flip last byte of signature
    sig = base64.urlsafe_b64decode(parts[2] + "==")
    bad_sig = sig[:-1] + bytes([sig[-1] ^ 0xFF])
    bad_token = f"{parts[0]}.{parts[1]}.{base64.urlsafe_b64encode(bad_sig).rstrip(b'=').decode()}"
    with pytest.raises((InvalidSignature, Exception)):
        verify_jws(_pub_b64(test_key), bad_token)


# ---------------------------------------------------------------------------
# Integration — HTTP endpoint
# ---------------------------------------------------------------------------

@pytest.fixture
def api_key():
    from trust_layer.keys import create_api_key
    return create_api_key("cus_test", "ref_test", test_mode=True)


def test_endpoint_happy_path(client, api_key):
    resp = client.post("/v1/verdict/tier-upgrade", json={
        "requester_did": "did:web:agent.example",
        "current_tier": "T1",
        "requested_tier": "T2",
        "facet": "scope.scheduling.write",
        "limit": 1,
        "actual": 0,
        "session_id": "session:http-test-001",
    }, headers={"X-Api-Key": api_key})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["gateway_did"] == GATEWAY_DID
    assert "ctef_envelope" in data
    assert data["ctef_envelope"]["claim_type"] == "authority"
    assert "envelope_sha256" in data
    assert "verdict_jws" in data


def test_endpoint_bearer_auth(client, api_key):
    resp = client.post("/v1/verdict/tier-upgrade", json={
        "requester_did": "did:web:a.example",
        "current_tier": "T1",
        "requested_tier": "T2",
        "facet": "scope.read",
        "limit": 10,
        "session_id": "session:bearer",
    }, headers={"Authorization": f"Bearer {api_key}"})
    assert resp.status_code == 200


def test_endpoint_auto_policy_ref(client, api_key):
    resp = client.post("/v1/verdict/tier-upgrade", json={
        "requester_did": "did:web:a.example",
        "current_tier": "T1",
        "requested_tier": "T2",
        "facet": "scope.read",
        "limit": 10,
        "session_id": "session:policy-auto",
    }, headers={"X-Api-Key": api_key})
    assert resp.status_code == 200
    policy_ref = resp.json()["ctef_envelope"]["tier_upgrade_proof"]["approval_evidence"]["policy_ref"]
    assert policy_ref.startswith("sha256:")


def test_endpoint_t2_to_t3(client, api_key):
    resp = client.post("/v1/verdict/tier-upgrade", json={
        "requester_did": "did:web:a.example",
        "current_tier": "T2",
        "requested_tier": "T3",
        "facet": "scope.admin",
        "limit": 5,
        "session_id": "session:t2t3",
    }, headers={"X-Api-Key": api_key})
    assert resp.status_code == 200


def test_endpoint_invalid_transition(client, api_key):
    resp = client.post("/v1/verdict/tier-upgrade", json={
        "requester_did": "did:web:a.example",
        "current_tier": "T1",
        "requested_tier": "T3",
        "facet": "scope.admin",
        "limit": 1,
        "session_id": "session:bad-trans",
    }, headers={"X-Api-Key": api_key})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "invalid_transition"


def test_endpoint_constraint_violation(client, api_key):
    resp = client.post("/v1/verdict/tier-upgrade", json={
        "requester_did": "did:web:a.example",
        "current_tier": "T1",
        "requested_tier": "T2",
        "facet": "scope.write",
        "limit": 1,
        "actual": 5,
        "session_id": "session:cv",
    }, headers={"X-Api-Key": api_key})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "constraint_violation"


def test_endpoint_missing_key(client):
    resp = client.post("/v1/verdict/tier-upgrade", json={
        "requester_did": "did:web:a.example",
        "current_tier": "T1",
        "requested_tier": "T2",
        "facet": "scope.read",
        "limit": 1,
        "session_id": "session:noauth",
    })
    assert resp.status_code == 401


def test_endpoint_invalid_key(client):
    resp = client.post("/v1/verdict/tier-upgrade", json={
        "requester_did": "did:web:a.example",
        "current_tier": "T1",
        "requested_tier": "T2",
        "facet": "scope.read",
        "limit": 1,
        "session_id": "session:badkey",
    }, headers={"X-Api-Key": "mcp_pro_notarealkey"})
    assert resp.status_code == 401
