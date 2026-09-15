"""Tests for POST /v1/demo — public demo endpoint."""

from unittest.mock import patch, AsyncMock
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from trust_layer.app import app
    return TestClient(app)


@pytest.fixture(autouse=True)
def _reset_demo_fallback():
    """Reset in-memory rate-limit counter between tests (shared module state)."""
    from trust_layer import demo as demo_mod
    demo_mod._demo_fallback.clear()
    yield
    demo_mod._demo_fallback.clear()


_DEMO_BODY = {"target": "https://api.openai.com/v1/chat/completions", "payload": {"model": "gpt-4"}}


def test_demo_returns_200_with_proof_id(client):
    with patch("trust_layer.app._post_proof_background", new=AsyncMock()), \
         patch("trust_layer.app._track_task"):
        r = client.post("/v1/demo", json=_DEMO_BODY)
    assert r.status_code == 200
    data = r.json()
    assert data["is_demo"] is True
    assert data["proof_id"].startswith("prf_")
    assert data["verify_url"].endswith(data["proof_id"])
    assert data["tsa_status"] == "pending"
    assert data["rekor_status"] == "pending"
    assert "signup_url" in data["next_step"]


def test_demo_proof_stored_and_verifiable(client):
    with patch("trust_layer.app._post_proof_background", new=AsyncMock()), \
         patch("trust_layer.app._track_task"):
        r = client.post("/v1/demo", json=_DEMO_BODY)
    proof_id = r.json()["proof_id"]

    r2 = client.get(f"/v1/proof/{proof_id}")
    assert r2.status_code == 200
    data = r2.json()
    assert data["is_demo"] is True
    assert "demo_notice" in data
    assert data["integrity_verified"] is True


def test_demo_signature_present(client):
    with patch("trust_layer.app._post_proof_background", new=AsyncMock()), \
         patch("trust_layer.app._track_task"):
        r = client.post("/v1/demo", json=_DEMO_BODY)
    data = r.json()
    assert data["signature"].startswith("ed25519:")
    assert data["pubkey"].startswith("ed25519:")


def test_demo_signature_cryptographically_valid(client):
    from trust_layer.crypto import verify_proof_signature
    from trust_layer.config import ARKFORGE_PUBLIC_KEY
    with patch("trust_layer.app._post_proof_background", new=AsyncMock()), \
         patch("trust_layer.app._track_task"):
        r = client.post("/v1/demo", json=_DEMO_BODY)
    data = r.json()
    proof_id = data["proof_id"]

    r2 = client.get(f"/v1/proof/{proof_id}")
    chain_hash = r2.json()["hashes"]["chain"].replace("sha256:", "")
    assert verify_proof_signature(ARKFORGE_PUBLIC_KEY, chain_hash, data["signature"])


def test_demo_missing_target_returns_400(client):
    r = client.post("/v1/demo", json={"payload": {}})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_target"


def test_demo_payload_too_large_returns_400(client):
    large_payload = {"data": "x" * 5000}
    r = client.post("/v1/demo", json={"target": "https://api.openai.com", "payload": large_payload})
    assert r.status_code == 400
    assert r.json()["error"] == "payload_too_large"


def test_demo_rate_limit(client):
    """11th request from same IP should get 429."""
    from trust_layer import demo as demo_mod
    # conftest already neutralizes Redis (returns None) — fallback in-memory kicks in.
    # TestClient sends requests from host "testclient".
    demo_mod._demo_fallback["testclient"] = []

    with patch("trust_layer.app._post_proof_background", new=AsyncMock()), \
         patch("trust_layer.app._track_task"):
        for _ in range(10):
            r = client.post("/v1/demo", json=_DEMO_BODY)
            assert r.status_code == 200
        r_limited = client.post("/v1/demo", json=_DEMO_BODY)

    assert r_limited.status_code == 429
    data = r_limited.json()
    assert data["error"] == "rate_limited"
    assert "retry_after_seconds" in data


def test_demo_no_auth_required(client):
    """No API key header needed — endpoint is fully public."""
    with patch("trust_layer.app._post_proof_background", new=AsyncMock()), \
         patch("trust_layer.app._track_task"):
        r = client.post("/v1/demo", json=_DEMO_BODY)
    assert r.status_code == 200


def test_demo_invalid_json_returns_400(client):
    r = client.post("/v1/demo", content=b"not-json", headers={"Content-Type": "application/json"})
    assert r.status_code == 400


def test_proof_page_says_anchoring_is_in_progress_not_broken(client):
    """A proof waiting for its batch is not a failed proof, and the page must not
    look like one — the demo page is where a prospect first sees the product."""
    from trust_layer.templates import render_proof_page
    proof = {"proof_id": "prf_20260913_120000_aaaaaa", "spec_version": "3.0",
             "hashes": {"chain": "sha256:" + "ab" * 32},
             "parties": {"seller": "demo"}, "certification_fee": {"method": "none"},
             "timestamp": "2026-09-13T12:00:00+00:00",
             "timestamp_authority": {"status": "pending_batch"},
             "batch_anchor": {"status": "pending", "batch_id": "batch_x"}}
    html = render_proof_page(proof, integrity_verified=True)
    assert "ANCHORING IN PROGRESS" in html
    assert "within 10 minutes" in html
    assert "INTEGRITY CHECK FAILED" not in html


def test_proof_page_still_says_failed_when_integrity_is_broken(client):
    """The waiting state must not swallow a real failure."""
    from trust_layer.templates import render_proof_page
    proof = {"proof_id": "prf_20260913_120000_aaaaaa", "spec_version": "3.0",
             "hashes": {"chain": "sha256:" + "ab" * 32},
             "parties": {"seller": "demo"}, "certification_fee": {"method": "none"},
             "timestamp": "2026-09-13T12:00:00+00:00",
             "timestamp_authority": {"status": "pending_batch"},
             "batch_anchor": {"status": "pending"}}
    html = render_proof_page(proof, integrity_verified=False)
    assert "INTEGRITY CHECK FAILED" in html


def test_verified_free_tier_proof_page_claims_no_payment(client):
    """A free-tier proof records no payment by anyone. Its page must not say the
    action was paid, nor sell the proof as dispute-proof."""
    from trust_layer.templates import render_proof_page
    proof = {"proof_id": "prf_20260913_120000_aaaaaa", "spec_version": "3.1",
             "hashes": {"chain": "sha256:" + "ab" * 32},
             "parties": {"seller": "api.example.com"},
             "certification_fee": {"method": "none", "status": "free_tier"},
             "timestamp": "2026-09-13T12:00:00+00:00",
             "timestamp_authority": {"status": "verified"},
             "batch_anchor": {"status": "anchored"}}
    html = render_proof_page(proof, integrity_verified=True)
    assert "paid" not in html.lower()
    assert "dispute-proof" not in html.lower()


def test_proof_page_describes_the_commitment_algorithm_for_spec_3(client):
    """From spec 3.0 the chain hash is a Merkle root of per-field commitments
    (proof-spec section 2). Showing the legacy concatenation formula would send a
    verifier to the wrong algorithm."""
    from trust_layer.templates import render_proof_page
    proof = {"proof_id": "prf_20260913_120000_aaaaaa", "spec_version": "3.1",
             "hashes": {"chain": "sha256:" + "ab" * 32},
             "parties": {"seller": "api.example.com"},
             "certification_fee": {"method": "none", "status": "free_tier"},
             "timestamp": "2026-09-13T12:00:00+00:00",
             "timestamp_authority": {"status": "verified"},
             "batch_anchor": {"status": "anchored"}}
    html = render_proof_page(proof, integrity_verified=True)
    assert "Merkle root" in html
    assert "payment_id" not in html


def test_anchored_proof_page_does_not_call_the_record_immutable(client):
    """Rekor makes later changes detectable; it does not make anything immutable."""
    from trust_layer.templates import render_proof_page
    proof = {"proof_id": "prf_20260913_120000_aaaaaa", "spec_version": "3.1",
             "hashes": {"chain": "sha256:" + "ab" * 32},
             "parties": {"seller": "api.example.com"},
             "certification_fee": {"method": "none", "status": "free_tier"},
             "timestamp": "2026-09-13T12:00:00+00:00",
             "timestamp_authority": {"status": "verified"},
             "transparency_log": {"status": "verified", "log_index": 2834496977},
             "batch_anchor": {"status": "anchored"}}
    html = render_proof_page(proof, integrity_verified=True)
    assert "immutabl" not in html.lower()
    assert "cannot be altered" not in html.lower()


def test_agent_card_does_not_overstate_witnesses(client):
    """The agent card is read by other agents: it must not count ArkForge's own
    signature as an independent witness, nor call proofs immutable."""
    r = client.get("/.well-known/agent.json")
    assert r.status_code == 200
    text = r.text.lower()
    assert "3 independent" not in text
    assert "immutable" not in text
