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
