"""End-to-end integration tests via FastAPI TestClient."""

import json
from unittest.mock import patch, AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from trust_layer.app import app
from trust_layer.keys import create_api_key
from trust_layer.credits import add_credits
from trust_layer.config import PROOF_PRICE


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def api_key():
    key = create_api_key("cus_integ_test", "ref_integ_test", "integ@test.com", test_mode=True)
    add_credits(key, 10.00, "pi_integ_setup")
    return key


def _mock_http_client():
    """Patch HTTP client for integration tests."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"scanned": True, "frameworks": ["pytorch"]}
    mock_response.headers = {}

    mock_http = AsyncMock()
    mock_http.post.return_value = mock_response
    mock_http.__aenter__ = AsyncMock(return_value=mock_http)
    mock_http.__aexit__ = AsyncMock(return_value=None)

    return mock_http


# --- Health ---

def test_health(client):
    r = client.get("/v1/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["service"] == "arkforge-trust-layer"


# --- Pricing ---

def test_pricing(client):
    r = client.get("/v1/pricing")
    assert r.status_code == 200
    data = r.json()
    assert "plans" in data
    assert data["plans"]["pro"]["proof_price"] == f"{PROOF_PRICE} EUR"
    assert "buy_credits" in data["plans"]["pro"]


# --- Proxy ---

def test_proxy_no_auth(client):
    r = client.post("/v1/proxy", json={"target": "https://example.com", "payload": {}})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_api_key"


def test_proxy_invalid_key(client):
    r = client.post(
        "/v1/proxy",
        json={"target": "https://example.com", "payload": {}},
        headers={"Authorization": "Bearer mcp_test_invalid_000"},
    )
    assert r.status_code == 401


def test_proxy_missing_target(client, api_key):
    r = client.post(
        "/v1/proxy",
        json={"payload": {}},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_target"


def test_proxy_invalid_currency(client, api_key):
    r = client.post(
        "/v1/proxy",
        json={"target": "https://example.com", "currency": "btc", "payload": {}},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_currency"


def test_proxy_http_target_rejected(client, api_key):
    r = client.post(
        "/v1/proxy",
        json={"target": "http://example.com", "payload": {}},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_target"


def test_proxy_private_ip_rejected(client, api_key):
    r = client.post(
        "/v1/proxy",
        json={"target": "https://192.168.1.1/api", "payload": {}},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert r.status_code == 400


def test_proxy_insufficient_credits(client):
    """Pro key with no credits should get 402."""
    key = create_api_key("cus_no_credits", "ref_no_credits", "no@credits.com", test_mode=True)
    mock_http = _mock_http_client()

    with patch("httpx.AsyncClient", return_value=mock_http), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):
        r = client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "payload": {}},
            headers={"Authorization": f"Bearer {key}"},
        )

    assert r.status_code == 402
    assert r.json()["error"]["code"] == "insufficient_credits"


def test_proxy_full_success(client, api_key):
    mock_http = _mock_http_client()

    with patch("httpx.AsyncClient", return_value=mock_http), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        r = client.post(
            "/v1/proxy",
            json={
                "target": "https://example.com/api/scan",
                "payload": {"repo_url": "https://github.com/test/repo"},
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )

    assert r.status_code == 200
    data = r.json()
    assert "proof" in data
    assert "service_response" in data
    assert data["proof"]["proof_id"].startswith("prf_")
    assert data["proof"]["payment"]["provider"] == "prepaid_credit"
    assert data["service_response"]["status_code"] == 200

    # Check X-ArkForge-Proof header
    assert "x-arkforge-proof" in r.headers


# --- Proof verification ---

def test_proof_not_found(client):
    r = client.get("/v1/proof/prf_nonexistent")
    assert r.status_code == 404


def test_proof_verification_after_proxy(client, api_key):
    """Full flow: proxy call → verify proof."""
    mock_http = _mock_http_client()

    with patch("httpx.AsyncClient", return_value=mock_http), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        r = client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "payload": {}},
            headers={"Authorization": f"Bearer {api_key}"},
        )

    assert r.status_code == 200
    proof_id = r.json()["proof"]["proof_id"]

    # Verify proof
    r2 = client.get(f"/v1/proof/{proof_id}")
    assert r2.status_code == 200
    proof_data = r2.json()
    assert proof_data["integrity_verified"] is True
    assert proof_data["hashes"]["chain"].startswith("sha256:")


# --- OTS ---

def test_tsr_not_found(client):
    r = client.get("/v1/proof/prf_nonexistent/tsr")
    assert r.status_code == 404


# --- Usage ---

def test_usage_no_auth(client):
    r = client.get("/v1/usage")
    assert r.status_code == 401


def test_usage_with_key(client, api_key):
    r = client.get("/v1/usage", headers={"Authorization": f"Bearer {api_key}"})
    assert r.status_code == 200
    data = r.json()
    assert "daily" in data
    assert "used" in data["daily"]
    assert "remaining" in data["daily"]
    # Pro key should have credit info
    assert "credit_balance" in data
    assert "proofs_remaining" in data


# --- Pubkey ---

def test_pubkey_returns_valid_key(client):
    r = client.get("/v1/pubkey")
    assert r.status_code == 200
    data = r.json()
    assert data["algorithm"] == "Ed25519"
    assert data["pubkey"].startswith("ed25519:")
    # 32 bytes -> 43 chars base64url
    b64_part = data["pubkey"][len("ed25519:"):]
    assert len(b64_part) == 43


# --- Full flow with signature ---

def test_proxy_full_flow_has_signature_and_spec(client, api_key):
    """Full flow: proxy call produces proof with signature, spec_version, pubkey."""
    mock_http = _mock_http_client()
    # Add Date header to mock upstream response
    mock_http.post.return_value.headers = {"Date": "Thu, 26 Feb 2026 17:00:00 GMT"}

    with patch("httpx.AsyncClient", return_value=mock_http), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        r = client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "payload": {}},
            headers={"Authorization": f"Bearer {api_key}"},
        )

    assert r.status_code == 200
    proof = r.json()["proof"]
    assert proof["spec_version"] == "1.1"
    assert proof["arkforge_signature"].startswith("ed25519:")
    assert proof["arkforge_pubkey"].startswith("ed25519:")
    assert proof["upstream_timestamp"] == "Thu, 26 Feb 2026 17:00:00 GMT"

    # Verify signature externally
    from trust_layer.crypto import verify_proof_signature
    chain_hash = proof["hashes"]["chain"].replace("sha256:", "")
    assert verify_proof_signature(proof["arkforge_pubkey"], chain_hash, proof["arkforge_signature"])

    # Verify proof via GET endpoint includes new fields
    proof_id = proof["proof_id"]
    r2 = client.get(f"/v1/proof/{proof_id}")
    assert r2.status_code == 200
    public = r2.json()
    assert public["spec_version"] == "1.1"
    assert public["arkforge_signature"].startswith("ed25519:")
    assert public["upstream_timestamp"] == "Thu, 26 Feb 2026 17:00:00 GMT"


# --- Webhook ---

def test_webhook_invalid_json(client):
    r = client.post(
        "/v1/webhooks/stripe",
        content=b"not json",
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 400
