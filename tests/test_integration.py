"""End-to-end integration tests via FastAPI TestClient."""

import json
from unittest.mock import patch, AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from trust_layer.app import app
from trust_layer.keys import create_api_key
from trust_layer.payments.base import ChargeResult


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def api_key():
    return create_api_key("cus_integ_test", "ref_integ_test", "integ@test.com", test_mode=True)


def _mock_proxy_deps():
    """Patch payment provider and HTTP client for integration tests."""
    mock_charge = ChargeResult(
        provider="stripe", transaction_id="pi_integ_test",
        amount=0.50, currency="eur", status="succeeded",
        receipt_url="https://pay.stripe.com/receipts/integ",
    )
    mock_provider = AsyncMock()
    mock_provider.charge.return_value = mock_charge

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"scanned": True, "frameworks": ["pytorch"]}

    mock_http = AsyncMock()
    mock_http.post.return_value = mock_response
    mock_http.__aenter__ = AsyncMock(return_value=mock_http)
    mock_http.__aexit__ = AsyncMock(return_value=None)

    return mock_provider, mock_http


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
    assert "proxy" in data
    assert "eur" in data["proxy"]["currencies"]


# --- Proxy ---

def test_proxy_no_auth(client):
    r = client.post("/v1/proxy", json={"target": "https://example.com", "amount": 0.50, "payload": {}})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_api_key"


def test_proxy_invalid_key(client):
    r = client.post(
        "/v1/proxy",
        json={"target": "https://example.com", "amount": 0.50, "payload": {}},
        headers={"Authorization": "Bearer mcp_test_invalid_000"},
    )
    assert r.status_code == 401


def test_proxy_missing_target(client, api_key):
    r = client.post(
        "/v1/proxy",
        json={"amount": 0.50, "payload": {}},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_target"


def test_proxy_invalid_currency(client, api_key):
    r = client.post(
        "/v1/proxy",
        json={"target": "https://example.com", "amount": 0.50, "currency": "btc", "payload": {}},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_currency"


def test_proxy_amount_too_low(client, api_key):
    r = client.post(
        "/v1/proxy",
        json={"target": "https://example.com", "amount": 0.10, "payload": {}},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_amount"


def test_proxy_amount_too_high(client, api_key):
    r = client.post(
        "/v1/proxy",
        json={"target": "https://example.com", "amount": 100.0, "payload": {}},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_amount"


def test_proxy_http_target_rejected(client, api_key):
    r = client.post(
        "/v1/proxy",
        json={"target": "http://example.com", "amount": 0.50, "payload": {}},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_target"


def test_proxy_private_ip_rejected(client, api_key):
    r = client.post(
        "/v1/proxy",
        json={"target": "https://192.168.1.1/api", "amount": 0.50, "payload": {}},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    assert r.status_code == 400


def test_proxy_full_success(client, api_key):
    mock_provider, mock_http = _mock_proxy_deps()

    with patch("trust_layer.proxy.get_provider", return_value=mock_provider), \
         patch("httpx.AsyncClient", return_value=mock_http), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        r = client.post(
            "/v1/proxy",
            json={
                "target": "https://example.com/api/scan",
                "amount": 0.50,
                "payload": {"repo_url": "https://github.com/test/repo"},
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )

    assert r.status_code == 200
    data = r.json()
    assert "proof" in data
    assert "service_response" in data
    assert data["proof"]["proof_id"].startswith("prf_")
    assert data["service_response"]["status_code"] == 200

    # Check X-ArkForge-Proof header
    assert "x-arkforge-proof" in r.headers


# --- Proof verification ---

def test_proof_not_found(client):
    r = client.get("/v1/proof/prf_nonexistent")
    assert r.status_code == 404


def test_proof_verification_after_proxy(client, api_key):
    """Full flow: proxy call → verify proof."""
    mock_provider, mock_http = _mock_proxy_deps()

    with patch("trust_layer.proxy.get_provider", return_value=mock_provider), \
         patch("httpx.AsyncClient", return_value=mock_http), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        r = client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "amount": 0.50, "payload": {}},
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

def test_ots_not_found(client):
    r = client.get("/v1/proof/prf_nonexistent/ots")
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


# --- Webhook ---

def test_webhook_invalid_json(client):
    r = client.post(
        "/v1/webhooks/stripe",
        content=b"not json",
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 400
