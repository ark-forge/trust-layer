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


# --- /v1/keys/setup (payment mode) ---

def test_setup_key_payment_mode(client, monkeypatch):
    """Checkout session créée en mode payment avec montant et line_items."""
    import trust_layer.app as app_mod
    monkeypatch.setattr(app_mod, "STRIPE_TEST_KEY", "sk_test_fake")

    mock_customer = MagicMock()
    mock_customer.id = "cus_test_setup"
    mock_customer_list = MagicMock()
    mock_customer_list.data = []

    mock_session = MagicMock()
    mock_session.url = "https://checkout.stripe.com/pay/cs_test_xxx"
    mock_session.id = "cs_test_xxx"

    with patch("stripe.Customer.list", return_value=mock_customer_list), \
         patch("stripe.Customer.create", return_value=mock_customer), \
         patch("stripe.checkout.Session.create", return_value=mock_session) as mock_create:

        r = client.post("/v1/keys/setup", json={
            "email": "pro@test.com",
            "mode": "test",
            "amount": 10.0,
        })

    assert r.status_code == 200
    data = r.json()
    assert data["checkout_url"] == "https://checkout.stripe.com/pay/cs_test_xxx"
    assert data["amount"] == 10.0
    assert data["proofs_included"] == 100

    # Vérifier que le Checkout est en mode payment (pas setup)
    call_kwargs = mock_create.call_args.kwargs
    assert call_kwargs["mode"] == "payment"
    assert call_kwargs["line_items"][0]["price_data"]["unit_amount"] == 1000
    assert call_kwargs["payment_intent_data"]["setup_future_usage"] == "off_session"
    assert call_kwargs["metadata"]["product"] == "trust_layer_pro_setup"
    assert call_kwargs["metadata"]["credit_amount"] == "10.0"


def test_setup_key_amount_too_low(client, monkeypatch):
    """Montant inférieur au minimum rejeté (vérifié avant d'appeler Stripe)."""
    import trust_layer.app as app_mod
    monkeypatch.setattr(app_mod, "STRIPE_TEST_KEY", "sk_test_fake")
    r = client.post("/v1/keys/setup", json={
        "email": "pro@test.com",
        "mode": "test",
        "amount": 5.0,
    })
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_amount"


def test_setup_key_defaults_to_10(client, monkeypatch):
    """Sans amount, défaut à 10€."""
    import trust_layer.app as app_mod
    monkeypatch.setattr(app_mod, "STRIPE_TEST_KEY", "sk_test_fake")

    mock_customer = MagicMock()
    mock_customer.id = "cus_test_default"
    mock_customer_list = MagicMock()
    mock_customer_list.data = []

    mock_session = MagicMock()
    mock_session.url = "https://checkout.stripe.com/pay/cs_test_yyy"
    mock_session.id = "cs_test_yyy"

    with patch("stripe.Customer.list", return_value=mock_customer_list), \
         patch("stripe.Customer.create", return_value=mock_customer), \
         patch("stripe.checkout.Session.create", return_value=mock_session) as mock_create:

        r = client.post("/v1/keys/setup", json={"email": "pro@test.com", "mode": "test"})

    assert r.status_code == 200
    call_kwargs = mock_create.call_args.kwargs
    assert call_kwargs["line_items"][0]["price_data"]["unit_amount"] == 1000  # 10€


# --- Webhook checkout.session.completed — créditation Pro ---

def test_webhook_pro_setup_credits_account(client):
    """Webhook Pro setup: crée la clé ET crédite le compte."""
    from trust_layer.credits import get_balance

    event = {
        "type": "checkout.session.completed",
        "livemode": False,
        "data": {
            "object": {
                "customer": "cus_webhook_pro_test",
                "customer_details": {"email": "webhook_pro@test.com"},
                "payment_intent": "pi_webhook_pro_001",
                "subscription": None,
                "metadata": {
                    "product": "trust_layer_pro_setup",
                    "email": "webhook_pro@test.com",
                    "credit_amount": "10.0",
                },
            }
        },
    }

    with patch("trust_layer.app.send_welcome_email"):
        r = client.post(
            "/v1/webhooks/stripe",
            json=event,
            headers={"Content-Type": "application/json"},
        )

    assert r.status_code == 200
    assert r.json()["received"] is True

    # La clé a été créée — trouver via load_api_keys
    from trust_layer.keys import load_api_keys
    keys = load_api_keys()
    pro_key = None
    for key_str, info in keys.items():
        if info.get("email") == "webhook_pro@test.com":
            pro_key = key_str
            break

    assert pro_key is not None, "Pro API key not created by webhook"
    balance = get_balance(pro_key)
    assert balance == 10.0, f"Expected balance 10.0, got {balance}"


# --- /v1/keys/portal ---

def test_billing_portal(client, monkeypatch):
    """Retourne une URL Stripe Customer Portal."""
    import trust_layer.app as app_mod
    monkeypatch.setattr(app_mod, "STRIPE_TEST_KEY", "sk_test_fake")

    mock_portal = MagicMock()
    mock_portal.url = "https://billing.stripe.com/session/test_portal_xxx"

    with patch("stripe.billing_portal.Session.create", return_value=mock_portal) as mock_create:
        r = client.post("/v1/keys/portal", json={
            "customer_id": "cus_test_portal",
            "mode": "test",
        })

    assert r.status_code == 200
    data = r.json()
    assert data["portal_url"] == "https://billing.stripe.com/session/test_portal_xxx"
    assert data["customer_id"] == "cus_test_portal"

    mock_create.assert_called_once()
    call_kwargs = mock_create.call_args.kwargs
    assert call_kwargs["customer"] == "cus_test_portal"


def test_billing_portal_requires_customer_id(client):
    """customer_id manquant → 400."""
    r = client.post("/v1/keys/portal", json={"mode": "test"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_request"
