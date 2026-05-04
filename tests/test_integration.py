"""End-to-end integration tests via FastAPI TestClient."""

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import patch, AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from trust_layer.app import app
from trust_layer.keys import create_api_key, update_overage_settings
from trust_layer.credits import add_credits
from trust_layer.config import (
    PROOF_PRICE,
    FREE_TIER_MONTHLY_LIMIT,
    PRO_MONTHLY_LIMIT,
    ENTERPRISE_MONTHLY_LIMIT,
    PLATFORM_MONTHLY_LIMIT,
    PRO_OVERAGE_PRICE,
    ENTERPRISE_OVERAGE_PRICE,
)
import trust_layer.rate_limit as _rl_mod  # for patched RATE_LIMITS_FILE at runtime
from trust_layer.persistence import load_json, save_json


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


def test_health_shows_environment(client, monkeypatch):
    import trust_layer.config as cfg
    monkeypatch.setattr(cfg, "TRUST_LAYER_ENV", "test")
    r = client.get("/v1/health")
    assert r.json()["environment"] == "test"


# --- Pricing ---

def test_pricing(client):
    r = client.get("/v1/pricing")
    assert r.status_code == 200
    data = r.json()
    assert "plans" in data

    # Free plan
    free = data["plans"]["free"]
    assert free["monthly_quota"] == FREE_TIER_MONTHLY_LIMIT
    assert free["overage"] is None
    assert free["credit_card_required"] is False
    assert "3" in free["witnesses"]

    # Pro plan
    pro = data["plans"]["pro"]
    assert pro["monthly_quota"] == PRO_MONTHLY_LIMIT
    assert pro["overage"] == f"{PRO_OVERAGE_PRICE} EUR/proof (opt-in)"
    assert "buy_credits" in pro
    assert "3" in pro["witnesses"]

    # Enterprise plan
    ent = data["plans"]["enterprise"]
    assert ent["monthly_quota"] == ENTERPRISE_MONTHLY_LIMIT
    assert ent["overage"] == f"{ENTERPRISE_OVERAGE_PRICE} EUR/proof (opt-in)"
    assert "QTSP" in ent["witnesses"]


def test_pricing_all_three_plans_present(client):
    r = client.get("/v1/pricing")
    plans = r.json()["plans"]
    assert set(plans.keys()) == {"free", "pro", "enterprise", "platform"}


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
    """Test key with no credits should succeed — test keys are internal, no charge."""
    key = create_api_key("cus_no_credits", "ref_no_credits", "no@credits.com", test_mode=True)
    mock_http = _mock_http_client()

    with patch("httpx.AsyncClient", return_value=mock_http), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):
        r = client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "payload": {}},
            headers={"Authorization": f"Bearer {key}"},
        )

    assert r.status_code == 200
    assert r.json()["proof"]["certification_fee"]["amount"] == 0.0


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
    assert data["proof"]["certification_fee"]["amount"] == 0.0
    assert data["service_response"]["status_code"] == 200

    # Check X-ArkForge-Proof header
    assert "x-arkforge-proof" in r.headers


# --- Proof verification ---

def test_proof_not_found(client):
    # Use a valid format ID that doesn't exist in storage
    r = client.get("/v1/proof/prf_20200101_000000_000000")
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
    # Use a valid format ID that doesn't exist in storage
    r = client.get("/v1/proof/prf_20200101_000000_000000/tsr")
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
    # test key: no monthly limit, no overage credits
    assert "monthly" not in data
    assert "proofs_remaining" not in data


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
    assert proof["spec_version"] == "1.2"
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
    assert public["spec_version"] == "1.2"
    assert public["arkforge_signature"].startswith("ed25519:")
    assert public["upstream_timestamp"] == "Thu, 26 Feb 2026 17:00:00 GMT"


# --- Webhook ---

def test_webhook_no_secrets_returns_503(client, monkeypatch):
    """Webhook is rejected with 503 when no webhook secrets are configured."""
    import trust_layer.app as app_mod
    monkeypatch.setattr(app_mod, "STRIPE_WEBHOOK_SECRET_LIVE", "")
    monkeypatch.setattr(app_mod, "STRIPE_WEBHOOK_SECRET_TEST", "")
    r = client.post(
        "/v1/webhooks/stripe",
        content=b"any payload",
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 503


# --- /v1/keys/setup (payment mode) ---

def test_setup_key_subscription_mode(client, monkeypatch):
    """Checkout session créée en mode subscription avec price_id Pro."""
    import trust_layer.app as app_mod
    monkeypatch.setattr(app_mod, "STRIPE_TEST_KEY", "sk_test_fake")
    monkeypatch.setattr(app_mod, "STRIPE_PRO_PRICE_ID_TEST", "price_test_pro_monthly")

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
        })

    assert r.status_code == 200
    data = r.json()
    assert data["checkout_url"] == "https://checkout.stripe.com/pay/cs_test_xxx"
    assert data["plan"] == "pro"
    assert data["price_monthly_eur"] == 29.0
    assert data["proofs_per_month"] == 5000

    # Vérifier que le Checkout est en mode subscription
    call_kwargs = mock_create.call_args.kwargs
    assert call_kwargs["mode"] == "subscription"
    assert call_kwargs["line_items"][0]["price"] == "price_test_pro_monthly"
    assert call_kwargs["metadata"]["product"] == "trust_layer_pro_subscription"


def test_setup_key_no_price_id_returns_500(client, monkeypatch):
    """Sans price_id configuré, retourne 500."""
    import trust_layer.app as app_mod
    monkeypatch.setattr(app_mod, "STRIPE_TEST_KEY", "sk_test_fake")
    monkeypatch.setattr(app_mod, "STRIPE_PRO_PRICE_ID", "")
    r = client.post("/v1/keys/setup", json={"email": "pro@test.com", "mode": "test"})
    assert r.status_code == 500
    assert r.json()["error"]["code"] == "internal_error"


# --- Webhook checkout.session.completed — abonnement Pro ---

def test_webhook_pro_subscription_creates_key(client, monkeypatch):
    """Webhook Pro subscription: crée la clé avec plan pro, pas de crédits."""
    import trust_layer.app as app_mod
    monkeypatch.setattr(app_mod, "STRIPE_WEBHOOK_SECRET_TEST", "whsec_test_fake")

    from trust_layer.credits import get_balance

    # HTTP body (plain dict, JSON-serializable)
    event_body = {
        "id": "evt_test_webhook_pro_sub_001",
        "type": "checkout.session.completed",
        "livemode": False,
        "data": {"object": {}},
    }
    # stripe 15: construct_event returns StripeObject (not dict) — mock with attributes
    inner_object = {
        "customer": "cus_webhook_pro_sub_test",
        "customer_details": {"email": "webhook_pro_sub@test.com"},
        "payment_intent": None,
        "subscription": "sub_pro_test_001",
        "metadata": {
            "product": "trust_layer_pro_subscription",
            "email": "webhook_pro_sub@test.com",
        },
    }
    mock_event = MagicMock()
    mock_event.id = "evt_test_webhook_pro_sub_001"
    mock_event.type = "checkout.session.completed"
    mock_event.livemode = False
    mock_event.data.object.to_dict.return_value = inner_object

    with patch("trust_layer.app.send_welcome_email"), \
         patch("stripe.Webhook.construct_event", return_value=mock_event):
        r = client.post(
            "/v1/webhooks/stripe",
            json=event_body,
            headers={"Content-Type": "application/json"},
        )

    assert r.status_code == 200
    assert r.json()["received"] is True

    from trust_layer.keys import load_api_keys
    keys = load_api_keys()
    pro_key = next((k for k, v in keys.items() if v.get("email") == "webhook_pro_sub@test.com"), None)
    assert pro_key is not None, "Pro API key not created by webhook"

    # Pas de crédits ajoutés — modèle subscription quota mensuel
    balance = get_balance(pro_key)
    assert balance == 0.0, f"Expected no credits (subscription model), got {balance}"

    # Plan correctement défini
    assert keys[pro_key]["plan"] == "pro"


@pytest.mark.parametrize("product_tag", [
    "scanner_pro_subscription",
])
def test_webhook_scanner_pro_subscription_creates_pro_key(client, monkeypatch, product_tag):
    """scanner_pro_subscription must route to plan=pro (not free fallback)."""
    import trust_layer.app as app_mod
    monkeypatch.setattr(app_mod, "STRIPE_WEBHOOK_SECRET_TEST", "whsec_test_fake")

    from trust_layer.credits import get_balance

    event_body = {
        "id": "evt_test_scanner_pro_001",
        "type": "checkout.session.completed",
        "livemode": False,
        "data": {"object": {}},
    }
    inner_object = {
        "customer": "cus_scanner_pro_test",
        "customer_details": {"email": "scanner_pro@test.com"},
        "payment_intent": None,
        "subscription": "sub_scanner_pro_001",
        "metadata": {
            "product": product_tag,
            "email": "scanner_pro@test.com",
            "plan": "pro",
        },
    }
    mock_event = MagicMock()
    mock_event.id = "evt_test_scanner_pro_001"
    mock_event.type = "checkout.session.completed"
    mock_event.livemode = False
    mock_event.data.object.to_dict.return_value = inner_object

    with patch("trust_layer.app.send_welcome_email_pro"), \
         patch("stripe.Webhook.construct_event", return_value=mock_event):
        r = client.post(
            "/v1/webhooks/stripe",
            json=event_body,
            headers={"Content-Type": "application/json"},
        )

    assert r.status_code == 200
    assert r.json()["received"] is True

    from trust_layer.keys import load_api_keys
    keys = load_api_keys()
    scanner_key = next((k for k, v in keys.items() if v.get("email") == "scanner_pro@test.com"), None)
    assert scanner_key is not None, f"{product_tag} did not create an API key"
    assert keys[scanner_key]["plan"] == "pro", f"{product_tag} should create pro plan, got {keys[scanner_key].get('plan')}"

    balance = get_balance(scanner_key)
    assert balance == 0.0, f"Expected no credits (subscription model), got {balance}"


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


# --- Overage billing — HTTP-level integration ---

def _exhaust_monthly_quota(key, monthly_limit=5000):
    """Pre-fill rate_limits.json to simulate exhausted monthly quota.

    Uses the module-level RATE_LIMITS_FILE (patched by conftest) so the write
    goes to the same tmp path that check_rate_limit reads from.
    """
    key_id = key[:16]
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    rl_file = _rl_mod.RATE_LIMITS_FILE  # patched by conftest
    limits = load_json(rl_file, {})
    limits[key_id] = {
        "date": today, "count": 0,
        "month": month, "month_count": monthly_limit,
    }
    save_json(rl_file, limits)


def test_pro_monthly_quota_exhausted_suggests_overage(client):
    """Pro key with exhausted monthly quota → 429, message mentions /v1/keys/overage."""
    from trust_layer.config import _PRO_MONTHLY_LIMIT
    key = create_api_key("cus_integ_quota", "ref_integ_quota", "quota@test.com", plan="pro")
    add_credits(key, 5.0, "pi_quota_integ")
    # Exhaust the real monthly limit — no dict patching needed
    _exhaust_monthly_quota(key, monthly_limit=_PRO_MONTHLY_LIMIT)

    mock_http = _mock_http_client()
    with patch("httpx.AsyncClient", return_value=mock_http), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):
        r = client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "payload": {}},
            headers={"Authorization": f"Bearer {key}"},
        )

    assert r.status_code == 429
    body = r.json()
    assert body["error"]["code"] == "rate_limited"
    assert "/v1/keys/overage" in body["error"]["message"]


def test_pro_usage_includes_monthly_section(client):
    """Pro key /v1/usage includes monthly quota section (test key has no monthly limit)."""
    key = create_api_key("cus_integ_pro_usage", "ref_pro_usage", "pro_usage@test.com", plan="pro")
    add_credits(key, 5.0, "pi_pro_usage")
    r = client.get("/v1/usage", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200
    data = r.json()
    assert "monthly" in data, f"Pro /v1/usage must include monthly section, got: {list(data.keys())}"
    assert "used" in data["monthly"]
    assert "limit" in data["monthly"]
    assert "remaining" in data["monthly"]


def test_overage_full_flow_via_http(client):
    """Full overage e2e: enable overage → proxy call (quota exhausted) → proof → verify."""
    from trust_layer.config import _PRO_MONTHLY_LIMIT
    key = create_api_key("cus_integ_ov_flow", "ref_ov_flow", "ov_flow@test.com", plan="pro")
    add_credits(key, 5.0, "pi_ov_flow")
    update_overage_settings(key, enabled=True, cap_eur=10.0, overage_rate=PRO_OVERAGE_PRICE)
    # Exhaust real monthly limit — no dict patching needed
    _exhaust_monthly_quota(key, monthly_limit=_PRO_MONTHLY_LIMIT)

    mock_http = _mock_http_client()
    with patch("httpx.AsyncClient", return_value=mock_http), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):
        r = client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "payload": {}},
            headers={"Authorization": f"Bearer {key}"},
        )

    assert r.status_code == 200, f"Expected 200 for overage call, got {r.status_code}: {r.text}"
    data = r.json()
    assert "proof" in data
    proof = data["proof"]
    assert proof["proof_id"].startswith("prf_")
    # Certification fee: prepaid_credit at overage rate
    fee = proof["certification_fee"]
    assert fee["method"] == "prepaid_credit"
    assert round(fee["amount"], 4) == PRO_OVERAGE_PRICE

    # Verify the proof is retrievable and integrity is valid
    proof_id = proof["proof_id"]
    r2 = client.get(f"/v1/proof/{proof_id}")
    assert r2.status_code == 200
    proof_data = r2.json()
    assert proof_data["integrity_verified"] is True


def test_free_tier_monthly_quota_429_via_http(client):
    """Free key with exhausted 100-proof monthly quota → 429 via HTTP."""
    key = create_api_key("cus_integ_free_quota", "ref_free_quota", "free_quota@test.com", plan="free")
    # Exhaust real free tier monthly limit
    _exhaust_monthly_quota(key, monthly_limit=FREE_TIER_MONTHLY_LIMIT)

    mock_http = _mock_http_client()
    with patch("httpx.AsyncClient", return_value=mock_http), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):
        r = client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "payload": {}},
            headers={"Authorization": f"Bearer {key}"},
        )

    assert r.status_code == 429
    assert r.json()["error"]["code"] == "rate_limited"


def test_overage_cap_reached_429_via_http(client):
    """Overage cap reached → 429 overage_cap_reached via HTTP."""
    from trust_layer.config import OVERAGE_CAP_MIN, _PRO_MONTHLY_LIMIT
    key = create_api_key("cus_integ_cap", "ref_cap", "cap@test.com", plan="pro")
    add_credits(key, 5.0, "pi_cap_integ")
    update_overage_settings(key, enabled=True, cap_eur=OVERAGE_CAP_MIN, overage_rate=PRO_OVERAGE_PRICE)

    # Pre-fill: quota exhausted (real Pro limit) + overage cap already hit
    key_id = key[:16]
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    rl_file = _rl_mod.RATE_LIMITS_FILE
    limits = load_json(rl_file, {})
    limits[key_id] = {
        "date": today, "count": 0,
        "month": month, "month_count": _PRO_MONTHLY_LIMIT,
        "overage_count": 500, "overage_spent_eur": 5.00,
    }
    save_json(rl_file, limits)

    mock_http = _mock_http_client()
    with patch("httpx.AsyncClient", return_value=mock_http), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):
        r = client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "payload": {}},
            headers={"Authorization": f"Bearer {key}"},
        )

    assert r.status_code == 429
    assert r.json()["error"]["code"] == "overage_cap_reached"


# --- Monthly quota enforcement (e2e) ---

def test_proxy_returns_429_when_rate_limited(client):
    """Proxy returns 429 with 'rate_limited' when check_rate_limit blocks."""
    key = create_api_key("cus_rl_block", "ref_rl_block", "rl_block@test.com",
                         test_mode=True)
    add_credits(key, 10.0, "pi_rl_block")
    mock_http = _mock_http_client()

    # Simulate exhausted quota: first call allowed, second blocked
    call_results = [(True, 5, False, ""), (False, 0, False, "monthly_quota")]

    with patch("trust_layer.proxy.check_rate_limit", side_effect=call_results), \
         patch("httpx.AsyncClient", return_value=mock_http), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        r1 = client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "payload": {}},
            headers={"Authorization": f"Bearer {key}"},
        )
        assert r1.status_code == 200

        r2 = client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "payload": {}},
            headers={"Authorization": f"Bearer {key}"},
        )

    assert r2.status_code == 429
    assert r2.json()["error"]["code"] == "rate_limited"


def test_enterprise_key_works_and_has_monthly_quota(client):
    """Enterprise key (mcp_ent_*) is accepted and /v1/usage shows monthly quota."""
    key = create_api_key("cus_ent_e2e", "ref_ent_e2e", "ent_e2e@company.com",
                         plan="enterprise")
    add_credits(key, 100.0, "pi_ent_e2e_setup")
    mock_http = _mock_http_client()

    with patch("httpx.AsyncClient", return_value=mock_http), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):
        r = client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "payload": {}},
            headers={"Authorization": f"Bearer {key}"},
        )

    assert r.status_code == 200
    assert r.json()["proof"]["proof_id"].startswith("prf_")

    # /v1/usage should report monthly for enterprise
    r2 = client.get("/v1/usage", headers={"Authorization": f"Bearer {key}"})
    assert r2.status_code == 200
    data = r2.json()
    assert "monthly" in data
    assert data["monthly"]["limit"] == ENTERPRISE_MONTHLY_LIMIT


def test_usage_shows_monthly_for_pro(client):
    """Pro key (mcp_pro_*) usage response includes monthly quota fields."""
    # Use a real mcp_pro_* key (test_mode=False, plan="pro")
    key = create_api_key("cus_pro_monthly_e2e", "ref_pro_monthly_e2e",
                         "pro_monthly@test.com", test_mode=False, plan="pro")
    add_credits(key, 10.0, "pi_pro_monthly_e2e")

    r = client.get("/v1/usage", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200
    data = r.json()
    assert "monthly" in data
    assert data["monthly"]["limit"] == PRO_MONTHLY_LIMIT
    assert data["monthly"]["remaining"] == PRO_MONTHLY_LIMIT  # no calls yet
    # overage credits visible
    assert "overage_credits_eur" in data
    assert data["overage_credits_eur"] == 10.0


# --- GET /v1/proof/{proof_id}/full ---

def test_proof_full_requires_auth(client, api_key):
    """GET /v1/proof/{id}/full returns 401 when no API key is provided."""
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

    r2 = client.get(f"/v1/proof/{proof_id}/full")
    assert r2.status_code == 401
    assert r2.json()["error"]["code"] == "auth_required"


def test_proof_full_wrong_owner(client, api_key):
    """GET /v1/proof/{id}/full returns 403 when a different valid API key is used."""
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

    other_key = create_api_key("cus_other_owner", "ref_other_owner", "other@test.com", test_mode=True)
    r2 = client.get(f"/v1/proof/{proof_id}/full", headers={"X-Api-Key": other_key})
    assert r2.status_code == 403
    assert r2.json()["error"]["code"] == "forbidden"


def test_proof_full_returns_payment(client, api_key):
    """GET /v1/proof/{id}/full returns 200 with parties and certification_fee for the owner."""
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

    r2 = client.get(f"/v1/proof/{proof_id}/full", headers={"Authorization": f"Bearer {api_key}"})
    assert r2.status_code == 200
    data = r2.json()
    assert data["integrity_verified"] is True
    assert "parties" in data
    assert "certification_fee" in data
    assert data["parties"]["buyer_fingerprint"] != ""


# ---------------------------------------------------------------------------
# Platform plan — TSA routing E2E
# ---------------------------------------------------------------------------

@pytest.fixture
def platform_key():
    """Internal Platform key — mcp_plat_ prefix, subscription quota (no credits needed)."""
    return create_api_key("cus_internal_arkforge", "ref_internal_platform", "contact@arkforge.tech", plan="platform")


def test_platform_key_has_correct_prefix(platform_key):
    """Platform API key must start with mcp_plat_."""
    assert platform_key.startswith("mcp_plat_"), f"Expected mcp_plat_ prefix, got: {platform_key[:12]}"


def test_platform_key_plan_detection(platform_key):
    """get_key_plan() must return 'platform' for mcp_plat_ keys."""
    from trust_layer.keys import get_key_plan
    assert get_key_plan(platform_key) == "platform"


def test_platform_proxy_call_routes_tsa_to_digicert(client, platform_key):
    """E2E: proxy call with Platform key → background task calls submit_hash(plan='platform')
    → first TSA attempt must be DigiCert, not FreeTSA."""
    mock_http = _mock_http_client()
    tsa_plans_seen = []

    original_submit = __import__("trust_layer.timestamps", fromlist=["submit_hash"]).submit_hash

    def capture_submit_hash(hash_hex, plan=""):
        tsa_plans_seen.append(plan)
        return (b"\x30\x82\x00\x01", "digicert.com")

    with patch("httpx.AsyncClient", return_value=mock_http), \
         patch("trust_layer.proxy.submit_hash", side_effect=capture_submit_hash), \
         patch("trust_layer.proxy.submit_to_rekor", return_value={"status": "anchored"}), \
         patch("trust_layer.proxy._log_background_task"):
        r = client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "payload": {"input": "test"}},
            headers={"X-Api-Key": platform_key},
        )

    assert r.status_code == 200, f"Proxy call failed: {r.json()}"
    assert tsa_plans_seen == ["platform"], \
        f"Expected submit_hash called with plan='platform', got: {tsa_plans_seen}"


def test_platform_proof_records_digicert_provider(client, platform_key):
    """E2E: proof stored on disk must show tsa_provider='digicert.com' for Platform key."""
    from trust_layer.proofs import load_proof

    mock_http = _mock_http_client()

    with patch("httpx.AsyncClient", return_value=mock_http), \
         patch("trust_layer.proxy.submit_hash", return_value=(b"\x30\x82\x00\x01", "digicert.com")), \
         patch("trust_layer.proxy.submit_to_rekor", return_value={"status": "anchored"}), \
         patch("trust_layer.proxy._log_background_task"):
        r = client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "payload": {}},
            headers={"X-Api-Key": platform_key},
        )

    assert r.status_code == 200
    proof_id = r.json()["proof"]["proof_id"]
    proof = load_proof(proof_id)
    assert proof is not None
    tsa_provider = proof.get("timestamp_authority", {}).get("provider", "")
    assert tsa_provider == "digicert.com", \
        f"Expected digicert.com in proof TSA provider, got: '{tsa_provider}'"
