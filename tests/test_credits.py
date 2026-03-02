"""Tests for prepaid credit system."""

import json
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from trust_layer.credits import (
    get_balance,
    debit_credits,
    add_credits,
    InsufficientCredits,
)
from trust_layer.config import PROOF_PRICE, MIN_CREDIT_PURCHASE, MAX_CREDIT_PURCHASE
from trust_layer.keys import create_api_key
from trust_layer.payments.base import ChargeResult


@pytest.fixture
def pro_api_key():
    return create_api_key("cus_credit_test", "ref_credit_test", "credit@test.com", test_mode=True)


@pytest.fixture
def free_api_key():
    return create_api_key("", "free_signup_credit@test.com", "credit@test.com", test_mode=False, plan="free")


# --- Balance ---

def test_get_balance_new_key(pro_api_key):
    assert get_balance(pro_api_key) == 0.0


def test_get_balance_after_purchase(pro_api_key):
    add_credits(pro_api_key, 10.00, "pi_test_purchase")
    assert get_balance(pro_api_key) == 10.00


# --- Debit ---

def test_debit_credits_success(pro_api_key):
    add_credits(pro_api_key, 10.00, "pi_test_purchase")
    txn_id = debit_credits(pro_api_key, PROOF_PRICE, "prf_test_001")
    assert txn_id.startswith("crd_")
    assert get_balance(pro_api_key) == pytest.approx(9.90)


def test_debit_insufficient_balance(pro_api_key):
    with pytest.raises(InsufficientCredits) as exc_info:
        debit_credits(pro_api_key, PROOF_PRICE, "prf_test_002")
    assert exc_info.value.balance == 0.0
    assert exc_info.value.required == PROOF_PRICE


def test_debit_multiple_until_empty(pro_api_key):
    add_credits(pro_api_key, 1.00, "pi_test_1eur")
    # 1.00 EUR / 0.10 = 10 proofs
    for i in range(10):
        debit_credits(pro_api_key, PROOF_PRICE, f"prf_test_{i:03d}")
    assert get_balance(pro_api_key) == pytest.approx(0.0)
    with pytest.raises(InsufficientCredits):
        debit_credits(pro_api_key, PROOF_PRICE, "prf_test_011")


# --- Add credits ---

def test_add_credits_returns_new_balance(pro_api_key):
    balance = add_credits(pro_api_key, 5.00, "pi_test_5eur")
    assert balance == 5.00
    balance2 = add_credits(pro_api_key, 3.00, "pi_test_3eur")
    assert balance2 == 8.00


# --- Transaction log ---

def test_credit_transaction_log(pro_api_key, tmp_path):
    import trust_layer.credits as credits_mod
    log_path = tmp_path / "data" / "credit_transactions.jsonl"
    credits_mod.CREDIT_TRANSACTIONS_LOG = log_path

    add_credits(pro_api_key, 10.00, "pi_log_test")
    debit_credits(pro_api_key, PROOF_PRICE, "prf_log_test")

    lines = log_path.read_text().strip().split("\n")
    assert len(lines) == 2

    purchase = json.loads(lines[0])
    assert purchase["type"] == "purchase"
    assert purchase["amount"] == 10.00
    assert purchase["stripe_pi"] == "pi_log_test"

    debit = json.loads(lines[1])
    assert debit["type"] == "debit"
    assert debit["amount"] == PROOF_PRICE
    assert debit["proof_id"] == "prf_log_test"


# --- Integration: proxy with credits ---

@pytest.mark.asyncio
async def test_proxy_with_credits(pro_api_key):
    """Full proxy flow using prepaid credits."""
    add_credits(pro_api_key, 1.00, "pi_test_proxy")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"result": "ok"}
    mock_response.headers = {}

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_response
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    from trust_layer.proxy import execute_proxy

    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        result = await execute_proxy(
            target="https://example.com/api",
            method="POST",
            payload={},
            amount=0.10,
            currency="eur",
            api_key=pro_api_key,
        )

    assert "proof" in result
    assert result["proof"]["certification_fee"]["method"] == "prepaid_credit"
    assert result["proof"]["certification_fee"]["amount"] == PROOF_PRICE
    assert result["proof"]["certification_fee"]["status"] == "succeeded"
    assert result["proof"]["certification_fee"]["transaction_id"].startswith("crd_")
    assert get_balance(pro_api_key) == pytest.approx(0.90)


@pytest.mark.asyncio
async def test_proxy_no_credits(pro_api_key):
    """Proxy should fail with 402 when no credits."""
    from trust_layer.proxy import execute_proxy, ProxyError

    with pytest.raises(ProxyError) as exc_info:
        await execute_proxy(
            target="https://example.com/api",
            method="POST",
            payload={},
            amount=0.10,
            currency="eur",
            api_key=pro_api_key,
        )
    assert exc_info.value.code == "insufficient_credits"
    assert exc_info.value.status == 402


# --- API endpoint: /v1/credits/buy ---

@pytest.fixture
def client():
    from trust_layer.app import app
    from fastapi.testclient import TestClient
    return TestClient(app)


def test_buy_credits_success(client, pro_api_key):
    mock_charge = ChargeResult(
        provider="stripe", transaction_id="pi_buy_test",
        amount=10.00, currency="eur", status="succeeded",
        receipt_url="https://pay.stripe.com/receipts/buy_test",
    )
    mock_provider = AsyncMock()
    mock_provider.charge.return_value = mock_charge

    with patch("trust_layer.payments.get_provider", return_value=mock_provider):
        r = client.post(
            "/v1/credits/buy",
            json={"amount": 10.00},
            headers={"X-Api-Key": pro_api_key},
        )

    assert r.status_code == 200
    data = r.json()
    assert data["credits_added"] == 10.00
    assert data["balance"] == 10.00
    assert data["proofs_available"] == 100
    assert data["receipt_url"] == "https://pay.stripe.com/receipts/buy_test"


def test_buy_credits_below_minimum(client, pro_api_key):
    r = client.post(
        "/v1/credits/buy",
        json={"amount": 0.50},
        headers={"X-Api-Key": pro_api_key},
    )
    assert r.status_code == 400
    assert "minimum" in r.json()["error"]["message"].lower()


def test_buy_credits_above_maximum(client, pro_api_key):
    r = client.post(
        "/v1/credits/buy",
        json={"amount": 200.00},
        headers={"X-Api-Key": pro_api_key},
    )
    assert r.status_code == 400
    assert "maximum" in r.json()["error"]["message"].lower()


def test_buy_credits_free_key_rejected(client, free_api_key):
    r = client.post(
        "/v1/credits/buy",
        json={"amount": 10.00},
        headers={"X-Api-Key": free_api_key},
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "invalid_plan"


def test_buy_credits_no_auth(client):
    r = client.post("/v1/credits/buy", json={"amount": 10.00})
    assert r.status_code == 401
