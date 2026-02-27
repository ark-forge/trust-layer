"""Tests for the free tier proxy flow (3 witnesses, no Stripe)."""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from trust_layer.proxy import execute_proxy, ProxyError
from trust_layer.payments.base import ChargeResult
from trust_layer.templates import render_proof_page


@pytest.fixture
def free_api_key(tmp_path):
    """Create a free-tier API key (no Stripe customer)."""
    from trust_layer.keys import create_api_key
    key = create_api_key(
        stripe_customer_id="",
        ref_id="free_signup_test@example.com",
        email="test@example.com",
        test_mode=True,
        plan="free",
    )
    return key


@pytest.mark.asyncio
async def test_free_tier_skips_stripe(free_api_key):
    """Free tier should skip Stripe charge and produce a valid proof."""
    import httpx

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"result": "ok"}
    mock_response.headers = {}

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_response
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        result = await execute_proxy(
            target="https://example.com/api/test",
            method="POST",
            payload={"key": "value"},
            amount=0,
            currency="eur",
            api_key=free_api_key,
        )

    assert "proof" in result
    proof = result["proof"]
    assert proof["proof_id"].startswith("prf_")
    assert proof["payment"]["provider"] == "none"
    assert proof["payment"]["status"] == "free_tier"
    assert proof["payment"]["amount"] == 0.0
    assert proof["payment"]["transaction_id"] == "free_tier"
    assert proof["payment"]["receipt_url"] is None


@pytest.mark.asyncio
async def test_free_tier_no_stripe_call(free_api_key):
    """Ensure get_provider is never called for free tier."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"result": "ok"}
    mock_response.headers = {}

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_response
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    mock_get_provider = MagicMock()

    with patch("trust_layer.proxy.get_provider", mock_get_provider), \
         patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        await execute_proxy(
            target="https://example.com/api/test",
            method="POST",
            payload={},
            amount=0,
            currency="eur",
            api_key=free_api_key,
        )

    mock_get_provider.assert_not_called()


@pytest.mark.asyncio
async def test_free_tier_still_forwards_request(free_api_key):
    """Free tier should still forward the request to the target API."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": "forwarded"}
    mock_response.headers = {}

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_response
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        result = await execute_proxy(
            target="https://example.com/api/test",
            method="POST",
            payload={"input": "test"},
            amount=0,
            currency="eur",
            api_key=free_api_key,
        )

    assert result["service_response"]["status_code"] == 200
    assert result["service_response"]["body"]["data"] == "forwarded"


@pytest.mark.asyncio
async def test_free_tier_has_signature(free_api_key):
    """Free tier proofs should still have Ed25519 signature."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"ok": True}
    mock_response.headers = {}

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_response
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        result = await execute_proxy(
            target="https://example.com/api",
            method="POST",
            payload={},
            amount=0,
            currency="eur",
            api_key=free_api_key,
        )

    proof = result["proof"]
    assert "arkforge_signature" in proof
    assert "arkforge_pubkey" in proof
    assert proof["arkforge_signature"]  # non-empty


def test_free_tier_template_greys_out_stripe():
    """Free tier proof page should grey out Stripe witness."""
    proof = {
        "proof_id": "prf_test_free",
        "timestamp": "2026-02-27T15:00:00Z",
        "hashes": {"chain": "sha256:abc", "request": "sha256:def", "response": "sha256:ghi"},
        "parties": {"buyer_fingerprint": "sha256:buyer", "seller": "example.com"},
        "payment": {"provider": "none", "transaction_id": "free_tier", "amount": 0.0, "currency": "EUR", "status": "free_tier"},
        "timestamp_authority": {"status": "submitted"},
        "verification_url": "https://test.arkforge.fr/v1/proof/prf_test_free",
    }

    html = render_proof_page(proof, integrity_verified=True)

    # Stripe witness should be greyed out
    assert "not applicable (free tier)" in html
    # Other witnesses should still be present
    assert "Ed25519" in html
    assert "RFC 3161" in html
    assert "Archive.org" in html
    # Trust point should say "free tier"
    assert "free tier" in html.lower()


def test_pro_tier_template_shows_stripe():
    """Pro tier proof page should show Stripe witness in green."""
    proof = {
        "proof_id": "prf_test_pro",
        "timestamp": "2026-02-27T15:00:00Z",
        "hashes": {"chain": "sha256:abc", "request": "sha256:def", "response": "sha256:ghi"},
        "parties": {"buyer_fingerprint": "sha256:buyer", "seller": "example.com"},
        "payment": {"provider": "stripe", "transaction_id": "pi_test", "amount": 0.50, "currency": "EUR", "status": "succeeded", "receipt_url": "https://pay.stripe.com/receipts/test"},
        "timestamp_authority": {"status": "verified"},
        "verification_url": "https://test.arkforge.fr/v1/proof/prf_test_pro",
    }

    html = render_proof_page(proof, integrity_verified=True)

    # Stripe should show as active witness
    assert "confirms payment occurred" in html
    assert "not applicable (free tier)" not in html
    # Payment verified text
    assert "Payment verified independently by Stripe" in html
