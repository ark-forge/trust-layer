"""Tests for core proxy logic."""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from trust_layer.proxy import (
    validate_target_url,
    validate_currency,
    validate_amount,
    execute_proxy,
    ProxyError,
)
from trust_layer.payments.base import ChargeResult


def test_validate_target_https():
    url = validate_target_url("https://example.com/api")
    assert url == "https://example.com/api"


def test_validate_target_rejects_http():
    with pytest.raises(ProxyError) as exc_info:
        validate_target_url("http://example.com/api")
    assert exc_info.value.code == "invalid_target"


def test_validate_target_rejects_localhost():
    with pytest.raises(ProxyError):
        validate_target_url("https://localhost/api")


def test_validate_target_rejects_private_ip():
    with pytest.raises(ProxyError):
        validate_target_url("https://192.168.1.1/api")

    with pytest.raises(ProxyError):
        validate_target_url("https://10.0.0.1/api")

    with pytest.raises(ProxyError):
        validate_target_url("https://127.0.0.1/api")


def test_validate_target_rejects_zero():
    with pytest.raises(ProxyError):
        validate_target_url("https://0.0.0.0/api")


def test_validate_currency_valid():
    assert validate_currency("eur") == "eur"
    assert validate_currency("USD") == "usd"
    assert validate_currency("GBP") == "gbp"


def test_validate_currency_invalid():
    with pytest.raises(ProxyError) as exc_info:
        validate_currency("btc")
    assert exc_info.value.code == "invalid_currency"
    assert "btc" in exc_info.value.message


def test_validate_amount_valid():
    assert validate_amount(0.50) == 0.50
    assert validate_amount(50.00) == 50.00
    assert validate_amount(25.0) == 25.0


def test_validate_amount_too_low():
    with pytest.raises(ProxyError) as exc_info:
        validate_amount(0.10)
    assert exc_info.value.code == "invalid_amount"


def test_validate_amount_too_high():
    with pytest.raises(ProxyError) as exc_info:
        validate_amount(100.00)
    assert exc_info.value.code == "invalid_amount"


def test_proxy_error_to_dict():
    err = ProxyError("test_code", "test message", 400)
    d = err.to_dict()
    assert d["error"]["code"] == "test_code"
    assert d["error"]["status"] == 400


def test_proxy_error_with_proof():
    proof = {"proof_id": "prf_test", "hashes": {}}
    err = ProxyError("service_error", "Target failed", 502, proof=proof)
    d = err.to_dict()
    assert d["proof"]["proof_id"] == "prf_test"


@pytest.mark.asyncio
async def test_execute_proxy_invalid_key():
    with pytest.raises(ProxyError) as exc_info:
        await execute_proxy(
            target="https://example.com/api",
            method="POST",
            payload={"key": "value"},
            amount=0.50,
            currency="eur",
            api_key="mcp_test_invalid_nonexistent_key",
        )
    assert exc_info.value.code == "invalid_api_key"


@pytest.mark.asyncio
async def test_execute_proxy_full_flow(test_api_key):
    """Full proxy flow with mock payment + mock target service."""
    mock_charge = ChargeResult(
        provider="stripe",
        transaction_id="pi_test_flow",
        amount=0.50,
        currency="eur",
        status="succeeded",
        receipt_url="https://pay.stripe.com/receipts/test_flow",
    )

    mock_provider = AsyncMock()
    mock_provider.charge.return_value = mock_charge

    import httpx

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"result": "scan_complete", "score": 85}

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_response
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("trust_layer.proxy.get_provider", return_value=mock_provider), \
         patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy.submit_hash", return_value=None), \
         patch("trust_layer.proxy.send_proof_email"):

        result = await execute_proxy(
            target="https://example.com/api/scan",
            method="POST",
            payload={"repo_url": "https://github.com/test/repo"},
            amount=0.50,
            currency="eur",
            api_key=test_api_key,
        )

    assert "proof" in result
    assert "service_response" in result
    assert result["service_response"]["status_code"] == 200
    assert result["service_response"]["body"]["result"] == "scan_complete"
    assert result["proof"]["proof_id"].startswith("prf_")
    assert "verification_url" in result["proof"]
    assert result["proof"]["hashes"]["chain"].startswith("sha256:")

    mock_provider.charge.assert_called_once()


@pytest.mark.asyncio
async def test_execute_proxy_service_error(test_api_key):
    """Payment OK but service returns 500 — proof is still returned."""
    mock_charge = ChargeResult(
        provider="stripe", transaction_id="pi_test_502",
        amount=0.50, currency="eur", status="succeeded", receipt_url=None,
    )
    mock_provider = AsyncMock()
    mock_provider.charge.return_value = mock_charge

    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.json.return_value = {"error": "internal server error"}

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_response
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("trust_layer.proxy.get_provider", return_value=mock_provider), \
         patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy.submit_hash", return_value=None), \
         patch("trust_layer.proxy.send_proof_email"):

        result = await execute_proxy(
            target="https://example.com/api/fail",
            method="POST",
            payload={},
            amount=0.50,
            currency="eur",
            api_key=test_api_key,
        )

    # Should return error with proof (payment happened)
    assert "error" in result
    assert result["error"]["code"] == "service_error"
    assert "proof" in result
    assert result["proof"]["payment"]["status"] == "succeeded"


@pytest.mark.asyncio
async def test_execute_proxy_payment_failed(test_api_key):
    """Payment fails — no forward, no proof."""
    mock_charge = ChargeResult(
        provider="stripe", transaction_id="pi_test_fail",
        amount=0.50, currency="eur", status="failed", receipt_url=None,
    )
    mock_provider = AsyncMock()
    mock_provider.charge.return_value = mock_charge

    with patch("trust_layer.proxy.get_provider", return_value=mock_provider):
        with pytest.raises(ProxyError) as exc_info:
            await execute_proxy(
                target="https://example.com/api",
                method="POST",
                payload={},
                amount=0.50,
                currency="eur",
                api_key=test_api_key,
            )
    assert exc_info.value.code == "payment_failed"


@pytest.mark.asyncio
async def test_execute_proxy_idempotency(test_api_key):
    """Same idempotency key returns cached response."""
    mock_charge = ChargeResult(
        provider="stripe", transaction_id="pi_test_idemp",
        amount=0.50, currency="eur", status="succeeded", receipt_url=None,
    )
    mock_provider = AsyncMock()
    mock_provider.charge.return_value = mock_charge

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"result": "ok"}

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_response
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("trust_layer.proxy.get_provider", return_value=mock_provider), \
         patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy.submit_hash", return_value=None), \
         patch("trust_layer.proxy.send_proof_email"):

        result1 = await execute_proxy(
            target="https://example.com/api",
            method="POST", payload={}, amount=0.50, currency="eur",
            api_key=test_api_key, idempotency_key="idemp-key-123",
        )

        # Second call with same key — should return cached
        result2 = await execute_proxy(
            target="https://example.com/api",
            method="POST", payload={}, amount=0.50, currency="eur",
            api_key=test_api_key, idempotency_key="idemp-key-123",
        )

    assert result1 == result2
    # Provider should only be called once
    assert mock_provider.charge.call_count == 1
