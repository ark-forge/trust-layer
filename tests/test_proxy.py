"""Tests for core proxy logic."""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from trust_layer.proxy import (
    validate_target_url,
    validate_currency,
    validate_amount,
    execute_proxy,
    ProxyError,
    _scrub_internal_secret,
)
from trust_layer.config import PROOF_PRICE
from trust_layer.credits import add_credits


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
            amount=0.10,
            currency="eur",
            api_key="mcp_test_invalid_nonexistent_key",
        )
    assert exc_info.value.code == "invalid_api_key"


def _mock_http_client(response_body=None, status_code=200, headers=None):
    """Helper to create a mock HTTP client."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.json.return_value = response_body or {"result": "ok"}
    mock_response.headers = headers or {}

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_response
    mock_client.get.return_value = mock_response
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    return mock_client


@pytest.mark.asyncio
async def test_execute_proxy_full_flow(test_api_key):
    """Full proxy flow with prepaid credits + mock target service."""
    # Add credits first
    add_credits(test_api_key, 10.00, "pi_test_flow")

    mock_client = _mock_http_client({"result": "scan_complete", "score": 85})

    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        result = await execute_proxy(
            target="https://example.com/api/scan",
            method="POST",
            payload={"repo_url": "https://github.com/test/repo"},
            amount=PROOF_PRICE,
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
    assert result["proof"]["certification_fee"]["method"] == "prepaid_credit"


@pytest.mark.asyncio
async def test_execute_proxy_service_error(test_api_key):
    """Credits deducted but service returns 500 — proof is still returned."""
    add_credits(test_api_key, 10.00, "pi_test_502")

    mock_client = _mock_http_client({"error": "internal server error"}, status_code=500)

    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        result = await execute_proxy(
            target="https://example.com/api/fail",
            method="POST",
            payload={},
            amount=PROOF_PRICE,
            currency="eur",
            api_key=test_api_key,
        )

    # Should return error with proof (credits were deducted)
    assert "error" in result
    assert result["error"]["code"] == "service_error"
    assert "proof" in result
    assert result["proof"]["certification_fee"]["status"] == "succeeded"


@pytest.mark.asyncio
async def test_execute_proxy_insufficient_credits(test_api_key):
    """No credits — 402 insufficient_credits."""
    with pytest.raises(ProxyError) as exc_info:
        await execute_proxy(
            target="https://example.com/api",
            method="POST",
            payload={},
            amount=PROOF_PRICE,
            currency="eur",
            api_key=test_api_key,
        )
    assert exc_info.value.code == "insufficient_credits"
    assert exc_info.value.status == 402


@pytest.mark.asyncio
async def test_execute_proxy_captures_upstream_date(test_api_key):
    """Upstream Date header should be captured as upstream_timestamp in proof."""
    add_credits(test_api_key, 10.00, "pi_test_date")

    mock_client = _mock_http_client(
        {"result": "ok"},
        headers={"Date": "Thu, 26 Feb 2026 17:08:14 GMT"},
    )

    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        result = await execute_proxy(
            target="https://example.com/api",
            method="POST", payload={}, amount=PROOF_PRICE, currency="eur",
            api_key=test_api_key,
        )

    assert result["proof"].get("upstream_timestamp") == "Thu, 26 Feb 2026 17:08:14 GMT"


@pytest.mark.asyncio
async def test_execute_proxy_has_arkforge_signature(test_api_key):
    """Proof should contain arkforge_signature and arkforge_pubkey."""
    add_credits(test_api_key, 10.00, "pi_test_sig")

    mock_client = _mock_http_client()

    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        result = await execute_proxy(
            target="https://example.com/api",
            method="POST", payload={}, amount=PROOF_PRICE, currency="eur",
            api_key=test_api_key,
        )

    proof = result["proof"]
    assert "arkforge_signature" in proof
    assert proof["arkforge_signature"].startswith("ed25519:")
    assert "arkforge_pubkey" in proof
    assert proof["arkforge_pubkey"].startswith("ed25519:")

    # Verify the signature
    from trust_layer.crypto import verify_proof_signature
    chain_hash = proof["hashes"]["chain"].replace("sha256:", "")
    assert verify_proof_signature(proof["arkforge_pubkey"], chain_hash, proof["arkforge_signature"]) is True


@pytest.mark.asyncio
async def test_execute_proxy_has_spec_version(test_api_key):
    """Proof record should contain spec_version: '1.1'."""
    add_credits(test_api_key, 10.00, "pi_test_spec")

    mock_client = _mock_http_client()

    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        result = await execute_proxy(
            target="https://example.com/api",
            method="POST", payload={}, amount=PROOF_PRICE, currency="eur",
            api_key=test_api_key,
        )

    assert result["proof"]["spec_version"] == "1.1"


@pytest.mark.asyncio
async def test_execute_proxy_idempotency(test_api_key):
    """Same idempotency key returns cached response."""
    add_credits(test_api_key, 10.00, "pi_test_idemp")

    mock_client = _mock_http_client()

    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        result1 = await execute_proxy(
            target="https://example.com/api",
            method="POST", payload={}, amount=PROOF_PRICE, currency="eur",
            api_key=test_api_key, idempotency_key="idemp-key-123",
        )

        # Second call with same key — should return cached (no additional debit)
        result2 = await execute_proxy(
            target="https://example.com/api",
            method="POST", payload={}, amount=PROOF_PRICE, currency="eur",
            api_key=test_api_key, idempotency_key="idemp-key-123",
        )

    assert result1 == result2
    # Only one HTTP call should have been made
    assert mock_client.post.call_count == 1


# ---------------------------------------------------------------------------
# Security: X-Internal-Secret scrubbing (A5)
# ---------------------------------------------------------------------------

def test_scrub_internal_secret_flat_dict():
    """X-Internal-Secret key is removed from a flat dict."""
    body = {"result": "ok", "X-Internal-Secret": "supersecret", "score": 42}
    cleaned = _scrub_internal_secret(body)
    assert "X-Internal-Secret" not in cleaned
    assert cleaned["result"] == "ok"
    assert cleaned["score"] == 42


def test_scrub_internal_secret_case_insensitive():
    """Key matching is case-insensitive."""
    body = {"x-internal-secret": "s3cr3t", "data": "safe"}
    cleaned = _scrub_internal_secret(body)
    assert "x-internal-secret" not in cleaned
    assert cleaned["data"] == "safe"


def test_scrub_internal_secret_nested():
    """X-Internal-Secret is removed from nested structures (echo-header pattern)."""
    body = {
        "url": "https://example.com",
        "headers": {
            "Content-Type": "application/json",
            "X-Internal-Secret": "supersecret",
            "X-Api-Key": "user_key",
        },
    }
    cleaned = _scrub_internal_secret(body)
    assert "X-Internal-Secret" not in cleaned["headers"]
    assert cleaned["headers"]["Content-Type"] == "application/json"
    assert cleaned["headers"]["X-Api-Key"] == "user_key"


def test_scrub_internal_secret_list():
    """_scrub_internal_secret handles lists recursively."""
    body = [
        {"X-Internal-Secret": "leak", "ok": True},
        "plain string",
        42,
    ]
    cleaned = _scrub_internal_secret(body)
    assert isinstance(cleaned, list)
    assert "X-Internal-Secret" not in cleaned[0]
    assert cleaned[0]["ok"] is True
    assert cleaned[1] == "plain string"


def test_scrub_does_not_affect_other_keys():
    """Non-secret keys and values are untouched."""
    body = {"a": 1, "b": {"c": "hello"}}
    cleaned = _scrub_internal_secret(body)
    assert cleaned == body


@pytest.mark.asyncio
async def test_execute_proxy_scrubs_secret_from_response(test_api_key):
    """X-Internal-Secret never appears in the response returned to the client,
    even when the upstream service echoes all request headers (httpbin /anything pattern)."""
    add_credits(test_api_key, 10.00, "pi_test_scrub")

    # Simulate an echo-headers service that mirrors X-Internal-Secret back
    echo_body = {
        "url": "https://example.com/anything",
        "headers": {
            "Content-Type": "application/json",
            "X-Internal-Secret": "THIS_MUST_NOT_LEAK",
        },
    }
    mock_client = _mock_http_client(echo_body)

    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        result = await execute_proxy(
            target="https://example.com/anything",
            method="POST",
            payload={},
            amount=PROOF_PRICE,
            currency="eur",
            api_key=test_api_key,
        )

    response_body = result["service_response"]["body"]
    assert "X-Internal-Secret" not in response_body.get("headers", {})
    # Chain hash still present — integrity not broken
    assert result["proof"]["hashes"]["chain"]


@pytest.mark.asyncio
async def test_execute_proxy_extra_headers_forwarded(test_api_key):
    """Authorization header in extra_headers is forwarded to the target service."""
    add_credits(test_api_key, 10.00, "pi_test_extra_fwd")

    captured_headers = {}

    async def mock_post(url, json=None, headers=None, **kwargs):
        captured_headers.update(headers or {})
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"ok": True}
        mock_resp.headers = {}
        return mock_resp

    mock_client = AsyncMock()
    mock_client.post = mock_post
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        await execute_proxy(
            target="https://example.com/api",
            method="POST",
            payload={},
            amount=PROOF_PRICE,
            currency="eur",
            api_key=test_api_key,
            extra_headers={"Authorization": "token ghp_xxx"},
        )

    assert captured_headers.get("Authorization") == "token ghp_xxx"


@pytest.mark.asyncio
async def test_execute_proxy_extra_headers_blocks_internal_secret(test_api_key):
    """X-Internal-Secret in extra_headers is silently dropped — never forwarded."""
    add_credits(test_api_key, 10.00, "pi_test_extra_secret")

    captured_headers = {}

    async def mock_post(url, json=None, headers=None, **kwargs):
        captured_headers.update(headers or {})
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"ok": True}
        mock_resp.headers = {}
        return mock_resp

    mock_client = AsyncMock()
    mock_client.post = mock_post
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        await execute_proxy(
            target="https://example.com/api",
            method="POST",
            payload={},
            amount=PROOF_PRICE,
            currency="eur",
            api_key=test_api_key,
            extra_headers={"X-Internal-Secret": "INJECTED"},
        )

    # The real INTERNAL_SECRET may or may not be set, but "INJECTED" must never appear
    assert captured_headers.get("X-Internal-Secret") != "INJECTED"


@pytest.mark.asyncio
async def test_execute_proxy_extra_headers_blocks_hop_by_hop(test_api_key):
    """Hop-by-hop headers (Host, Transfer-Encoding) in extra_headers are silently dropped."""
    add_credits(test_api_key, 10.00, "pi_test_extra_hop")

    captured_headers = {}

    async def mock_post(url, json=None, headers=None, **kwargs):
        captured_headers.update(headers or {})
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"ok": True}
        mock_resp.headers = {}
        return mock_resp

    mock_client = AsyncMock()
    mock_client.post = mock_post
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=mock_client), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        await execute_proxy(
            target="https://example.com/api",
            method="POST",
            payload={},
            amount=PROOF_PRICE,
            currency="eur",
            api_key=test_api_key,
            extra_headers={"Host": "evil.com", "Transfer-Encoding": "chunked"},
        )

    assert "Host" not in captured_headers
    assert "Transfer-Encoding" not in captured_headers


@pytest.mark.asyncio
async def test_execute_proxy_extra_headers_max_count(test_api_key):
    """More than 10 extra_headers raises ProxyError invalid_request."""
    add_credits(test_api_key, 10.00, "pi_test_extra_max")

    too_many = {f"X-Custom-{i}": f"value{i}" for i in range(11)}

    with pytest.raises(ProxyError) as exc_info:
        with patch("httpx.AsyncClient"), \
             patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):
            await execute_proxy(
                target="https://example.com/api",
                method="POST",
                payload={},
                amount=PROOF_PRICE,
                currency="eur",
                api_key=test_api_key,
                extra_headers=too_many,
            )

    assert exc_info.value.code == "invalid_request"
    assert exc_info.value.status == 400
