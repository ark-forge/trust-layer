"""Tests for receipt fetching, parsing, and chain hash integration."""

import hashlib
from unittest.mock import AsyncMock, patch, MagicMock

import httpx
import pytest

from trust_layer.receipt import (
    ReceiptResult,
    ReceiptParser,
    StripeReceiptParser,
    fetch_receipt,
    register_parser,
    get_parser,
    get_registered_domains,
    _validate_receipt_url,
    _detect_receipt_type,
    _PARSER_REGISTRY,
)
from trust_layer.proofs import (
    generate_proof,
    verify_proof_integrity,
    get_public_proof,
    sha256_hex,
    SPEC_VERSION,
    SPEC_VERSION_RECEIPT,
)


# ═══════════════════════════════════════════════════════════
# URL Validation
# ═══════════════════════════════════════════════════════════

class TestURLValidation:
    def test_valid_stripe_pay(self):
        valid, err = _validate_receipt_url("https://pay.stripe.com/receipts/payment/CAcaFwo")
        assert valid is True
        assert err == ""

    def test_valid_stripe_receipt(self):
        valid, err = _validate_receipt_url("https://receipt.stripe.com/payment/CAcaFwo")
        assert valid is True
        assert err == ""

    def test_rejects_http(self):
        valid, err = _validate_receipt_url("http://pay.stripe.com/receipts/test")
        assert valid is False
        assert "HTTPS" in err

    def test_rejects_unknown_domain(self):
        valid, err = _validate_receipt_url("https://evil.com/receipts/test")
        assert valid is False
        assert "whitelist" in err

    def test_rejects_empty(self):
        valid, err = _validate_receipt_url("")
        assert valid is False

    def test_rejects_none(self):
        valid, err = _validate_receipt_url(None)
        assert valid is False

    def test_rejects_private_ip(self):
        valid, err = _validate_receipt_url("https://192.168.1.1/receipts")
        assert valid is False


class TestDetectReceiptType:
    def test_stripe_pay(self):
        assert _detect_receipt_type("https://pay.stripe.com/receipts/x") == "stripe"

    def test_stripe_receipt(self):
        assert _detect_receipt_type("https://receipt.stripe.com/x") == "stripe"

    def test_unknown(self):
        assert _detect_receipt_type("https://unknown.com/x") == "unknown"


# ═══════════════════════════════════════════════════════════
# Stripe Parser
# ═══════════════════════════════════════════════════════════

class TestStripeParser:
    def setup_method(self):
        self.parser = StripeReceiptParser()

    def test_parse_dollar_amount(self):
        html = '<div class="amount">$49.99</div><span>Paid</span><span>February 28, 2026</span>'
        result = self.parser.parse(html)
        assert result["amount"] == 49.99
        assert result["currency"] == "usd"
        assert result["status"] == "paid"
        assert result["date"] == "February 28, 2026"

    def test_parse_euro_amount(self):
        html = '<span class="total">\u20ac12.50</span><span>Payment successful</span>'
        result = self.parser.parse(html)
        assert result["amount"] == 12.50
        assert result["currency"] == "eur"
        assert result["status"] == "paid"

    def test_parse_gbp_amount(self):
        html = '<span>\u00a375.00</span><span>succeeded</span>'
        result = self.parser.parse(html)
        assert result["amount"] == 75.00
        assert result["currency"] == "gbp"

    def test_parse_currency_code_format(self):
        html = '<span>100.00 EUR</span><span>Paid</span>'
        result = self.parser.parse(html)
        assert result["amount"] == 100.00
        assert result["currency"] == "eur"

    def test_parse_european_comma_format(self):
        html = '<span>1,50 EUR</span>'
        result = self.parser.parse(html)
        assert result["amount"] == 1.50
        assert result["currency"] == "eur"

    def test_parse_status_paid(self):
        html = '<span>$10.00</span><div>Paid</div>'
        result = self.parser.parse(html)
        assert result["status"] == "paid"

    def test_parse_status_payment_complete(self):
        html = '<span>$10.00</span><div>Payment complete</div>'
        result = self.parser.parse(html)
        assert result["status"] == "paid"

    def test_parse_iso_date(self):
        html = '<span>$10.00</span><span>2026-02-28</span>'
        result = self.parser.parse(html)
        assert result["date"] == "2026-02-28"

    def test_parse_slash_date(self):
        html = '<span>$10.00</span><span>2/28/2026</span>'
        result = self.parser.parse(html)
        assert result["date"] == "2/28/2026"

    def test_empty_html_returns_empty(self):
        result = self.parser.parse("")
        assert result == {}

    def test_no_amount_returns_empty(self):
        result = self.parser.parse("<html><body>No numbers here</body></html>")
        assert result == {}


# ═══════════════════════════════════════════════════════════
# Abstract Parser Architecture
# ═══════════════════════════════════════════════════════════

class TestParserRegistry:
    def test_stripe_parser_registered(self):
        parser = get_parser("stripe")
        assert parser is not None
        assert parser.name == "stripe"

    def test_registered_domains_include_stripe(self):
        domains = get_registered_domains()
        assert "pay.stripe.com" in domains
        assert "receipt.stripe.com" in domains

    def test_register_custom_parser(self):
        """Verify adding a new PSP parser works without modifying existing code."""
        class FakePayPalParser(ReceiptParser):
            name = "paypal"
            domains = ["www.paypal.com"]

            def parse(self, html: str) -> dict:
                return {"amount": 42.0, "currency": "usd"}

        register_parser(FakePayPalParser())
        assert get_parser("paypal") is not None
        assert "www.paypal.com" in get_registered_domains()
        assert _detect_receipt_type("https://www.paypal.com/receipt/123") == "paypal"

        # Validate that paypal domain is now accepted
        valid, _ = _validate_receipt_url("https://www.paypal.com/receipt/123")
        assert valid is True

        # Cleanup: remove from registry to not affect other tests
        del _PARSER_REGISTRY["paypal"]
        from trust_layer.receipt import _DOMAIN_TO_PARSER
        del _DOMAIN_TO_PARSER["www.paypal.com"]


# ═══════════════════════════════════════════════════════════
# Fetch Receipt (mocked httpx)
# ═══════════════════════════════════════════════════════════

SAMPLE_STRIPE_HTML = b"""
<!DOCTYPE html>
<html>
<head><title>Stripe Receipt</title></head>
<body>
<div class="amount">$25.00</div>
<div class="status">Paid</div>
<div class="date">February 28, 2026</div>
</body>
</html>
"""


class TestFetchReceipt:
    @pytest.mark.asyncio
    async def test_fetch_success(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = SAMPLE_STRIPE_HTML

        with patch("trust_layer.receipt.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await fetch_receipt("https://pay.stripe.com/receipts/payment/test123")

        assert result.receipt_fetch_status == "fetched"
        assert result.receipt_type == "stripe"
        assert result.receipt_content_hash is not None
        assert len(result.receipt_content_hash) == 64  # SHA-256 hex
        assert result.parsing_status == "success"
        assert result.parsed_fields["amount"] == 25.00
        assert result.parsed_fields["currency"] == "usd"
        assert result.parsed_fields["status"] == "paid"

    @pytest.mark.asyncio
    async def test_fetch_timeout(self):
        with patch("trust_layer.receipt.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.side_effect = httpx.TimeoutException("timed out")
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await fetch_receipt("https://pay.stripe.com/receipts/payment/test123")

        assert result.receipt_fetch_status == "failed"
        assert result.receipt_fetch_error == "Timeout"
        assert result.receipt_content_hash is None

    @pytest.mark.asyncio
    async def test_fetch_404(self):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.content = b"Not Found"

        with patch("trust_layer.receipt.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await fetch_receipt("https://pay.stripe.com/receipts/payment/test123")

        assert result.receipt_fetch_status == "failed"
        assert "404" in result.receipt_fetch_error

    @pytest.mark.asyncio
    async def test_fetch_invalid_domain(self):
        result = await fetch_receipt("https://evil.com/receipts/test")
        assert result.receipt_fetch_status == "failed"
        assert "whitelist" in result.receipt_fetch_error

    @pytest.mark.asyncio
    async def test_content_hash_deterministic(self):
        """Same HTML content must always produce the same hash."""
        html_bytes = b"<html><body>$10.00 Paid</body></html>"
        expected_hash = hashlib.sha256(html_bytes).hexdigest()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = html_bytes

        with patch("trust_layer.receipt.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await fetch_receipt("https://pay.stripe.com/receipts/test")

        assert result.receipt_content_hash == expected_hash

    @pytest.mark.asyncio
    async def test_parse_failure_still_has_hash(self):
        """Even if parsing fails, the content hash must be present."""
        html_bytes = b"<html><body>No amounts here at all</body></html>"

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = html_bytes

        with patch("trust_layer.receipt.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await fetch_receipt("https://pay.stripe.com/receipts/test")

        assert result.receipt_fetch_status == "fetched"
        assert result.receipt_content_hash is not None
        assert len(result.receipt_content_hash) == 64
        assert result.parsing_status == "failed"


# ═══════════════════════════════════════════════════════════
# Chain Hash with Receipt (proofs.py integration)
# ═══════════════════════════════════════════════════════════

class TestChainHashWithReceipt:
    def _make_proof_args(self):
        return dict(
            request_data={"target": "https://api.example.com", "payload": {}},
            response_data={"result": "ok"},
            payment_data={"transaction_id": "pi_test", "amount": 0.10, "currency": "eur", "status": "succeeded"},
            timestamp="2026-02-28T12:00:00Z",
            buyer_fingerprint="abc123",
            seller="api.example.com",
        )

    def test_chain_hash_with_receipt_is_v2(self):
        """Proof with receipt_content_hash must be spec v2.1."""
        args = self._make_proof_args()
        proof = generate_proof(**args, receipt_content_hash="deadbeef" * 8)
        assert proof["spec_version"] == SPEC_VERSION_RECEIPT
        assert proof["spec_version"] == "2.1"

    def test_chain_hash_without_receipt_is_v1(self):
        """Proof without receipt_content_hash must be spec v1.2 (canonical JSON chain hash)."""
        args = self._make_proof_args()
        proof = generate_proof(**args)
        assert proof["spec_version"] == SPEC_VERSION
        assert proof["spec_version"] == "1.2"

    def test_chain_hash_differs_with_receipt(self):
        """Adding receipt_content_hash must change the chain hash."""
        args = self._make_proof_args()
        proof_without = generate_proof(**args)
        proof_with = generate_proof(**args, receipt_content_hash="deadbeef" * 8)
        assert proof_without["hashes"]["chain"] != proof_with["hashes"]["chain"]

    def test_chain_hash_without_receipt_unchanged(self):
        """Chain hash without receipt must match the v1.2 canonical JSON formula exactly."""
        args = self._make_proof_args()
        proof = generate_proof(**args)

        # Manually compute expected chain hash (v1.2 canonical JSON formula)
        from trust_layer.proofs import canonical_json
        req_hash = sha256_hex(canonical_json(args["request_data"]))
        resp_hash = sha256_hex(canonical_json(args["response_data"]))
        chain_data = {
            "request_hash": req_hash,
            "response_hash": resp_hash,
            "transaction_id": "pi_test",
            "timestamp": "2026-02-28T12:00:00Z",
            "buyer_fingerprint": "abc123",
            "seller": "api.example.com",
        }
        expected = sha256_hex(canonical_json(chain_data))

        assert proof["_raw_chain_hash"] == expected

    def test_verify_integrity_with_receipt(self):
        """verify_proof_integrity must work with receipt-bearing proofs."""
        args = self._make_proof_args()
        receipt_hash = hashlib.sha256(b"<html>receipt</html>").hexdigest()
        provider_payment = {
            "type": "stripe",
            "receipt_content_hash": f"sha256:{receipt_hash}",
            "receipt_fetch_status": "fetched",
        }
        proof = generate_proof(**args, receipt_content_hash=receipt_hash, provider_payment=provider_payment)

        # Simulate stored proof structure
        proof_record = {
            "proof_id": "prf_test",
            "spec_version": proof["spec_version"],
            "hashes": proof["hashes"],
            "parties": proof["parties"],
            "certification_fee": proof["certification_fee"],
            "timestamp": proof["timestamp"],
            "provider_payment": proof.get("provider_payment"),
        }

        assert verify_proof_integrity(proof_record) is True

    def test_verify_integrity_old_proofs_still_work(self):
        """v1.1 proofs (legacy concatenation) must still verify — backward compat."""
        from trust_layer.proofs import canonical_json
        args = self._make_proof_args()
        # Build a real legacy v1.1 proof using the old string concatenation formula
        req_hash = sha256_hex(canonical_json(args["request_data"]))
        resp_hash = sha256_hex(canonical_json(args["response_data"]))
        chain_input = req_hash + resp_hash + "pi_test" + "2026-02-28T12:00:00Z" + "abc123" + "api.example.com"
        chain_hash = sha256_hex(chain_input)
        proof_record = {
            "proof_id": "prf_old",
            "spec_version": "1.1",
            "hashes": {
                "request": f"sha256:{req_hash}",
                "response": f"sha256:{resp_hash}",
                "chain": f"sha256:{chain_hash}",
            },
            "parties": {"buyer_fingerprint": "abc123", "seller": "api.example.com"},
            "certification_fee": {"transaction_id": "pi_test"},
            "timestamp": "2026-02-28T12:00:00Z",
        }
        assert verify_proof_integrity(proof_record) is True

    def test_provider_payment_in_proof(self):
        """provider_payment dict must be stored in the proof."""
        args = self._make_proof_args()
        pe = {"type": "stripe", "receipt_url": "https://pay.stripe.com/receipts/test"}
        proof = generate_proof(**args, provider_payment=pe)
        assert proof["provider_payment"] == pe

    def test_no_provider_payment_not_in_proof(self):
        """Without provider_payment, key must not be in the proof."""
        args = self._make_proof_args()
        proof = generate_proof(**args)
        assert "provider_payment" not in proof


# ═══════════════════════════════════════════════════════════
# Public Proof
# ═══════════════════════════════════════════════════════════

class TestPublicProofWithReceipt:
    def test_public_proof_includes_provider_payment(self):
        pe = {"type": "stripe", "receipt_url": "https://pay.stripe.com/receipts/test", "receipt_content_hash": "sha256:abc123"}
        proof = {
            "proof_id": "prf_test",
            "spec_version": "2.0",
            "hashes": {"request": "sha256:a", "response": "sha256:b", "chain": "sha256:c"},
            "parties": {"buyer_fingerprint": "x", "seller": "y"},
            "certification_fee": {"transaction_id": "t", "amount": 0.10, "currency": "eur", "status": "succeeded"},
            "timestamp": "2026-02-28T12:00:00Z",
            "provider_payment": pe,
        }
        public = get_public_proof(proof)
        assert public["provider_payment"] == pe

    def test_public_proof_without_provider_payment(self):
        proof = {
            "proof_id": "prf_test",
            "spec_version": "1.1",
            "hashes": {"request": "sha256:a", "response": "sha256:b", "chain": "sha256:c"},
            "parties": {"buyer_fingerprint": "x", "seller": "y"},
            "certification_fee": {"transaction_id": "t", "amount": 0.10, "currency": "eur", "status": "succeeded"},
            "timestamp": "2026-02-28T12:00:00Z",
        }
        public = get_public_proof(proof)
        assert public["provider_payment"] is None


# ═══════════════════════════════════════════════════════════
# Integration: proxy endpoint with provider_payment
# ═══════════════════════════════════════════════════════════

class TestProxyIntegration:
    """Integration tests using FastAPI TestClient."""

    def _setup_free_key(self, client):
        """Create a free API key and return it."""
        resp = client.post("/v1/keys/free-signup", json={"email": "receipt-test@example.com"})
        assert resp.status_code == 200
        return resp.json()["api_key"]

    def test_proxy_with_provider_payment(self, client):
        api_key = self._setup_free_key(client)

        mock_target_response = httpx.Response(
            status_code=200,
            json={"result": "ok"},
            headers={"Date": "Sat, 28 Feb 2026 12:00:00 GMT"},
        )

        # Mock fetch_receipt at the proxy module level (avoids httpx double-mock conflict)
        fake_receipt = ReceiptResult(
            receipt_url="https://pay.stripe.com/receipts/payment/test123",
            receipt_type="stripe",
            receipt_fetch_status="fetched",
            receipt_content_hash=hashlib.sha256(SAMPLE_STRIPE_HTML).hexdigest(),
            parsing_status="success",
            parsed_fields={"amount": 25.0, "currency": "usd", "status": "paid", "date": "February 28, 2026"},
        )

        with patch("trust_layer.proxy.httpx.AsyncClient") as mock_proxy_client, \
             patch("trust_layer.proxy.fetch_receipt", new_callable=AsyncMock, return_value=fake_receipt):

            proxy_client = AsyncMock()
            proxy_client.post.return_value = mock_target_response
            proxy_client.get.return_value = mock_target_response
            proxy_client.__aenter__ = AsyncMock(return_value=proxy_client)
            proxy_client.__aexit__ = AsyncMock(return_value=False)
            mock_proxy_client.return_value = proxy_client

            resp = client.post(
                "/v1/proxy",
                json={
                    "target": "https://api.example.com/endpoint",
                    "payload": {"key": "value"},
                    "provider_payment": {
                        "type": "stripe",
                        "receipt_url": "https://pay.stripe.com/receipts/payment/test123",
                    },
                },
                headers={"X-Api-Key": api_key},
            )

        assert resp.status_code == 200
        data = resp.json()
        proof = data.get("proof", {})
        assert proof.get("provider_payment") is not None
        pe = proof["provider_payment"]
        assert pe["type"] == "stripe"
        assert pe["receipt_fetch_status"] == "fetched"
        assert pe["receipt_content_hash"] is not None
        assert pe["receipt_content_hash"].startswith("sha256:")
        assert pe["verification_status"] == "fetched"
        assert proof["spec_version"] == "2.1"

    def test_proxy_without_provider_payment_unchanged(self, client):
        api_key = self._setup_free_key(client)

        mock_response = httpx.Response(
            status_code=200,
            json={"result": "ok"},
        )

        with patch("trust_layer.proxy.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            resp = client.post(
                "/v1/proxy",
                json={
                    "target": "https://api.example.com/endpoint",
                    "payload": {"key": "value"},
                },
                headers={"X-Api-Key": api_key},
            )

        assert resp.status_code == 200
        data = resp.json()
        proof = data.get("proof", {})
        assert proof.get("provider_payment") is None
        assert proof["spec_version"] == "1.2"

    def test_public_proof_endpoint_includes_provider_payment(self, client):
        """Verify that GET /v1/proof/{proof_id} returns provider_payment."""
        api_key = self._setup_free_key(client)

        mock_target = httpx.Response(status_code=200, json={"ok": True})

        fake_receipt = ReceiptResult(
            receipt_url="https://pay.stripe.com/receipts/payment/xyz",
            receipt_type="stripe",
            receipt_fetch_status="fetched",
            receipt_content_hash=hashlib.sha256(SAMPLE_STRIPE_HTML).hexdigest(),
            parsing_status="success",
            parsed_fields={"amount": 25.0, "currency": "usd", "status": "paid"},
        )

        with patch("trust_layer.proxy.httpx.AsyncClient") as mock_proxy, \
             patch("trust_layer.proxy.fetch_receipt", new_callable=AsyncMock, return_value=fake_receipt):

            pc = AsyncMock()
            pc.post.return_value = mock_target
            pc.__aenter__ = AsyncMock(return_value=pc)
            pc.__aexit__ = AsyncMock(return_value=False)
            mock_proxy.return_value = pc

            resp = client.post(
                "/v1/proxy",
                json={
                    "target": "https://api.example.com/test",
                    "payload": {},
                    "provider_payment": {
                        "type": "stripe",
                        "receipt_url": "https://pay.stripe.com/receipts/payment/xyz",
                    },
                },
                headers={"X-Api-Key": api_key},
            )

        assert resp.status_code == 200
        proof_id = resp.json()["proof"]["proof_id"]

        # Now fetch the public proof
        public_resp = client.get(f"/v1/proof/{proof_id}")
        assert public_resp.status_code == 200
        public_data = public_resp.json()
        assert public_data.get("provider_payment") is not None
        assert public_data["provider_payment"]["type"] == "stripe"
        assert public_data["integrity_verified"] is True
