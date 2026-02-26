"""Tests for the Triptyque de la Preuve — 3 levels of ArkForge watermark."""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from trust_layer.proxy import _inject_digital_stamp, _submit_archive_org, execute_proxy
from trust_layer.proofs import verify_proof_integrity, store_proof, load_proof, get_public_proof
from trust_layer.templates import _esc, render_proof_page
from trust_layer.payments.base import ChargeResult


# --- Helpers ---

def _make_proof_record(proof_id="prf_20260225_120000_abc123"):
    """Create a minimal proof record for testing."""
    return {
        "proof_id": proof_id,
        "verification_url": f"https://test.arkforge.fr/v1/proof/{proof_id}",
        "verification_algorithm": "https://test.arkforge.fr/docs/verification",
        "hashes": {
            "request": "sha256:aaa111",
            "response": "sha256:bbb222",
            "chain": "sha256:ccc333",
        },
        "parties": {
            "buyer_fingerprint": "buyer_hash_xyz",
            "seller": "example.com",
            "agent_identity": None,
            "agent_version": None,
        },
        "payment": {
            "provider": "stripe",
            "transaction_id": "pi_test_triptyque",
            "amount": 0.50,
            "currency": "eur",
            "status": "succeeded",
            "receipt_url": "https://pay.stripe.com/receipts/test",
        },
        "timestamp": "2026-02-25T12:00:00Z",
        "timestamp_authority": {"status": "submitted", "provider": "freetsa.org", "tsr_url": f"https://test.arkforge.fr/v1/proof/{proof_id}/tsr"},
        "identity_consistent": None,
    }


def _mock_full_proxy():
    """Return context managers for a full proxy mock (payment + service OK)."""
    mock_charge = ChargeResult(
        provider="stripe",
        transaction_id="pi_test_triptyque",
        amount=0.50,
        currency="eur",
        status="succeeded",
        receipt_url="https://pay.stripe.com/receipts/test",
    )
    mock_provider = AsyncMock()
    mock_provider.charge.return_value = mock_charge

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"result": "scan_complete", "score": 85}

    mock_client = AsyncMock()
    mock_client.post.return_value = mock_response
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    return mock_provider, mock_client


def _mock_error_proxy():
    """Return context managers for a proxy mock where service returns 500."""
    mock_charge = ChargeResult(
        provider="stripe",
        transaction_id="pi_test_err",
        amount=0.50,
        currency="eur",
        status="succeeded",
        receipt_url=None,
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

    return mock_provider, mock_client


# ============================================================
# Level 1 — Digital Stamp
# ============================================================

class TestLevel1DigitalStamp:

    @pytest.mark.asyncio
    async def test_attestation_present_in_success(self, test_api_key):
        """Attestation is injected into successful proxy responses."""
        mock_provider, mock_client = _mock_full_proxy()

        with patch("trust_layer.proxy.get_provider", return_value=mock_provider), \
             patch("httpx.AsyncClient", return_value=mock_client), \
             patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

            result = await execute_proxy(
                target="https://example.com/api/scan",
                method="POST",
                payload={"repo_url": "https://github.com/test/repo"},
                amount=0.50,
                currency="eur",
                api_key=test_api_key,
            )

        body = result["service_response"]["body"]
        assert "_arkforge_attestation" in body
        att = body["_arkforge_attestation"]
        assert att["id"].startswith("prf_")
        assert "seal" in att
        assert att["status"] == "VERIFIED_TRANSACTION"

    @pytest.mark.asyncio
    async def test_no_attestation_on_error_upstream(self, test_api_key):
        """No attestation when upstream service returns 500."""
        mock_provider, mock_client = _mock_error_proxy()

        with patch("trust_layer.proxy.get_provider", return_value=mock_provider), \
             patch("httpx.AsyncClient", return_value=mock_client), \
             patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

            result = await execute_proxy(
                target="https://example.com/api/fail",
                method="POST",
                payload={},
                amount=0.50,
                currency="eur",
                api_key=test_api_key,
            )

        # Error path — no attestation injected (even if service_response exists)
        sr = result.get("service_response", {})
        body = sr.get("body", {})
        assert "_arkforge_attestation" not in body

    @pytest.mark.asyncio
    async def test_no_attestation_on_raw_text(self, test_api_key):
        """No attestation when response is _raw_text (non-JSON)."""
        mock_charge = ChargeResult(
            provider="stripe", transaction_id="pi_test_raw",
            amount=0.50, currency="eur", status="succeeded", receipt_url=None,
        )
        mock_provider = AsyncMock()
        mock_provider.charge.return_value = mock_charge

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = Exception("not JSON")
        mock_response.text = "<html>Hello</html>"

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("trust_layer.proxy.get_provider", return_value=mock_provider), \
             patch("httpx.AsyncClient", return_value=mock_client), \
             patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

            result = await execute_proxy(
                target="https://example.com/api/html",
                method="POST",
                payload={},
                amount=0.50,
                currency="eur",
                api_key=test_api_key,
            )

        body = result["service_response"]["body"]
        assert "_raw_text" in body
        assert "_arkforge_attestation" not in body

    @pytest.mark.asyncio
    async def test_chain_hash_not_affected(self, test_api_key):
        """Chain hash integrity is NOT affected by attestation injection."""
        mock_provider, mock_client = _mock_full_proxy()

        with patch("trust_layer.proxy.get_provider", return_value=mock_provider), \
             patch("httpx.AsyncClient", return_value=mock_client), \
             patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

            result = await execute_proxy(
                target="https://example.com/api/scan",
                method="POST",
                payload={"test": True},
                amount=0.50,
                currency="eur",
                api_key=test_api_key,
            )

        # Attestation is present
        assert "_arkforge_attestation" in result["service_response"]["body"]

        # But proof integrity is still valid (hash was computed BEFORE injection)
        proof_id = result["proof"]["proof_id"]
        stored = load_proof(proof_id)
        assert stored is not None
        assert verify_proof_integrity(stored)

    def test_inject_digital_stamp_nominal(self):
        """Unit test: _inject_digital_stamp injects correctly."""
        proof_record = _make_proof_record()
        result = {
            "proof": proof_record,
            "service_response": {
                "status_code": 200,
                "body": {"data": "ok"},
            },
        }
        _inject_digital_stamp(result, proof_record)
        att = result["service_response"]["body"]["_arkforge_attestation"]
        assert att["id"] == "prf_20260225_120000_abc123"
        assert att["seal"] == "https://test.arkforge.fr/v1/proof/prf_20260225_120000_abc123"
        assert att["status"] == "VERIFIED_TRANSACTION"

    def test_inject_digital_stamp_skip_no_service_response(self):
        """Unit test: _inject_digital_stamp skips when no service_response."""
        proof_record = _make_proof_record()
        result = {"proof": proof_record}
        _inject_digital_stamp(result, proof_record)
        assert "service_response" not in result

    def test_inject_digital_stamp_skip_on_error(self):
        """Unit test: _inject_digital_stamp skips on error results."""
        proof_record = _make_proof_record()
        result = {
            "error": {"code": "service_error", "message": "fail", "status": 502},
            "service_response": {"status_code": 500, "body": {"error": "oops"}},
        }
        _inject_digital_stamp(result, proof_record)
        assert "_arkforge_attestation" not in result["service_response"]["body"]


# ============================================================
# Level 2 — Ghost Stamp
# ============================================================

class TestLevel2GhostStamp:

    def test_four_headers_on_success(self, client, test_api_key):
        """4 X-ArkForge-* headers present on successful proxy response."""
        mock_provider, mock_client = _mock_full_proxy()

        with patch("trust_layer.proxy.get_provider", return_value=mock_provider), \
             patch("httpx.AsyncClient", return_value=mock_client), \
             patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

            resp = client.post("/v1/proxy", json={
                "target": "https://example.com/api",
                "amount": 0.50,
                "currency": "eur",
                "payload": {"test": True},
            }, headers={"X-Api-Key": test_api_key})

        assert resp.status_code == 200
        assert "x-arkforge-proof" in resp.headers
        assert resp.headers["x-arkforge-verified"] == "true"
        assert resp.headers["x-arkforge-proof-id"].startswith("prf_")
        assert "/v/" in resp.headers["x-arkforge-trust-link"]

    def test_verified_false_on_service_error(self, client, test_api_key):
        """X-ArkForge-Verified is false when upstream returns 500."""
        mock_provider, mock_client = _mock_error_proxy()

        with patch("trust_layer.proxy.get_provider", return_value=mock_provider), \
             patch("httpx.AsyncClient", return_value=mock_client), \
             patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

            resp = client.post("/v1/proxy", json={
                "target": "https://example.com/api/fail",
                "amount": 0.50,
                "currency": "eur",
                "payload": {},
            }, headers={"X-Api-Key": test_api_key})

        assert resp.headers["x-arkforge-verified"] == "false"

    def test_backward_compat_proof_header(self, client, test_api_key):
        """X-ArkForge-Proof header still present (backward compat)."""
        mock_provider, mock_client = _mock_full_proxy()

        with patch("trust_layer.proxy.get_provider", return_value=mock_provider), \
             patch("httpx.AsyncClient", return_value=mock_client), \
             patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

            resp = client.post("/v1/proxy", json={
                "target": "https://example.com/api",
                "amount": 0.50,
                "currency": "eur",
                "payload": {},
            }, headers={"X-Api-Key": test_api_key})

        assert "x-arkforge-proof" in resp.headers
        assert "/v1/proof/prf_" in resp.headers["x-arkforge-proof"]


# ============================================================
# Level 3 — Visual Stamp
# ============================================================

class TestLevel3VisualStamp:

    def _store_test_proof(self, proof_id="prf_test_visual"):
        """Store a proof and return its ID."""
        proof_record = _make_proof_record(proof_id)
        store_proof(proof_id, proof_record)
        return proof_id

    def test_html_on_accept_text_html(self, client):
        """Accept: text/html returns HTML response."""
        pid = self._store_test_proof()
        resp = client.get(f"/v1/proof/{pid}", headers={"Accept": "text/html"})
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "ArkForge" in resp.text
        assert "VERIFIED" in resp.text or "INTEGRITY" in resp.text
        assert pid in resp.text

    def test_json_on_accept_application_json(self, client):
        """Accept: application/json returns JSON response."""
        pid = self._store_test_proof("prf_test_json")
        resp = client.get(f"/v1/proof/{pid}", headers={"Accept": "application/json"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["proof_id"] == pid

    def test_json_on_no_accept(self, client):
        """No Accept header returns JSON (backward compat)."""
        pid = self._store_test_proof("prf_test_noaccept")
        resp = client.get(f"/v1/proof/{pid}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["proof_id"] == pid

    def test_json_wins_over_html(self, client):
        """Accept: application/json, text/html — JSON wins."""
        pid = self._store_test_proof("prf_test_both")
        resp = client.get(f"/v1/proof/{pid}", headers={"Accept": "application/json, text/html"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["proof_id"] == pid

    def test_green_badge_verified(self, client):
        """Badge is green (#22c55e) on verified proof with OTS verified."""
        pid = "prf_test_green"
        proof = _make_proof_record(pid)
        # Make TSA verified and set real hashes for integrity to pass
        proof["timestamp_authority"]["status"] = "verified"
        # We need integrity to pass — store raw data so verify_proof_integrity works
        from trust_layer.proofs import sha256_hex, canonical_json
        req_data = {"target": "https://example.com", "method": "POST", "payload": {}, "amount": 0.5, "currency": "eur"}
        resp_data = {"result": "ok"}
        req_hash = sha256_hex(canonical_json(req_data))
        resp_hash = sha256_hex(canonical_json(resp_data))
        chain_input = req_hash + resp_hash + "pi_test_triptyque" + "2026-02-25T12:00:00Z" + "buyer_hash_xyz" + "example.com"
        chain_hash = sha256_hex(chain_input)
        proof["hashes"] = {
            "request": f"sha256:{req_hash}",
            "response": f"sha256:{resp_hash}",
            "chain": f"sha256:{chain_hash}",
        }
        store_proof(pid, proof)

        resp = client.get(f"/v1/proof/{pid}", headers={"Accept": "text/html"})
        assert resp.status_code == 200
        assert "#22c55e" in resp.text
        assert "VERIFIED" in resp.text

    def test_html_shows_payment_info(self, client):
        """HTML page displays payment information."""
        pid = self._store_test_proof("prf_test_payment")
        resp = client.get(f"/v1/proof/{pid}", headers={"Accept": "text/html"})
        assert resp.status_code == 200
        assert "0.5" in resp.text
        assert "Stripe" in resp.text

    def test_short_url_redirects(self, client):
        """GET /v/{proof_id} returns 302 redirect to full path."""
        pid = self._store_test_proof("prf_test_redirect")
        resp = client.get(f"/v/{pid}", follow_redirects=False)
        assert resp.status_code == 302
        assert f"/v1/proof/{pid}" in resp.headers["location"]

    def test_short_url_404(self, client):
        """GET /v/prf_nonexistent returns 404."""
        resp = client.get("/v/prf_nonexistent")
        assert resp.status_code == 404


# ============================================================
# Unit: _esc() anti-XSS
# ============================================================

class TestEscape:

    def test_esc_html_entities(self):
        assert _esc('<script>alert("xss")</script>') == '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'

    def test_esc_none(self):
        assert _esc(None) == ""

    def test_esc_number(self):
        assert _esc(42) == "42"

    def test_esc_ampersand(self):
        assert _esc("a&b") == "a&amp;b"


# ============================================================
# Archive.org Independent Witness
# ============================================================

class TestArchiveOrgWitness:

    def test_html_shows_archive_org_green_when_snapshot_exists(self, client):
        """Archive.org witness is green with link when snapshot exists."""
        pid = "prf_test_archive_green"
        proof = _make_proof_record(pid)
        proof["archive_org"] = {
            "status": "submitted",
            "snapshot_url": "https://web.archive.org/web/20260225/https://test.arkforge.fr/v1/proof/prf_test_archive_green",
            "submitted_at": "2026-02-25T12:00:00+00:00",
        }
        store_proof(pid, proof)

        resp = client.get(f"/v1/proof/{pid}", headers={"Accept": "text/html"})
        assert resp.status_code == 200
        assert "Archive.org" in resp.text
        assert "#22c55e" in resp.text  # green dot
        assert "web.archive.org" in resp.text
        assert "public snapshot preserved" in resp.text

    def test_html_shows_archive_org_grey_when_no_snapshot(self, client):
        """Archive.org witness is grey when no snapshot."""
        pid = "prf_test_archive_grey"
        proof = _make_proof_record(pid)
        # No archive_org key at all
        store_proof(pid, proof)

        resp = client.get(f"/v1/proof/{pid}", headers={"Accept": "text/html"})
        assert resp.status_code == 200
        assert "Archive.org" in resp.text
        assert "#475569" in resp.text  # grey dot
        assert "snapshot not yet available" in resp.text

    def test_json_includes_archive_org_field(self):
        """get_public_proof() includes archive_org field."""
        proof = _make_proof_record()
        proof["archive_org"] = {
            "status": "submitted",
            "snapshot_url": "https://web.archive.org/web/20260225/https://test.arkforge.fr/v1/proof/prf_test",
            "submitted_at": "2026-02-25T12:00:00+00:00",
        }
        public = get_public_proof(proof)
        assert "archive_org" in public
        assert public["archive_org"]["status"] == "submitted"

    def test_json_archive_org_none_when_absent(self):
        """get_public_proof() returns None for archive_org when absent."""
        proof = _make_proof_record()
        public = get_public_proof(proof)
        assert public["archive_org"] is None

    @pytest.mark.asyncio
    async def test_archive_org_called_in_execute_proxy(self, test_api_key):
        """_archive_org_background is fired during execute_proxy."""
        import asyncio
        mock_provider, mock_client = _mock_full_proxy()
        archive_result = {
            "status": "submitted",
            "snapshot_url": "https://web.archive.org/web/20260225/https://test.arkforge.fr/v1/proof/prf_test",
            "submitted_at": "2026-02-25T12:00:00+00:00",
        }

        with patch("trust_layer.proxy.get_provider", return_value=mock_provider), \
             patch("httpx.AsyncClient", return_value=mock_client), \
             patch("trust_layer.proxy.submit_hash", return_value=None), \
             patch("trust_layer.proxy.send_proof_email"), \
             patch("trust_layer.proxy._submit_archive_org", return_value=archive_result):

            result = await execute_proxy(
                target="https://example.com/api/scan",
                method="POST",
                payload={"test": True},
                amount=0.50,
                currency="eur",
                api_key=test_api_key,
            )
            # Let the background task complete
            await asyncio.sleep(0.1)

        # Background task updates proof on disk
        proof_id = result["proof"]["proof_id"]
        stored = load_proof(proof_id)
        assert stored["archive_org"] == archive_result

    @pytest.mark.asyncio
    async def test_archive_org_failure_does_not_break_flow(self, test_api_key):
        """When _submit_archive_org returns None, flow continues without archive_org."""
        import asyncio
        mock_provider, mock_client = _mock_full_proxy()

        with patch("trust_layer.proxy.get_provider", return_value=mock_provider), \
             patch("httpx.AsyncClient", return_value=mock_client), \
             patch("trust_layer.proxy.submit_hash", return_value=None), \
             patch("trust_layer.proxy.send_proof_email"), \
             patch("trust_layer.proxy._submit_archive_org", return_value=None):

            result = await execute_proxy(
                target="https://example.com/api/scan",
                method="POST",
                payload={"test": True},
                amount=0.50,
                currency="eur",
                api_key=test_api_key,
            )
            await asyncio.sleep(0.1)

        proof_id = result["proof"]["proof_id"]
        stored = load_proof(proof_id)
        assert stored.get("archive_org") is None
