"""Tests for visitor attribution (is_external classification + /v1/track/event)."""

import json

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from trust_layer.app import app
    return TestClient(app)


def _read_conversion_events(tmp_path) -> list:
    log = tmp_path / "data" / "conversion_events.jsonl"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]


class TestClassifyVisitor:
    def test_internal_ip_shareholder(self):
        from trust_layer.app import _classify_visitor
        result = _classify_visitor("90.105.196.22", "", "Mozilla/5.0")
        assert result["is_external"] is False
        assert result["source_type"] == "internal"

    def test_internal_ip_server(self):
        from trust_layer.app import _classify_visitor
        result = _classify_visitor("57.131.27.61", "", "Mozilla/5.0")
        assert result["is_external"] is False
        assert result["source_type"] == "internal"

    def test_internal_ip_localhost(self):
        from trust_layer.app import _classify_visitor
        result = _classify_visitor("127.0.0.1", "", "Mozilla/5.0")
        assert result["is_external"] is False
        assert result["source_type"] == "internal"

    def test_bot_user_agent_curl(self):
        from trust_layer.app import _classify_visitor
        result = _classify_visitor("8.8.8.8", "", "curl/7.88.1")
        assert result["is_external"] is False
        assert result["source_type"] == "bot"

    def test_bot_user_agent_python_requests(self):
        from trust_layer.app import _classify_visitor
        result = _classify_visitor("8.8.8.8", "", "python-requests/2.31.0")
        assert result["is_external"] is False
        assert result["source_type"] == "bot"

    def test_bot_user_agent_spider(self):
        from trust_layer.app import _classify_visitor
        result = _classify_visitor("8.8.8.8", "", "Googlebot/2.1")
        assert result["is_external"] is False
        assert result["source_type"] == "bot"

    def test_external_with_google_referer(self):
        from trust_layer.app import _classify_visitor
        result = _classify_visitor("203.0.113.5", "https://www.google.com/search?q=trust+layer", "Mozilla/5.0")
        assert result["is_external"] is True
        assert result["source_type"] == "organic"
        assert result["referer_domain"] == "www.google.com"

    def test_external_direct_no_referer(self):
        from trust_layer.app import _classify_visitor
        result = _classify_visitor("203.0.113.5", "", "Mozilla/5.0")
        assert result["is_external"] is True
        assert result["source_type"] == "direct"

    def test_external_with_internal_referer(self):
        from trust_layer.app import _classify_visitor
        result = _classify_visitor("203.0.113.5", "https://arkforge.tech/en/pricing.html", "Mozilla/5.0")
        assert result["is_external"] is True
        assert result["source_type"] == "direct"

    def test_internal_ip_takes_precedence_over_external_referer(self):
        from trust_layer.app import _classify_visitor
        result = _classify_visitor("90.105.196.22", "https://www.google.com/", "Mozilla/5.0")
        assert result["is_external"] is False
        assert result["source_type"] == "internal"


class TestTrackEvent:
    def test_pricing_page_view_external(self, client, tmp_path):
        resp = client.post(
            "/v1/track/event",
            json={"event": "pricing_page_view", "page_url": "/en/pricing.html"},
            headers={
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                "referer": "https://www.google.com/search?q=trust+layer",
                "x-real-ip": "203.0.113.42",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["received"] is True

        events = _read_conversion_events(tmp_path)
        pv = [e for e in events if e["event"] == "pricing_page_view"]
        assert len(pv) == 1
        assert pv[0]["is_external"] is True
        assert pv[0]["source_type"] == "organic"
        assert pv[0]["referer_domain"] == "www.google.com"

    def test_pricing_page_view_internal(self, client, tmp_path):
        resp = client.post(
            "/v1/track/event",
            json={"event": "pricing_page_view"},
            headers={"x-real-ip": "90.105.196.22"},
        )
        assert resp.status_code == 200
        events = _read_conversion_events(tmp_path)
        pv = [e for e in events if e["event"] == "pricing_page_view"]
        assert len(pv) == 1
        assert pv[0]["is_external"] is False
        assert pv[0]["source_type"] == "internal"

    def test_pricing_page_view_bot(self, client, tmp_path):
        resp = client.post(
            "/v1/track/event",
            json={"event": "pricing_page_view"},
            headers={"user-agent": "python-requests/2.31.0", "x-real-ip": "8.8.8.8"},
        )
        assert resp.status_code == 200
        events = _read_conversion_events(tmp_path)
        pv = [e for e in events if e["event"] == "pricing_page_view"]
        assert len(pv) == 1
        assert pv[0]["is_external"] is False
        assert pv[0]["source_type"] == "bot"

    def test_body_referrer_overrides_http_referer(self, client, tmp_path):
        resp = client.post(
            "/v1/track/event",
            json={
                "event": "pricing_page_view",
                "page_url": "/en/pricing.html",
                "referrer": "dev.to",
            },
            headers={
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                "referer": "https://arkforge.tech/en/pricing.html",
                "x-real-ip": "203.0.113.99",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["received"] is True

        events = _read_conversion_events(tmp_path)
        pv = [e for e in events if e["event"] == "pricing_page_view"]
        assert len(pv) == 1
        assert pv[0]["is_external"] is True
        assert pv[0]["source_type"] == "organic"
        assert pv[0]["referer_domain"] == "dev.to"

    def test_unknown_event_rejected(self, client):
        resp = client.post("/v1/track/event", json={"event": "unknown_event"})
        assert resp.status_code == 200
        assert resp.json()["received"] is False

    def test_invalid_json(self, client):
        resp = client.post("/v1/track/event", content=b"not json", headers={"content-type": "application/json"})
        assert resp.status_code == 200
        assert resp.json()["received"] is False


class TestIsExternalGuardForcesTestMode:
    """Verify that non-external visitors (internal IP, bot) are forced to test mode in checkout endpoints."""

    def test_setup_internal_ip_forces_test_mode(self, client, monkeypatch):
        from unittest.mock import MagicMock, patch
        import trust_layer.app as app_mod
        monkeypatch.setattr(app_mod, "STRIPE_TEST_KEY", "sk_test_fake")
        monkeypatch.setattr(app_mod, "STRIPE_PRO_PRICE_ID_TEST", "price_test_pro")

        mock_customer = MagicMock()
        mock_customer.id = "cus_test_internal"
        mock_list = MagicMock()
        mock_list.data = []
        mock_session = MagicMock()
        mock_session.url = "https://checkout.stripe.com/pay/cs_test"
        mock_session.id = "cs_test"

        with patch("stripe.Customer.list", return_value=mock_list), \
             patch("stripe.Customer.create", return_value=mock_customer) as mock_create, \
             patch("stripe.checkout.Session.create", return_value=mock_session) as mock_checkout:
            r = client.post("/v1/keys/setup", json={
                "email": "real-user@gmail.com",
            }, headers={"x-real-ip": "57.131.27.61"})

        assert r.status_code == 200
        assert mock_create.call_args.kwargs["api_key"] == "sk_test_fake"
        assert mock_checkout.call_args.kwargs["metadata"]["stripe_mode"] == "test"

    def test_setup_bot_ua_keeps_live_mode(self, client, monkeypatch):
        """Bot-like UAs (python-requests, curl) should NOT be forced to test mode —
        real SDK users would be silently blocked from paying. Rate-limiting protects against abuse."""
        from unittest.mock import MagicMock, patch
        import trust_layer.app as app_mod
        monkeypatch.setattr(app_mod, "STRIPE_TEST_KEY", "sk_test_fake")
        monkeypatch.setattr(app_mod, "STRIPE_PRO_PRICE_ID_TEST", "price_test_pro")

        mock_customer = MagicMock()
        mock_customer.id = "cus_live_sdk"
        mock_list = MagicMock()
        mock_list.data = []
        mock_session = MagicMock()
        mock_session.url = "https://checkout.stripe.com/pay/cs_live"
        mock_session.id = "cs_live"

        with patch("stripe.Customer.list", return_value=mock_list), \
             patch("stripe.Customer.create", return_value=mock_customer) as mock_create, \
             patch("stripe.checkout.Session.create", return_value=mock_session) as mock_checkout:
            r = client.post("/v1/keys/setup", json={
                "email": "real-user@gmail.com",
            }, headers={"user-agent": "python-requests/2.31.0", "x-real-ip": "8.8.8.8"})

        assert r.status_code == 200
        assert mock_create.call_args.kwargs["api_key"] != "sk_test_fake"
        assert mock_checkout.call_args.kwargs["metadata"]["stripe_mode"] == "live"
