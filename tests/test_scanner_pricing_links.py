"""Les retours de checkout et d'essai pointent sur la page tarifs du bon produit.

Le scanner a sa propre page (/{lang}/scanner-pricing.html) ; /{lang}/pricing.html
ne porte plus que le Trust Layer.
"""

from unittest.mock import MagicMock, patch

import pytest

HEADERS = {"user-agent": "Mozilla/5.0", "x-real-ip": "8.8.8.8"}


@pytest.fixture
def stripe_live(monkeypatch):
    import trust_layer.app as app_mod
    monkeypatch.setattr(app_mod, "_SETUP_RATE", {})
    monkeypatch.setattr(app_mod, "_SETUP_RATE_EMAIL", {})
    monkeypatch.setattr(app_mod, "STRIPE_LIVE_KEY", "sk_live_fake")
    monkeypatch.setattr(app_mod, "STRIPE_PRO_PRICE_ID", "price_live_pro")
    monkeypatch.setattr(app_mod, "STRIPE_SCANNER_PRO_PRICE_ID", "price_live_scanner")


def _stripe_mocks():
    customers = MagicMock()
    customers.data = []
    customer = MagicMock()
    customer.id = "cus_fake"
    session = MagicMock()
    session.url = "https://checkout.stripe.com/pay/cs_fake"
    session.id = "cs_fake"
    return (
        patch("stripe.Customer.list", return_value=customers),
        patch("stripe.Customer.create", return_value=customer),
        patch("stripe.checkout.Session.create", return_value=session),
    )


def _setup(client, product):
    lst, create, checkout = _stripe_mocks()
    with lst, create, checkout as mock_checkout:
        r = client.post("/v1/keys/setup", json={
            "email": "buyer@company.com", "plan": "pro", "product": product, "lang": "en",
        }, headers=HEADERS)
    assert r.status_code == 200
    return mock_checkout.call_args.kwargs["cancel_url"]


def _trial(client, product, stripe_fails=False):
    lst, create, checkout = _stripe_mocks()
    if stripe_fails:
        checkout = patch("stripe.checkout.Session.create", side_effect=RuntimeError("stripe down"))
    with patch("trust_layer.app.find_active_trial_by_email", return_value=None), \
         patch("trust_layer.app.create_trial_key", return_value="tl_trial_fake"), \
         patch("trust_layer.keys.load_api_keys", return_value={"tl_trial_fake": {"trial_ends": "2026-10-01"}}), \
         lst, create, checkout as mock_checkout:
        r = client.post("/v1/keys/trial", json={
            "email": "trialist@company.com", "product": product, "lang": "fr",
        }, headers=HEADERS)
    assert r.status_code == 200
    return r.json(), mock_checkout


class TestCheckoutCancel:
    def test_scanner_cancel_returns_to_scanner_pricing(self, client, stripe_live):
        url = _setup(client, "scanner")
        assert url.startswith("https://arkforge.tech/en/scanner-pricing.html?")
        assert "intent=pro" in url
        assert "#" not in url

    def test_trust_layer_cancel_stays_on_pricing(self, client, stripe_live):
        url = _setup(client, "trust_layer")
        assert url.startswith("https://arkforge.tech/en/pricing.html?")
        assert url.endswith("#trust")


class TestAbandonedCheckoutEmail:
    def _body(self, **kwargs):
        from trust_layer import email_notify
        with patch.object(email_notify, "_send_email") as send:
            email_notify.send_checkout_abandoned_email("buyer@company.com", **kwargs)
        return send.call_args.args[2]

    def test_scanner_restart_link_is_scanner_pricing(self):
        body = self._body(plan="pro", lang="en", product="scanner_pro_subscription")
        assert "https://arkforge.tech/en/scanner-pricing.html?intent=pro" in body

    def test_trust_layer_restart_link_stays_on_pricing(self):
        body = self._body(plan="pro", lang="en", product="trust_layer_pro_subscription")
        assert "https://arkforge.tech/en/pricing.html?intent=pro" in body


class TestTrialLinks:
    def test_scanner_trial_cancel_returns_to_scanner_pricing(self, client, stripe_live):
        _, mock_checkout = _trial(client, "scanner")
        url = mock_checkout.call_args.kwargs["cancel_url"]
        assert url.startswith("https://arkforge.tech/fr/scanner-pricing.html?")
        assert "#" not in url

    def test_scanner_trial_fallback_upgrade_url_is_scanner_pricing(self, client, stripe_live):
        data, _ = _trial(client, "scanner", stripe_fails=True)
        assert data["upgrade_url"].startswith("https://arkforge.tech/fr/scanner-pricing.html?")
        assert "#" not in data["upgrade_url"]

    def test_trust_layer_trial_fallback_upgrade_url_stays_on_pricing(self, client, stripe_live):
        data, _ = _trial(client, "trust_layer", stripe_fails=True)
        assert data["upgrade_url"].startswith("https://arkforge.tech/fr/pricing.html?")
        assert data["upgrade_url"].endswith("#trust")
