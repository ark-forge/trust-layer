"""Tests for /v1/admin/smoke/* — admin lifecycle endpoints."""

from unittest.mock import patch


def test_smoke_setup_requires_internal_secret(client):
    resp = client.post("/v1/admin/smoke/setup")
    assert resp.status_code == 403


def test_smoke_setup_never_returns_a_webhook_secret(client):
    """The response used to carry STRIPE_WEBHOOK_SECRET_LIVE.

    Combined with the 2026-09-11 proxy leak, that turned any holder of
    X-Internal-Secret into someone able to forge signed Stripe events and mint
    arbitrary paid keys. The secret must never leave the server, whatever the
    caller's credentials.
    """
    with patch("trust_layer.routers.admin.INTERNAL_SECRET", "s3cr3t"):
        resp = client.post("/v1/admin/smoke/setup", headers={"X-Internal-Secret": "s3cr3t"})

    assert resp.status_code == 200
    body = resp.json()
    assert "webhook_secret" not in body
    assert not [v for v in body.values() if isinstance(v, str) and v.startswith("whsec_")]
    assert body["free_key"].startswith("mcp_free_")
