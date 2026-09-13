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


# --- POST /v1/admin/batch/close ---------------------------------------------

def test_batch_close_requires_internal_secret(client):
    resp = client.post("/v1/admin/batch/close")
    assert resp.status_code == 403


def test_batch_close_anchors_the_pending_batch(client):
    """The deployment gate needs a real anchor without waiting out the window."""
    import trust_layer.batch_anchor as ba
    from trust_layer.proofs import load_proof, store_proof

    for i in range(2):
        pid, chain = f"prf_20260913_11000{i}_aaaaaa", f"{i:064x}"
        store_proof(pid, {"proof_id": pid, "spec_version": "3.0",
                          "hashes": {"chain": f"sha256:{chain}"},
                          "batch_anchor": {"status": "pending"}})
        ba.add_proof(pid, chain)

    with patch("trust_layer.routers.admin.INTERNAL_SECRET", "s3cr3t"), \
         patch.object(ba, "_anchor_tsa", lambda root, plan="": {"status": "verified",
                                                                "provider": "freetsa.org"}), \
         patch.object(ba, "_anchor_rekor", lambda root: {"status": "included"}):
        resp = client.post("/v1/admin/batch/close", headers={"X-Internal-Secret": "s3cr3t"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["anchored"] is True and body["tree_size"] == 2
    assert load_proof("prf_20260913_110000_aaaaaa")["batch_anchor"]["status"] == "anchored"


def test_batch_close_on_an_empty_batch_is_not_an_error(client):
    with patch("trust_layer.routers.admin.INTERNAL_SECRET", "s3cr3t"):
        resp = client.post("/v1/admin/batch/close", headers={"X-Internal-Secret": "s3cr3t"})
    assert resp.status_code == 200
    assert resp.json()["anchored"] is False
