"""Shared fixtures for trust layer tests."""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Set test environment before importing anything
_tmpdir = tempfile.mkdtemp(prefix="trust_layer_test_")
os.environ["SETTINGS_ENV_PATH"] = "/dev/null"


@pytest.fixture(autouse=True)
def _isolate_data(tmp_path, monkeypatch):
    """Isolate all data paths to tmp_path for each test."""
    import trust_layer.config as cfg

    monkeypatch.setattr(cfg, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(cfg, "PROOFS_DIR", tmp_path / "proofs")
    monkeypatch.setattr(cfg, "API_KEYS_FILE", tmp_path / "data" / "api_keys.json")
    monkeypatch.setattr(cfg, "RATE_LIMITS_FILE", tmp_path / "data" / "rate_limits.json")
    monkeypatch.setattr(cfg, "IDEMPOTENCY_DIR", tmp_path / "data" / "idempotency")
    monkeypatch.setattr(cfg, "AGENTS_DIR", tmp_path / "data" / "agents")
    monkeypatch.setattr(cfg, "SERVICES_DIR", tmp_path / "data" / "services")
    monkeypatch.setattr(cfg, "BACKGROUND_TASKS_LOG", tmp_path / "data" / "background_tasks_log.jsonl")
    monkeypatch.setattr(cfg, "PROOF_ACCESS_LOG", tmp_path / "data" / "proof_access_log.jsonl")
    monkeypatch.setattr(cfg, "TRUST_LAYER_BASE_URL", "https://test.arkforge.fr")

    for d in ["data", "proofs", "data/idempotency", "data/agents", "data/services"]:
        (tmp_path / d).mkdir(parents=True, exist_ok=True)

    # Generate a test signing key for Ed25519 signature tests
    from trust_layer.crypto import generate_keypair, load_signing_key, get_public_key_b64url
    test_key_path = tmp_path / ".signing_key.pem"
    test_pubkey = generate_keypair(test_key_path)
    test_privkey = load_signing_key(test_key_path)
    monkeypatch.setattr(cfg, "_SIGNING_KEY", test_privkey)
    monkeypatch.setattr(cfg, "ARKFORGE_PUBLIC_KEY", test_pubkey)

    # Also patch the module-level imports in keys, rate_limit, proofs, proxy
    import trust_layer.keys as keys_mod
    import trust_layer.rate_limit as rl_mod
    import trust_layer.proofs as proofs_mod
    import trust_layer.proxy as proxy_mod

    monkeypatch.setattr(keys_mod, "API_KEYS_FILE", tmp_path / "data" / "api_keys.json")
    monkeypatch.setattr(rl_mod, "RATE_LIMITS_FILE", tmp_path / "data" / "rate_limits.json")
    monkeypatch.setattr(proofs_mod, "PROOFS_DIR", tmp_path / "proofs")
    monkeypatch.setattr(proxy_mod, "IDEMPOTENCY_DIR", tmp_path / "data" / "idempotency")
    monkeypatch.setattr(proxy_mod, "AGENTS_DIR", tmp_path / "data" / "agents")
    monkeypatch.setattr(proxy_mod, "SERVICES_DIR", tmp_path / "data" / "services")
    monkeypatch.setattr(proxy_mod, "TRUST_LAYER_BASE_URL", "https://test.arkforge.fr")
    monkeypatch.setattr(proxy_mod, "ARKFORGE_PUBLIC_KEY", test_pubkey)
    monkeypatch.setattr(proxy_mod, "BACKGROUND_TASKS_LOG", tmp_path / "data" / "background_tasks_log.jsonl")

    # Patch credits module
    import trust_layer.credits as credits_mod
    monkeypatch.setattr(credits_mod, "API_KEYS_FILE", tmp_path / "data" / "api_keys.json")
    monkeypatch.setattr(credits_mod, "CREDIT_TRANSACTIONS_LOG", tmp_path / "data" / "credit_transactions.jsonl")

    import trust_layer.app as app_mod
    monkeypatch.setattr(app_mod, "TRUST_LAYER_BASE_URL", "https://test.arkforge.fr")
    monkeypatch.setattr(app_mod, "ARKFORGE_PUBLIC_KEY", test_pubkey)
    monkeypatch.setattr(app_mod, "PROOF_ACCESS_LOG", tmp_path / "data" / "proof_access_log.jsonl")
    monkeypatch.setattr(app_mod, "WEBHOOK_IDEMPOTENCY_FILE", tmp_path / "data" / "webhook_idempotency.jsonl")

    # DNS rebinding mock — prevent real DNS resolution in proxy tests
    monkeypatch.setattr(proxy_mod, "_check_no_private_dns", AsyncMock(return_value=None))

    # Rekor — isolate to prevent real network calls in tests
    import trust_layer.rekor as rekor_mod
    monkeypatch.setattr(rekor_mod, "REKOR_URL", "https://rekor.test.internal")

    # Redis isolation — force fallback JSON pour tous les tests existants.
    # Les tests Redis-spécifiques mockent get_redis() explicitement.
    import trust_layer.redis_client as redis_mod
    monkeypatch.setattr(redis_mod, "_redis_client", None)
    monkeypatch.setattr(redis_mod, "_redis_checked", True)

    # Email isolation — la vault charge smtp.password dans os.environ même si
    # SETTINGS_ENV_PATH=/dev/null. On neutralise _send_email au niveau du module
    # pour éviter tout envoi SMTP réel (Resend) pendant les tests.
    import trust_layer.email_notify as email_mod
    monkeypatch.setattr(email_mod, "_send_email", lambda *a, **kw: None)

    # --- Feature routers: assess + compliance ---
    monkeypatch.setattr(cfg, "MCP_BASELINES_DIR", tmp_path / "data" / "mcp_baselines")
    monkeypatch.setattr(cfg, "ASSESSMENTS_DIR", tmp_path / "data" / "assessments")
    monkeypatch.setattr(cfg, "PROOF_INDEX_FILE", tmp_path / "data" / "proof_index.jsonl")
    for _feat_dir in ["data/mcp_baselines", "data/assessments"]:
        (tmp_path / _feat_dir).mkdir(parents=True, exist_ok=True)

    import trust_layer.mcp_assess as assess_mod
    monkeypatch.setattr(assess_mod, "MCP_BASELINES_DIR", tmp_path / "data" / "mcp_baselines")
    monkeypatch.setattr(assess_mod, "ASSESSMENTS_DIR", tmp_path / "data" / "assessments")

    import trust_layer.proof_index as pidx_mod
    monkeypatch.setattr(pidx_mod, "PROOF_INDEX_FILE", tmp_path / "data" / "proof_index.jsonl")
    # Reset proof_index singleton so each test gets a fresh File backend pointing to tmp_path
    monkeypatch.setattr(pidx_mod, "_index_backend", None)
    monkeypatch.setattr(pidx_mod, "_index_checked", False)


@pytest.fixture
def test_api_key(tmp_path):
    """Create a test API key and return (key, key_info)."""
    from trust_layer.keys import create_api_key
    key = create_api_key("cus_test123", "ref_test123", "test@example.com", test_mode=True)
    return key


@pytest.fixture
def mock_stripe_provider():
    """Return a mock payment provider that always succeeds."""
    from trust_layer.payments.base import ChargeResult
    provider = AsyncMock()
    provider.charge.return_value = ChargeResult(
        provider="stripe",
        transaction_id="pi_test_123456",
        amount=0.50,
        currency="eur",
        status="succeeded",
        receipt_url="https://pay.stripe.com/receipts/test",
    )
    provider.find_payment_method.return_value = "pm_test_123"
    return provider


@pytest.fixture
def client():
    """FastAPI test client."""
    from trust_layer.app import app
    return TestClient(app)
