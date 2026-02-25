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
    monkeypatch.setattr(cfg, "TRUST_LAYER_BASE_URL", "https://test.arkforge.fr")

    for d in ["data", "proofs", "data/idempotency", "data/agents", "data/services"]:
        (tmp_path / d).mkdir(parents=True, exist_ok=True)

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

    import trust_layer.app as app_mod
    monkeypatch.setattr(app_mod, "TRUST_LAYER_BASE_URL", "https://test.arkforge.fr")


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
