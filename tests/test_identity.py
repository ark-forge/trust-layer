"""Tests for agent identity headers — auto-identification + mismatch detection."""

import json
from unittest.mock import patch, AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from trust_layer.app import app
from trust_layer.keys import create_api_key
from trust_layer.credits import add_credits
from trust_layer.config import PROOF_PRICE
from trust_layer.proofs import generate_proof
from trust_layer.proxy import execute_proxy, _update_agent_profile


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def api_key():
    key = create_api_key("cus_id_test", "ref_id_test", "id@test.com", test_mode=True)
    add_credits(key, 10.00, "pi_id_setup")
    return key


def _mock_http_client():
    """Patch HTTP client."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"result": "ok"}
    mock_response.headers = {}

    mock_http = AsyncMock()
    mock_http.post.return_value = mock_response
    mock_http.__aenter__ = AsyncMock(return_value=mock_http)
    mock_http.__aexit__ = AsyncMock(return_value=None)

    return mock_http


# --- 1. Proof with identity headers ---

def test_proof_contains_identity():
    """generate_proof with identity → parties includes agent_identity + agent_version."""
    proof = generate_proof(
        request_data={"target": "https://example.com"},
        response_data={"result": "ok"},
        payment_data={"transaction_id": "pi_test"},
        timestamp="2026-01-01T00:00:00Z",
        buyer_fingerprint="fp_abc",
        seller="example.com",
        agent_identity="my-agent-v1",
        agent_version="1.2.3",
    )
    assert proof["parties"]["agent_identity"] == "my-agent-v1"
    assert proof["parties"]["agent_version"] == "1.2.3"


# --- 2. Proof without identity headers ---

def test_proof_without_identity():
    """generate_proof without identity → agent_identity: None."""
    proof = generate_proof(
        request_data={"target": "https://example.com"},
        response_data={"result": "ok"},
        payment_data={"transaction_id": "pi_test"},
        timestamp="2026-01-01T00:00:00Z",
    )
    assert proof["parties"]["agent_identity"] is None
    assert proof["parties"]["agent_version"] is None


# --- 3. Shadow profile stores identity ---

def test_shadow_profile_stores_identity(tmp_path):
    """_update_agent_profile stores declared_identity + declared_version."""
    import trust_layer.proxy as proxy_mod
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()

    with patch.object(proxy_mod, "AGENTS_DIR", agents_dir):
        _update_agent_profile("mcp_test_ident_key_001", 0.50, "eur", "example.com", True,
                              agent_identity="my-bot", agent_version="2.0")

    profile_path = agents_dir / "mcp_test_ident_k.json"
    profile = json.loads(profile_path.read_text())
    assert profile["declared_identity"] == "my-bot"
    assert profile["declared_version"] == "2.0"


# --- 4. Mismatch detection ---

def test_identity_mismatch_detection(tmp_path):
    """Same key, different identity → identity_mismatch flag."""
    import trust_layer.proxy as proxy_mod
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()

    with patch.object(proxy_mod, "AGENTS_DIR", agents_dir):
        _update_agent_profile("mcp_test_mismatch_001", 0.50, "eur", "example.com", True,
                              agent_identity="agent-X")
        _update_agent_profile("mcp_test_mismatch_001", 0.50, "eur", "example.com", True,
                              agent_identity="agent-Y")

    profile_path = agents_dir / "mcp_test_mismatc.json"
    profile = json.loads(profile_path.read_text())
    assert profile["identity_mismatch"] is True
    assert profile["declared_identity"] == "agent-Y"


# --- 5. Mismatch is permanent ---

def test_identity_mismatch_permanent(tmp_path):
    """After mismatch, returning to original identity still shows mismatch."""
    import trust_layer.proxy as proxy_mod
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()

    with patch.object(proxy_mod, "AGENTS_DIR", agents_dir):
        _update_agent_profile("mcp_test_perm_0001", 0.50, "eur", "example.com", True,
                              agent_identity="agent-X")
        _update_agent_profile("mcp_test_perm_0001", 0.50, "eur", "example.com", True,
                              agent_identity="agent-Y")
        _update_agent_profile("mcp_test_perm_0001", 0.50, "eur", "example.com", True,
                              agent_identity="agent-X")

    profile_path = agents_dir / "mcp_test_perm_00.json"
    profile = json.loads(profile_path.read_text())
    assert profile["identity_mismatch"] is True


# --- 6. No header doesn't clear existing identity ---

def test_no_header_preserves_identity(tmp_path):
    """Calling without identity header doesn't clear existing declared_identity."""
    import trust_layer.proxy as proxy_mod
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()

    with patch.object(proxy_mod, "AGENTS_DIR", agents_dir):
        _update_agent_profile("mcp_test_preserve01", 0.50, "eur", "example.com", True,
                              agent_identity="my-agent")
        _update_agent_profile("mcp_test_preserve01", 0.50, "eur", "example.com", True)

    profile_path = agents_dir / "mcp_test_preserv.json"
    profile = json.loads(profile_path.read_text())
    assert profile["declared_identity"] == "my-agent"


# --- 7. Chain hash unchanged with/without identity (backward compat) ---

def test_chain_hash_unchanged_with_identity():
    """Chain hash must be identical whether identity is provided or not."""
    common = dict(
        request_data={"target": "https://example.com"},
        response_data={"result": "ok"},
        payment_data={"transaction_id": "pi_test"},
        timestamp="2026-01-01T00:00:00Z",
        buyer_fingerprint="fp_abc",
        seller="example.com",
    )
    proof_without = generate_proof(**common)
    proof_with = generate_proof(**common, agent_identity="my-agent", agent_version="1.0")

    assert proof_without["hashes"]["chain"] == proof_with["hashes"]["chain"]


# --- 8. Integration: POST /v1/proxy with identity headers ---

def test_proxy_with_identity_headers(client, api_key):
    """POST /v1/proxy with X-Agent-Identity → proof contains identity."""
    mock_http = _mock_http_client()

    with patch("httpx.AsyncClient", return_value=mock_http), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        r = client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "payload": {}},
            headers={
                "Authorization": f"Bearer {api_key}",
                "X-Agent-Identity": "integration-test-agent",
                "X-Agent-Version": "3.0.0",
            },
        )

    assert r.status_code == 200
    data = r.json()
    assert data["proof"]["parties"]["agent_identity"] == "integration-test-agent"
    assert data["proof"]["parties"]["agent_version"] == "3.0.0"
    assert data["proof"]["identity_consistent"] is True


# --- 9. Integration: GET /v1/proof/{id} shows identity ---

def test_proof_endpoint_shows_identity(client, api_key):
    """GET /v1/proof/{id} → identity_consistent visible publicly."""
    mock_http = _mock_http_client()

    with patch("httpx.AsyncClient", return_value=mock_http), \
         patch("trust_layer.proxy._post_proof_background", new_callable=AsyncMock):

        r = client.post(
            "/v1/proxy",
            json={"target": "https://example.com/api", "payload": {}},
            headers={
                "Authorization": f"Bearer {api_key}",
                "X-Agent-Identity": "public-test-agent",
            },
        )

    assert r.status_code == 200
    proof_id = r.json()["proof"]["proof_id"]

    r2 = client.get(f"/v1/proof/{proof_id}")
    assert r2.status_code == 200
    proof_data = r2.json()
    # parties are private — not exposed in public proof (v1.3.0 privacy split)
    assert "parties" not in proof_data
    # identity_consistent is still publicly visible
    assert proof_data["identity_consistent"] is True
    assert proof_data["integrity_verified"] is True
