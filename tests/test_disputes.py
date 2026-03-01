"""Tests for the dispute system — creation, resolution, anti-abuse."""

import hashlib
from datetime import datetime, timezone, timedelta

import pytest

from trust_layer.disputes import (
    create_dispute,
    get_agent_disputes,
    resolve_dispute,
    DISPUTES_DIR,
)
from trust_layer.reputation import REPUTATION_CONFIG
from trust_layer.persistence import save_json, load_json
from trust_layer.proofs import store_proof


API_KEY = "mcp_test_" + "a" * 48
BUYER_FP = hashlib.sha256(API_KEY.encode()).hexdigest()


def _make_proof(proof_id, buyer_fp=BUYER_FP, seller="example.com",
                status_code=200, success=True, days_ago=0):
    """Create and store a minimal proof for testing."""
    now = datetime.now(timezone.utc) - timedelta(days=days_ago)
    proof = {
        "proof_id": proof_id,
        "spec_version": "1.1",
        "hashes": {
            "request": "sha256:aaa",
            "response": "sha256:bbb",
            "chain": "sha256:ccc",
        },
        "parties": {
            "buyer_fingerprint": buyer_fp,
            "seller": seller,
        },
        "payment": {"transaction_id": "test_tx", "amount": 0.10, "currency": "eur", "status": "succeeded"},
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "transaction_success": success,
        "upstream_status_code": status_code,
    }
    store_proof(proof_id, proof)
    return proof


def _make_agent_profile(tmp_path, monkeypatch, agent_fp=BUYER_FP):
    """Create agent profile in the test agents dir."""
    import trust_layer.disputes as disp_mod
    import trust_layer.reputation as rep_mod
    agents_dir = tmp_path / "data" / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(disp_mod, "AGENTS_DIR", agents_dir)
    monkeypatch.setattr(rep_mod, "AGENTS_DIR", agents_dir)
    disputes_dir = tmp_path / "data" / "disputes"
    disputes_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(disp_mod, "DISPUTES_DIR", disputes_dir)
    rep_dir = tmp_path / "data" / "reputation"
    rep_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(rep_mod, "REPUTATION_DIR", rep_dir)

    profile = {
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "transactions_total": 10,
        "transactions_succeeded": 9,
        "services_used": ["example.com"],
        "lost_disputes": 0,
        "disputes_filed": 0,
        "disputes_won": 0,
        "disputes_lost": 0,
    }
    save_json(agents_dir / f"{agent_fp[:16]}.json", profile)
    return agents_dir


class TestResolveDispute:
    """Unit tests for dispute resolution logic."""

    def test_upheld_buyer_contests_success_with_error_status(self):
        proof = {"parties": {"buyer_fingerprint": "abc", "seller": "x.com"},
                 "upstream_status_code": 502, "transaction_success": True}
        status, detail, corrected = resolve_dispute(proof, "sha256:abc", "buyer", "buyer_contests_success")
        assert status == "UPHELD"
        assert corrected is True

    def test_denied_buyer_contests_success_with_ok_status(self):
        proof = {"parties": {"buyer_fingerprint": "abc", "seller": "x.com"},
                 "upstream_status_code": 200, "transaction_success": True}
        status, detail, corrected = resolve_dispute(proof, "sha256:abc", "buyer", "buyer_contests_success")
        assert status == "DENIED"
        assert corrected is False

    def test_upheld_seller_contests_failure(self):
        proof = {"parties": {"buyer_fingerprint": "abc", "seller": "x.com"},
                 "upstream_status_code": 200, "transaction_success": False}
        status, detail, corrected = resolve_dispute(proof, "sha256:x.com", "seller", "seller_contests_failure")
        assert status == "UPHELD"

    def test_rejected_non_party(self):
        proof = {"parties": {"buyer_fingerprint": "abc", "seller": "x.com"},
                 "upstream_status_code": 200}
        status, detail, corrected = resolve_dispute(proof, "sha256:intruder", "buyer", "buyer_contests_success")
        assert status == "REJECTED"

    def test_denied_no_status_code(self):
        proof = {"parties": {"buyer_fingerprint": "abc", "seller": "x.com"}}
        status, detail, corrected = resolve_dispute(proof, "sha256:abc", "buyer", "buyer_contests_success")
        assert status == "DENIED"
        assert "upstream status code" in detail.lower()


class TestCreateDispute:
    """Integration tests for the full dispute flow."""

    def test_successful_dispute(self, tmp_path, monkeypatch):
        _make_agent_profile(tmp_path, monkeypatch)
        _make_proof("prf_test_001", status_code=502, success=True)

        result = create_dispute(API_KEY, "prf_test_001", "Service returned 502")
        assert "error" not in result
        assert result["status"] in ("UPHELD", "DENIED", "REJECTED")
        assert result["dispute_id"].startswith("disp_")

    def test_proof_not_found(self, tmp_path, monkeypatch):
        _make_agent_profile(tmp_path, monkeypatch)
        result = create_dispute(API_KEY, "prf_nonexistent", "some reason")
        assert result["error"] == "proof_not_found"
        assert result["status"] == 404

    def test_empty_reason_rejected(self, tmp_path, monkeypatch):
        _make_agent_profile(tmp_path, monkeypatch)
        _make_proof("prf_test_002")
        result = create_dispute(API_KEY, "prf_test_002", "")
        assert result["error"] == "reason_required"

    def test_not_party_rejected(self, tmp_path, monkeypatch):
        other_key = "mcp_test_" + "b" * 48
        other_fp = hashlib.sha256(other_key.encode()).hexdigest()
        _make_agent_profile(tmp_path, monkeypatch, agent_fp=other_fp)
        _make_proof("prf_test_003", buyer_fp="different_buyer")

        result = create_dispute(other_key, "prf_test_003", "not my proof")
        assert result["error"] == "not_party"
        assert result["status"] == 403

    def test_dispute_window_expired(self, tmp_path, monkeypatch):
        _make_agent_profile(tmp_path, monkeypatch)
        _make_proof("prf_test_004", days_ago=10)

        result = create_dispute(API_KEY, "prf_test_004", "too late")
        assert result["error"] == "window_expired"
        assert result["status"] == 409

    def test_already_disputed(self, tmp_path, monkeypatch):
        _make_agent_profile(tmp_path, monkeypatch)
        _make_proof("prf_test_005", status_code=502, success=True)

        result1 = create_dispute(API_KEY, "prf_test_005", "first dispute")
        assert "error" not in result1

        result2 = create_dispute(API_KEY, "prf_test_005", "second dispute")
        assert result2["error"] == "already_disputed"

    def test_legacy_proof_no_status_code(self, tmp_path, monkeypatch):
        """Proofs without upstream_status_code should be rejected without penalty."""
        _make_agent_profile(tmp_path, monkeypatch)
        # Create proof WITHOUT upstream_status_code (simulates pre-dispute-system proof)
        now = datetime.now(timezone.utc)
        proof = {
            "proof_id": "prf_legacy_001",
            "spec_version": "1.0",
            "hashes": {"request": "sha256:aaa", "response": "sha256:bbb", "chain": "sha256:ccc"},
            "parties": {"buyer_fingerprint": BUYER_FP, "seller": "example.com"},
            "payment": {"transaction_id": "test_tx", "amount": 0.10, "currency": "eur", "status": "succeeded"},
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "transaction_success": True,
            # No upstream_status_code field
        }
        store_proof("prf_legacy_001", proof)

        result = create_dispute(API_KEY, "prf_legacy_001", "Service failed")
        assert result["error"] == "legacy_proof"
        assert result["status"] == 422

        # Verify no penalty was applied
        from trust_layer.persistence import load_json as _load
        agents_dir = tmp_path / "data" / "agents"
        profile = _load(agents_dir / f"{BUYER_FP[:16]}.json")
        assert profile.get("lost_disputes", 0) == 0

    def test_cooldown_enforced(self, tmp_path, monkeypatch):
        _make_agent_profile(tmp_path, monkeypatch)
        _make_proof("prf_test_006a", status_code=502, success=True)
        _make_proof("prf_test_006b", status_code=503, success=True)

        result1 = create_dispute(API_KEY, "prf_test_006a", "first")
        assert "error" not in result1

        result2 = create_dispute(API_KEY, "prf_test_006b", "second too fast")
        assert result2["error"] == "cooldown"
        assert result2["status"] == 429

    def test_upheld_dispute_increments_loser(self, tmp_path, monkeypatch):
        agents_dir = _make_agent_profile(tmp_path, monkeypatch)
        _make_proof("prf_test_007", status_code=502, success=True, seller="example.com")

        result = create_dispute(API_KEY, "prf_test_007", "Server returned 502")
        assert result["status"] == "UPHELD"

        # Check contestant stats
        profile = load_json(agents_dir / f"{BUYER_FP[:16]}.json")
        assert profile.get("disputes_filed", 0) >= 1
        assert profile.get("disputes_won", 0) >= 1

    def test_denied_dispute_increments_contestant(self, tmp_path, monkeypatch):
        agents_dir = _make_agent_profile(tmp_path, monkeypatch)
        _make_proof("prf_test_008", status_code=200, success=True)

        result = create_dispute(API_KEY, "prf_test_008", "I think it failed")
        assert result["status"] == "DENIED"

        profile = load_json(agents_dir / f"{BUYER_FP[:16]}.json")
        assert profile.get("lost_disputes", 0) >= 1


class TestGetAgentDisputes:
    """Tests for dispute history retrieval."""

    def test_empty_disputes(self, tmp_path, monkeypatch):
        _make_agent_profile(tmp_path, monkeypatch)
        result = get_agent_disputes(f"sha256:{BUYER_FP}")
        assert result["disputes_filed"] == 0
        assert result["recent_disputes"] == []

    def test_disputes_after_filing(self, tmp_path, monkeypatch):
        _make_agent_profile(tmp_path, monkeypatch)
        _make_proof("prf_test_009", status_code=502, success=True)
        create_dispute(API_KEY, "prf_test_009", "error")

        result = get_agent_disputes(f"sha256:{BUYER_FP}")
        assert result["disputes_filed"] >= 1
        assert len(result["recent_disputes"]) >= 1
        d = result["recent_disputes"][0]
        assert "dispute_id" in d
        assert "reason" not in d  # reason is not public
