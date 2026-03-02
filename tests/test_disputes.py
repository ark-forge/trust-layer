"""Tests for the dispute system — creation, resolution, anti-abuse, consequences."""

import hashlib
from datetime import datetime, timezone, timedelta

import pytest

from trust_layer.disputes import create_dispute, get_agent_disputes, resolve_dispute, DISPUTES_DIR
from trust_layer.reputation import REPUTATION_CONFIG
from trust_layer.persistence import save_json, load_json
from trust_layer.proofs import store_proof, load_proof


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

API_KEY = "mcp_test_" + "a" * 48
KEY_PREFIX = API_KEY[:16]
BUYER_FP = hashlib.sha256(API_KEY.encode()).hexdigest()


def _make_proof(proof_id, buyer_fp=BUYER_FP, seller="example.com",
                status_code=200, success=True, days_ago=0):
    """Create and store a proof with dispute-required fields."""
    now = datetime.now(timezone.utc) - timedelta(days=days_ago)
    proof = {
        "proof_id": proof_id,
        "spec_version": "1.1",
        "hashes": {"request": "sha256:aaa", "response": "sha256:bbb", "chain": "sha256:ccc"},
        "parties": {"buyer_fingerprint": buyer_fp, "seller": seller},
        "certification_fee": {"transaction_id": "test_tx", "amount": 0.10, "currency": "eur", "status": "succeeded"},
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "transaction_success": success,
        "upstream_status_code": status_code,
    }
    store_proof(proof_id, proof)
    return proof


def _setup_test_env(tmp_path, monkeypatch, agent_fp=BUYER_FP, key_prefix=KEY_PREFIX):
    """Set up isolated test directories with agent profile + fingerprint index."""
    import trust_layer.disputes as disp_mod
    import trust_layer.reputation as rep_mod

    agents_dir = tmp_path / "data" / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)
    disputes_dir = tmp_path / "data" / "disputes"
    disputes_dir.mkdir(parents=True, exist_ok=True)
    rep_dir = tmp_path / "data" / "reputation"
    rep_dir.mkdir(parents=True, exist_ok=True)
    index_path = agents_dir / "_fingerprint_index.json"

    monkeypatch.setattr(disp_mod, "DISPUTES_DIR", disputes_dir)
    monkeypatch.setattr(rep_mod, "AGENTS_DIR", agents_dir)
    monkeypatch.setattr(rep_mod, "REPUTATION_DIR", rep_dir)
    monkeypatch.setattr(rep_mod, "_FINGERPRINT_INDEX_PATH", index_path)

    # Create agent profile (named by key_prefix, like production)
    profile = {
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "transactions_total": 10,
        "transactions_succeeded": 9,
        "services_used": ["example.com"],
        "buyer_fingerprint": agent_fp,
        "lost_disputes": 0,
        "disputes_filed": 0,
        "disputes_won": 0,
        "disputes_lost": 0,
    }
    save_json(agents_dir / f"{key_prefix}.json", profile)

    # Create fingerprint index (like production)
    save_json(index_path, {agent_fp: key_prefix})

    return agents_dir


# ---------------------------------------------------------------------------
# Resolution logic (pure function tests)
# ---------------------------------------------------------------------------

class TestResolveDispute:

    def test_upheld_buyer_contests_with_error_status(self):
        proof = {"parties": {"buyer_fingerprint": "abc", "seller": "x.com"},
                 "upstream_status_code": 502, "transaction_success": True}
        status, _, corrected = resolve_dispute(proof, "abc", "buyer_contests_success")
        assert status == "UPHELD"
        assert corrected is True

    def test_denied_buyer_contests_with_ok_status(self):
        proof = {"parties": {"buyer_fingerprint": "abc", "seller": "x.com"},
                 "upstream_status_code": 200, "transaction_success": True}
        status, _, corrected = resolve_dispute(proof, "abc", "buyer_contests_success")
        assert status == "DENIED"
        assert corrected is False

    def test_upheld_seller_contests_failure(self):
        proof = {"parties": {"buyer_fingerprint": "abc", "seller": "x.com"},
                 "upstream_status_code": 200, "transaction_success": False}
        status, _, _ = resolve_dispute(proof, "x.com", "seller_contests_failure")
        assert status == "UPHELD"

    def test_denied_seller_contests_failure_with_error_status(self):
        proof = {"parties": {"buyer_fingerprint": "abc", "seller": "x.com"},
                 "upstream_status_code": 500, "transaction_success": False}
        status, _, _ = resolve_dispute(proof, "x.com", "seller_contests_failure")
        assert status == "DENIED"

    def test_rejected_non_party(self):
        proof = {"parties": {"buyer_fingerprint": "abc", "seller": "x.com"},
                 "upstream_status_code": 200}
        status, _, _ = resolve_dispute(proof, "intruder", "buyer_contests_success")
        assert status == "REJECTED"

    def test_denied_no_status_code(self):
        proof = {"parties": {"buyer_fingerprint": "abc", "seller": "x.com"}}
        status, detail, _ = resolve_dispute(proof, "abc", "buyer_contests_success")
        assert status == "DENIED"
        assert "upstream_status_code" in detail.lower()


# ---------------------------------------------------------------------------
# Full dispute flow
# ---------------------------------------------------------------------------

class TestCreateDispute:

    def test_successful_upheld_dispute(self, tmp_path, monkeypatch):
        _setup_test_env(tmp_path, monkeypatch)
        _make_proof("prf_test_001", status_code=502, success=True)

        result = create_dispute(API_KEY, "prf_test_001", "Service returned 502")
        assert "error" not in result
        assert result["status"] == "UPHELD"
        assert result["dispute_id"].startswith("disp_")
        assert result["proof_corrected"] is True

    def test_successful_denied_dispute(self, tmp_path, monkeypatch):
        _setup_test_env(tmp_path, monkeypatch)
        _make_proof("prf_test_001b", status_code=200, success=True)

        result = create_dispute(API_KEY, "prf_test_001b", "I think it failed")
        assert "error" not in result
        assert result["status"] == "DENIED"

    def test_proof_not_found(self, tmp_path, monkeypatch):
        _setup_test_env(tmp_path, monkeypatch)
        result = create_dispute(API_KEY, "prf_nonexistent", "some reason")
        assert result["error"] == "proof_not_found"
        assert result["status"] == 404

    def test_empty_reason_rejected(self, tmp_path, monkeypatch):
        _setup_test_env(tmp_path, monkeypatch)
        _make_proof("prf_test_002")
        result = create_dispute(API_KEY, "prf_test_002", "")
        assert result["error"] == "reason_required"

    def test_not_party_rejected(self, tmp_path, monkeypatch):
        """Agent with different API key can't dispute another agent's proof."""
        other_key = "mcp_test_" + "b" * 48
        other_prefix = other_key[:16]
        other_fp = hashlib.sha256(other_key.encode()).hexdigest()
        _setup_test_env(tmp_path, monkeypatch, agent_fp=other_fp, key_prefix=other_prefix)
        _make_proof("prf_test_003", buyer_fp="different_buyer")

        result = create_dispute(other_key, "prf_test_003", "not my proof")
        assert result["error"] == "not_party"
        assert result["status"] == 403

    def test_dispute_window_expired(self, tmp_path, monkeypatch):
        _setup_test_env(tmp_path, monkeypatch)
        _make_proof("prf_test_004", days_ago=10)

        result = create_dispute(API_KEY, "prf_test_004", "too late")
        assert result["error"] == "window_expired"
        assert result["status"] == 409

    def test_already_disputed(self, tmp_path, monkeypatch):
        """Same proof can only be disputed once."""
        _setup_test_env(tmp_path, monkeypatch)
        _make_proof("prf_test_005", status_code=502, success=True)

        result1 = create_dispute(API_KEY, "prf_test_005", "first dispute")
        assert "error" not in result1

        result2 = create_dispute(API_KEY, "prf_test_005", "second dispute")
        assert result2["error"] == "already_disputed"

    def test_already_disputed_uses_proof_flag(self, tmp_path, monkeypatch):
        """Duplicate check reads proof.disputed flag, not file scan."""
        _setup_test_env(tmp_path, monkeypatch)
        _make_proof("prf_test_005b", status_code=502, success=True)
        create_dispute(API_KEY, "prf_test_005b", "first")

        # Verify proof has disputed flag
        proof = load_proof("prf_test_005b")
        assert proof["disputed"] is True
        assert "dispute_id" in proof

    def test_legacy_proof_no_status_code(self, tmp_path, monkeypatch):
        """Proofs without upstream_status_code → 422, no penalty."""
        agents_dir = _setup_test_env(tmp_path, monkeypatch)
        now = datetime.now(timezone.utc)
        proof = {
            "proof_id": "prf_legacy",
            "spec_version": "1.0",
            "hashes": {"request": "sha256:aaa", "response": "sha256:bbb", "chain": "sha256:ccc"},
            "parties": {"buyer_fingerprint": BUYER_FP, "seller": "example.com"},
            "certification_fee": {"transaction_id": "test_tx", "amount": 0.10, "currency": "eur", "status": "succeeded"},
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "transaction_success": True,
            # No upstream_status_code
        }
        store_proof("prf_legacy", proof)

        result = create_dispute(API_KEY, "prf_legacy", "Service failed")
        assert result["error"] == "legacy_proof"
        assert result["status"] == 422

        # No penalty applied
        profile = load_json(agents_dir / f"{KEY_PREFIX}.json")
        assert profile.get("lost_disputes", 0) == 0

    def test_nothing_to_contest_already_failed(self, tmp_path, monkeypatch):
        """Buyer can't contest a transaction already marked as failed."""
        _setup_test_env(tmp_path, monkeypatch)
        _make_proof("prf_test_ntc", status_code=500, success=False)

        result = create_dispute(API_KEY, "prf_test_ntc", "It failed")
        assert result["error"] == "nothing_to_contest"
        assert result["status"] == 400

    def test_cooldown_enforced(self, tmp_path, monkeypatch):
        _setup_test_env(tmp_path, monkeypatch)
        _make_proof("prf_test_006a", status_code=502, success=True)
        _make_proof("prf_test_006b", status_code=503, success=True)

        result1 = create_dispute(API_KEY, "prf_test_006a", "first")
        assert "error" not in result1

        result2 = create_dispute(API_KEY, "prf_test_006b", "second too fast")
        assert result2["error"] == "cooldown"
        assert result2["status"] == 429

    def test_cooldown_uses_profile_field(self, tmp_path, monkeypatch):
        """Cooldown reads last_dispute_at from profile, not file scan."""
        agents_dir = _setup_test_env(tmp_path, monkeypatch)
        _make_proof("prf_test_006c", status_code=502, success=True)
        create_dispute(API_KEY, "prf_test_006c", "first")

        profile = load_json(agents_dir / f"{KEY_PREFIX}.json")
        assert "last_dispute_at" in profile

    def test_upheld_increments_loser_stats(self, tmp_path, monkeypatch):
        """When buyer wins, buyer gets disputes_won. Seller has no agent profile to update."""
        agents_dir = _setup_test_env(tmp_path, monkeypatch)
        _make_proof("prf_test_007", status_code=502, success=True, seller="example.com")

        result = create_dispute(API_KEY, "prf_test_007", "Server returned 502")
        assert result["status"] == "UPHELD"

        profile = load_json(agents_dir / f"{KEY_PREFIX}.json")
        assert profile.get("disputes_filed", 0) >= 1
        assert profile.get("disputes_won", 0) >= 1
        # Buyer won → no lost_disputes for buyer
        assert profile.get("lost_disputes", 0) == 0

    def test_denied_increments_contestant_lost(self, tmp_path, monkeypatch):
        agents_dir = _setup_test_env(tmp_path, monkeypatch)
        _make_proof("prf_test_008", status_code=200, success=True)

        result = create_dispute(API_KEY, "prf_test_008", "I think it failed")
        assert result["status"] == "DENIED"

        profile = load_json(agents_dir / f"{KEY_PREFIX}.json")
        assert profile.get("lost_disputes", 0) >= 1

    def test_upheld_flips_proof_success(self, tmp_path, monkeypatch):
        """UPHELD dispute flips transaction_success in the proof."""
        _setup_test_env(tmp_path, monkeypatch)
        _make_proof("prf_test_flip", status_code=502, success=True)

        result = create_dispute(API_KEY, "prf_test_flip", "Service failed")
        assert result["status"] == "UPHELD"

        corrected = load_proof("prf_test_flip")
        assert corrected["transaction_success"] is False


# ---------------------------------------------------------------------------
# Dispute history
# ---------------------------------------------------------------------------

class TestGetAgentDisputes:

    def test_empty_disputes(self, tmp_path, monkeypatch):
        _setup_test_env(tmp_path, monkeypatch)
        result = get_agent_disputes(f"sha256:{BUYER_FP}")
        assert result["disputes_filed"] == 0
        assert result["recent_disputes"] == []

    def test_disputes_after_filing(self, tmp_path, monkeypatch):
        _setup_test_env(tmp_path, monkeypatch)
        _make_proof("prf_test_009", status_code=502, success=True)
        create_dispute(API_KEY, "prf_test_009", "error")

        result = get_agent_disputes(f"sha256:{BUYER_FP}")
        assert result["disputes_filed"] >= 1
        assert len(result["recent_disputes"]) >= 1
        d = result["recent_disputes"][0]
        assert "dispute_id" in d
        assert "reason" not in d  # reason is not public
