"""Tests for reputation score computation, caching, and agent resolution."""

import hashlib
import math
from datetime import datetime, timezone, timedelta

import pytest

from trust_layer.reputation import (
    REPUTATION_CONFIG,
    REPUTATION_DIR,
    _FINGERPRINT_INDEX_PATH,
    compute_reputation,
    get_reputation,
    invalidate_cache,
    get_public_reputation,
    resolve_agent_profile,
)
from trust_layer.persistence import save_json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

API_KEY = "mcp_test_" + "a" * 48
KEY_PREFIX = API_KEY[:16]
FINGERPRINT = hashlib.sha256(API_KEY.encode()).hexdigest()


def _make_profile(
    total=10, succeeded=9, services=None, days_ago=15,
    active_days=5, identity_mismatch=False, lost_disputes=0,
):
    """Build a minimal agent profile dict."""
    now = datetime.now(timezone.utc)
    first = (now - timedelta(days=days_ago)).isoformat()
    dates = [(now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(active_days)]
    return {
        "first_seen": first,
        "transactions_total": total,
        "transactions_succeeded": succeeded,
        "services_used": ["example.com"] if services is None else services,
        "last_transaction": now.isoformat(),
        "proof_dates_30d": dates,
        "identity_mismatch": identity_mismatch,
        "lost_disputes": lost_disputes,
        "buyer_fingerprint": FINGERPRINT,
    }


def _setup_agent(tmp_path, monkeypatch, profile=None, fingerprint=FINGERPRINT, key_prefix=KEY_PREFIX):
    """Create agent profile + fingerprint index in tmp dirs (matching production layout)."""
    import trust_layer.reputation as rep_mod
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir(exist_ok=True)
    rep_dir = tmp_path / "reputation"
    rep_dir.mkdir(exist_ok=True)
    index_path = agents_dir / "_fingerprint_index.json"

    monkeypatch.setattr(rep_mod, "AGENTS_DIR", agents_dir)
    monkeypatch.setattr(rep_mod, "REPUTATION_DIR", rep_dir)
    monkeypatch.setattr(rep_mod, "_FINGERPRINT_INDEX_PATH", index_path)

    if profile is not None:
        # Save profile by key_prefix (like production)
        save_json(agents_dir / f"{key_prefix}.json", profile)
        # Save fingerprint index (like production)
        save_json(index_path, {fingerprint: key_prefix})

    return agents_dir, rep_dir, index_path


# ---------------------------------------------------------------------------
# Score computation (pure logic, no I/O)
# ---------------------------------------------------------------------------

class TestComputeReputation:

    def test_empty_profile(self):
        """0 proofs → score 0 (success_rate=0 regardless of confidence)."""
        profile = _make_profile(total=0, succeeded=0, services=[], days_ago=0, active_days=0)
        rep = compute_reputation("sha256:abc123", profile)
        assert rep["reputation_score"] == 0
        assert rep["scoring"]["success_rate"] == 0
        assert rep["scoring"]["confidence"] == 0.60  # 0 proofs < threshold of 1

    def test_full_score_agent(self):
        """20+ proofs, 100% success → score 100 (full confidence, no penalty)."""
        profile = _make_profile(
            total=200, succeeded=200,
            services=[f"s{i}.com" for i in range(15)],
            days_ago=60, active_days=25,
        )
        rep = compute_reputation("sha256:abc123", profile)
        assert rep["reputation_score"] == 100

    def test_confidence_thresholds(self):
        """Confidence factor steps: 1→0.60, 2-4→0.75, 5-19→0.85, 20+→1.00."""
        # 1 proof, 100% success → floor(100 * 0.60) = 60
        p1 = _make_profile(total=1, succeeded=1, services=[])
        assert compute_reputation("sha256:x", p1)["reputation_score"] == 60
        assert compute_reputation("sha256:x", p1)["scoring"]["confidence"] == 0.60

        # 4 proofs, 100% success → floor(100 * 0.75) = 75
        p4 = _make_profile(total=4, succeeded=4, services=[])
        assert compute_reputation("sha256:x", p4)["reputation_score"] == 75
        assert compute_reputation("sha256:x", p4)["scoring"]["confidence"] == 0.75

        # 10 proofs, 100% success → floor(100 * 0.85) = 85
        p10 = _make_profile(total=10, succeeded=10, services=[])
        assert compute_reputation("sha256:x", p10)["reputation_score"] == 85
        assert compute_reputation("sha256:x", p10)["scoring"]["confidence"] == 0.85

        # 20 proofs, 100% success → floor(100 * 1.00) = 100
        p20 = _make_profile(total=20, succeeded=20, services=[])
        assert compute_reputation("sha256:x", p20)["reputation_score"] == 100
        assert compute_reputation("sha256:x", p20)["scoring"]["confidence"] == 1.00

    def test_success_rate_scaling(self):
        """score = floor(success_rate × confidence). 40 proofs (conf=1.0), 95% success → 95."""
        profile = _make_profile(
            total=40, succeeded=38,
            services=["a.com", "b.com", "c.com", "d.com"],
            days_ago=20, active_days=15,
        )
        rep = compute_reputation("sha256:abc123", profile)
        # 38/40 = 95.0%, confidence=1.00 (40 >= 20), score=floor(95.0)=95
        assert rep["scoring"]["success_rate"] == 95.0
        assert rep["scoring"]["confidence"] == 1.00
        assert rep["reputation_score"] == 95

    def test_identity_mismatch_penalty(self):
        """Identity mismatch deducts 15 points (additive, not multiplicative)."""
        base = _make_profile(total=100, succeeded=100, services=[])
        bad = _make_profile(total=100, succeeded=100, services=[], identity_mismatch=True)

        score_ok = compute_reputation("sha256:x", base)["reputation_score"]
        score_bad = compute_reputation("sha256:x", bad)["reputation_score"]
        assert score_ok == 100
        assert score_bad == 100 - 15  # = 85

    def test_dispute_penalty(self):
        """Lost disputes deduct 5 pts each; score cannot drop below 50 from disputes alone."""
        base = _make_profile(total=100, succeeded=100, services=[])
        p1 = _make_profile(total=100, succeeded=100, services=[], lost_disputes=1)
        p10 = _make_profile(total=100, succeeded=100, services=[], lost_disputes=10)

        s_base = compute_reputation("sha256:x", base)["reputation_score"]
        s_1 = compute_reputation("sha256:x", p1)["reputation_score"]
        s_10 = compute_reputation("sha256:x", p10)["reputation_score"]

        assert s_base == 100
        assert s_1 == 100 - 5       # = 95
        assert s_10 == 50           # floor (10 × 5 = 50 penalty, floor prevents going below 50)

    def test_signature_present(self):
        profile = _make_profile(total=10, succeeded=10)
        rep = compute_reputation("sha256:abc123", profile)
        assert rep["signature"] is not None
        assert rep["signature"].startswith("ed25519:")

    def test_agent_id_normalized(self):
        """Agent ID always starts with sha256: in output."""
        profile = _make_profile()
        assert compute_reputation("abc123", profile)["agent_id"] == "sha256:abc123"
        assert compute_reputation("sha256:abc123", profile)["agent_id"] == "sha256:abc123"


# ---------------------------------------------------------------------------
# Agent resolution (fingerprint → key_prefix)
# ---------------------------------------------------------------------------

class TestResolveAgentProfile:

    def test_unknown_agent(self, tmp_path, monkeypatch):
        _setup_agent(tmp_path, monkeypatch)
        path, profile = resolve_agent_profile("sha256:0000000000000000")
        assert path is None
        assert profile is None

    def test_known_agent_via_index(self, tmp_path, monkeypatch):
        """Profile stored by key_prefix, found via fingerprint index."""
        prof = _make_profile(total=5, succeeded=5)
        _setup_agent(tmp_path, monkeypatch, profile=prof)

        path, profile = resolve_agent_profile(f"sha256:{FINGERPRINT}")
        assert profile is not None
        assert profile["transactions_total"] == 5
        assert path.name == f"{KEY_PREFIX}.json"

    def test_without_index_returns_none(self, tmp_path, monkeypatch):
        """No index entry → agent not found (even if profile file exists)."""
        import trust_layer.reputation as rep_mod
        agents_dir = tmp_path / "agents"
        agents_dir.mkdir(exist_ok=True)
        monkeypatch.setattr(rep_mod, "AGENTS_DIR", agents_dir)
        monkeypatch.setattr(rep_mod, "_FINGERPRINT_INDEX_PATH", agents_dir / "_fingerprint_index.json")

        # Profile exists but no index
        save_json(agents_dir / f"{KEY_PREFIX}.json", _make_profile())
        path, profile = resolve_agent_profile(f"sha256:{FINGERPRINT}")
        assert profile is None


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------

class TestGetReputation:

    def test_unknown_agent_returns_none(self, tmp_path, monkeypatch):
        _setup_agent(tmp_path, monkeypatch)
        assert get_reputation("sha256:0000000000000000") is None

    def test_known_agent_returns_score(self, tmp_path, monkeypatch):
        prof = _make_profile(total=5, succeeded=5)
        _setup_agent(tmp_path, monkeypatch, profile=prof)

        result = get_reputation(f"sha256:{FINGERPRINT}")
        assert result is not None
        assert result["reputation_score"] >= 0
        assert result["total_proofs"] == 5

    def test_cache_ttl(self, tmp_path, monkeypatch):
        """Cached score returned within TTL even if profile changes."""
        prof = _make_profile(total=5, succeeded=5)
        agents_dir, _, index_path = _setup_agent(tmp_path, monkeypatch, profile=prof)

        r1 = get_reputation(f"sha256:{FINGERPRINT}")
        assert r1["total_proofs"] == 5

        # Update profile (simulating new transactions)
        prof["transactions_total"] = 50
        save_json(agents_dir / f"{KEY_PREFIX}.json", prof)

        r2 = get_reputation(f"sha256:{FINGERPRINT}")
        assert r2["total_proofs"] == 5  # still cached

    def test_invalidate_cache(self, tmp_path, monkeypatch):
        """After invalidation, score is recomputed from fresh profile."""
        prof = _make_profile(total=5, succeeded=5)
        agents_dir, _, _ = _setup_agent(tmp_path, monkeypatch, profile=prof)

        get_reputation(f"sha256:{FINGERPRINT}")

        prof["transactions_total"] = 50
        prof["transactions_succeeded"] = 50
        save_json(agents_dir / f"{KEY_PREFIX}.json", prof)
        invalidate_cache(f"sha256:{FINGERPRINT}")

        r = get_reputation(f"sha256:{FINGERPRINT}")
        assert r["total_proofs"] == 50


# ---------------------------------------------------------------------------
# Public response
# ---------------------------------------------------------------------------

class TestPublicReputation:

    def test_excludes_sensitive_fields(self):
        rep = compute_reputation("sha256:abc", _make_profile(services=["a.com", "b.com"]))
        public = get_public_reputation(rep)
        assert public["unique_services_count"] == 2
        assert "unique_services" not in public
        assert "amount_total_eur" not in public

    def test_includes_required_fields(self):
        rep = compute_reputation("sha256:abc", _make_profile())
        public = get_public_reputation(rep)
        for field in ["agent_id", "reputation_score", "scoring", "total_proofs",
                      "first_proof_at", "last_proof_at", "lost_disputes", "signature", "computed_at"]:
            assert field in public, f"Missing field: {field}"
