"""Tests for reputation score computation and caching."""

import math
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from trust_layer.reputation import (
    REPUTATION_CONFIG,
    compute_reputation,
    get_reputation,
    invalidate_cache,
    get_public_reputation,
    REPUTATION_DIR,
)
from trust_layer.persistence import save_json


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
    }


class TestComputeReputation:
    """Unit tests for the score formula."""

    def test_empty_profile(self):
        profile = _make_profile(total=0, succeeded=0, services=[], days_ago=0, active_days=0)
        rep = compute_reputation("sha256:abc123", profile)
        assert rep["reputation_score"] == 0
        assert rep["scores"]["volume"] == 0
        assert rep["scores"]["success"] == 0

    def test_full_score_agent(self):
        """Agent with max stats should score close to 100."""
        profile = _make_profile(
            total=200, succeeded=200, services=[f"s{i}.com" for i in range(15)],
            days_ago=60, active_days=25,
        )
        rep = compute_reputation("sha256:abc123", profile)
        assert rep["reputation_score"] == 100

    def test_spec_example(self):
        """Verify the example from the spec: 40 proofs, 15 active days, 20 days old, 4 services, 96% success."""
        profile = _make_profile(
            total=40, succeeded=38, services=["a.com", "b.com", "c.com", "d.com"],
            days_ago=20, active_days=15,
        )
        # Expected: floor(0.25*40 + 0.20*75 + 0.20*66.7 + 0.15*40 + 0.20*95) = floor(63.3)
        rep = compute_reputation("sha256:abc123", profile)
        # 38/40 = 95%, not 96% as in spec text (spec rounds differently)
        # floor(10 + 15 + 13.3 + 6 + 19.0) = floor(63.3) = 63
        assert rep["reputation_score"] == 63

    def test_volume_cap(self):
        """Volume caps at 100 proofs."""
        profile = _make_profile(total=50, succeeded=50, services=[], days_ago=0, active_days=0)
        rep = compute_reputation("sha256:abc123", profile)
        s_vol = rep["scores"]["volume"]
        assert s_vol == 50.0

        profile2 = _make_profile(total=150, succeeded=150, services=[], days_ago=0, active_days=0)
        rep2 = compute_reputation("sha256:abc123", profile2)
        assert rep2["scores"]["volume"] == 100.0

    def test_seniority_cap(self):
        """Seniority caps at 30 days."""
        profile = _make_profile(total=0, succeeded=0, services=[], days_ago=60, active_days=0)
        rep = compute_reputation("sha256:abc123", profile)
        assert rep["scores"]["seniority"] == 100.0

    def test_diversity_score(self):
        """Diversity = unique services / 10 * 100."""
        profile = _make_profile(total=5, succeeded=5, services=["a.com", "b.com", "c.com"], days_ago=1, active_days=1)
        rep = compute_reputation("sha256:abc123", profile)
        assert rep["scores"]["diversity"] == 30.0

    def test_identity_mismatch_penalty(self):
        """Identity mismatch applies 0.85 multiplier."""
        profile_ok = _make_profile(total=100, succeeded=100, services=[f"s{i}.com" for i in range(10)], days_ago=30, active_days=20)
        profile_bad = _make_profile(total=100, succeeded=100, services=[f"s{i}.com" for i in range(10)], days_ago=30, active_days=20, identity_mismatch=True)

        rep_ok = compute_reputation("sha256:abc123", profile_ok)
        rep_bad = compute_reputation("sha256:abc123", profile_bad)

        assert rep_bad["reputation_score"] == math.floor(rep_ok["reputation_score"] * 0.85)

    def test_dispute_penalty(self):
        """Lost disputes reduce score with floor at 50%."""
        profile_base = _make_profile(total=100, succeeded=100, services=[f"s{i}.com" for i in range(10)], days_ago=30, active_days=20)
        profile_1loss = _make_profile(total=100, succeeded=100, services=[f"s{i}.com" for i in range(10)], days_ago=30, active_days=20, lost_disputes=1)
        profile_10loss = _make_profile(total=100, succeeded=100, services=[f"s{i}.com" for i in range(10)], days_ago=30, active_days=20, lost_disputes=10)

        rep_base = compute_reputation("sha256:abc123", profile_base)
        rep_1 = compute_reputation("sha256:abc123", profile_1loss)
        rep_10 = compute_reputation("sha256:abc123", profile_10loss)

        assert rep_1["reputation_score"] == math.floor(rep_base["reputation_score"] * 0.95)
        # 10 losses = 50% penalty (floor)
        assert rep_10["reputation_score"] == math.floor(rep_base["reputation_score"] * 0.50)

    def test_signature_present(self):
        """Score should be signed with Ed25519."""
        profile = _make_profile(total=10, succeeded=10)
        rep = compute_reputation("sha256:abc123", profile)
        assert rep["signature"] is not None
        assert rep["signature"].startswith("ed25519:")

    def test_agent_id_prefix(self):
        """Agent ID should always start with sha256:."""
        profile = _make_profile()
        rep = compute_reputation("abc123", profile)
        assert rep["agent_id"].startswith("sha256:")

        rep2 = compute_reputation("sha256:abc123", profile)
        assert rep2["agent_id"] == "sha256:abc123"


class TestGetReputation:
    """Integration tests for caching and lookup."""

    def test_unknown_agent_returns_none(self, tmp_path, monkeypatch):
        import trust_layer.reputation as rep_mod
        monkeypatch.setattr(rep_mod, "AGENTS_DIR", tmp_path / "agents")
        monkeypatch.setattr(rep_mod, "REPUTATION_DIR", tmp_path / "reputation")
        (tmp_path / "agents").mkdir(exist_ok=True)

        result = get_reputation("sha256:0000000000000000")
        assert result is None

    def test_known_agent_returns_score(self, tmp_path, monkeypatch):
        import trust_layer.reputation as rep_mod
        agents_dir = tmp_path / "agents"
        agents_dir.mkdir(exist_ok=True)
        monkeypatch.setattr(rep_mod, "AGENTS_DIR", agents_dir)
        monkeypatch.setattr(rep_mod, "REPUTATION_DIR", tmp_path / "reputation")

        agent_id = "a1b2c3d4e5f60000" + "0" * 48
        profile = _make_profile(total=5, succeeded=5)
        save_json(agents_dir / f"{agent_id[:16]}.json", profile)

        result = get_reputation(f"sha256:{agent_id}")
        assert result is not None
        assert result["reputation_score"] >= 0
        assert result["total_proofs"] == 5

    def test_cache_ttl(self, tmp_path, monkeypatch):
        """Cached score should be returned within TTL."""
        import trust_layer.reputation as rep_mod
        agents_dir = tmp_path / "agents"
        agents_dir.mkdir(exist_ok=True)
        monkeypatch.setattr(rep_mod, "AGENTS_DIR", agents_dir)
        monkeypatch.setattr(rep_mod, "REPUTATION_DIR", tmp_path / "reputation")

        agent_id = "b1b2c3d4e5f60000" + "0" * 48
        profile = _make_profile(total=5, succeeded=5)
        save_json(agents_dir / f"{agent_id[:16]}.json", profile)

        r1 = get_reputation(f"sha256:{agent_id}")
        # Update profile but don't invalidate cache
        profile["transactions_total"] = 50
        save_json(agents_dir / f"{agent_id[:16]}.json", profile)

        r2 = get_reputation(f"sha256:{agent_id}")
        # Should still return cached value
        assert r2["total_proofs"] == 5

    def test_invalidate_cache(self, tmp_path, monkeypatch):
        """Invalidated cache should trigger recomputation."""
        import trust_layer.reputation as rep_mod
        agents_dir = tmp_path / "agents"
        agents_dir.mkdir(exist_ok=True)
        monkeypatch.setattr(rep_mod, "AGENTS_DIR", agents_dir)
        monkeypatch.setattr(rep_mod, "REPUTATION_DIR", tmp_path / "reputation")

        agent_id = "c1b2c3d4e5f60000" + "0" * 48
        profile = _make_profile(total=5, succeeded=5)
        save_json(agents_dir / f"{agent_id[:16]}.json", profile)

        get_reputation(f"sha256:{agent_id}")
        profile["transactions_total"] = 50
        profile["transactions_succeeded"] = 50
        save_json(agents_dir / f"{agent_id[:16]}.json", profile)
        invalidate_cache(f"sha256:{agent_id}")

        r = get_reputation(f"sha256:{agent_id}")
        assert r["total_proofs"] == 50


class TestPublicReputation:
    """Tests for the public-safe response."""

    def test_excludes_sensitive_fields(self):
        profile = _make_profile(total=10, succeeded=10, services=["a.com", "b.com"])
        rep = compute_reputation("sha256:abc123", profile)
        public = get_public_reputation(rep)

        assert "unique_services_count" in public
        assert public["unique_services_count"] == 2
        assert "unique_services" not in public
        assert "amount_total_eur" not in public

    def test_includes_required_fields(self):
        profile = _make_profile(total=10, succeeded=10)
        rep = compute_reputation("sha256:abc123", profile)
        public = get_public_reputation(rep)

        for field in ["agent_id", "reputation_score", "scores", "total_proofs",
                       "first_proof_at", "last_proof_at", "lost_disputes", "signature", "computed_at"]:
            assert field in public
