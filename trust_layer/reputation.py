"""Reputation Score — deterministic 0-100 score based on agent proof history."""

import math
from datetime import datetime, timezone
from pathlib import Path

from .config import AGENTS_DIR, get_signing_key, ARKFORGE_PUBLIC_KEY
from .crypto import sign_proof
from .persistence import load_json, save_json

REPUTATION_CONFIG = {
    # Scoring caps
    "volume_cap": 100,
    "regularity_cap": 20,
    "seniority_cap_days": 30,
    "diversity_cap": 10,
    # Weights
    "w_volume": 0.25,
    "w_regularity": 0.20,
    "w_seniority": 0.20,
    "w_diversity": 0.15,
    "w_success": 0.20,
    # Penalties
    "identity_penalty": 0.85,
    "dispute_penalty_per_loss": 0.05,
    "dispute_penalty_floor": 0.50,
    # Cache
    "cache_ttl_seconds": 3600,
    # Disputes
    "dispute_window_days": 7,
    "max_open_disputes_per_agent": 5,
    "dispute_cooldown_seconds": 3600,
    # Phase 2
    "leaderboard_min_proofs": 10,
}

# Directory for reputation cache files
REPUTATION_DIR: Path = AGENTS_DIR.parent / "reputation"


def _ensure_reputation_dir():
    REPUTATION_DIR.mkdir(parents=True, exist_ok=True)


def _cache_path(agent_id: str) -> Path:
    """Return path for reputation cache file. agent_id = full fingerprint (64 hex)."""
    prefix = agent_id.replace("sha256:", "")[:16]
    return REPUTATION_DIR / f"{prefix}.json"


def _find_agent_profile(agent_id: str) -> dict | None:
    """Find agent profile by fingerprint. Returns profile dict or None."""
    clean_id = agent_id.replace("sha256:", "")
    prefix = clean_id[:16]
    path = AGENTS_DIR / f"{prefix}.json"
    if path.exists():
        return load_json(path, {})
    return None


def compute_reputation(agent_id: str, profile: dict) -> dict:
    """Compute reputation score from agent profile. Returns full reputation record."""
    cfg = REPUTATION_CONFIG
    now = datetime.now(timezone.utc)

    # S_volume
    total_proofs = profile.get("transactions_total", 0)
    s_volume = min(100, (total_proofs / cfg["volume_cap"]) * 100)

    # S_regularity
    active_days = len(profile.get("proof_dates_30d", []))
    s_regularity = min(100, (active_days / cfg["regularity_cap"]) * 100)

    # S_seniority
    first_seen = profile.get("first_seen")
    if first_seen:
        try:
            first_dt = datetime.fromisoformat(first_seen)
            if first_dt.tzinfo is None:
                first_dt = first_dt.replace(tzinfo=timezone.utc)
            days_since = (now - first_dt).days
        except (ValueError, TypeError):
            days_since = 0
    else:
        days_since = 0
    s_seniority = min(100, (days_since / cfg["seniority_cap_days"]) * 100)

    # S_diversity
    unique_services = len(profile.get("services_used", []))
    s_diversity = min(100, (unique_services / cfg["diversity_cap"]) * 100)

    # S_success
    succeeded = profile.get("transactions_succeeded", 0)
    if total_proofs > 0:
        s_success = (succeeded / total_proofs) * 100
    else:
        s_success = 0

    # Weighted score
    score = (
        cfg["w_volume"] * s_volume
        + cfg["w_regularity"] * s_regularity
        + cfg["w_seniority"] * s_seniority
        + cfg["w_diversity"] * s_diversity
        + cfg["w_success"] * s_success
    )

    # Identity mismatch penalty
    if profile.get("identity_mismatch"):
        score *= cfg["identity_penalty"]

    # Dispute penalty
    lost_disputes = profile.get("lost_disputes", 0)
    if lost_disputes > 0:
        penalty = max(cfg["dispute_penalty_floor"], 1.0 - lost_disputes * cfg["dispute_penalty_per_loss"])
        score *= penalty

    score = math.floor(score)
    computed_at = now.isoformat()

    # Sign the score
    sign_payload = f"{agent_id}:{score}:{computed_at}"
    signing_key = get_signing_key()
    signature = sign_proof(signing_key, sign_payload) if signing_key else None

    return {
        "agent_id": agent_id if agent_id.startswith("sha256:") else f"sha256:{agent_id}",
        "declared_identity": profile.get("declared_identity"),
        "identity_mismatch": profile.get("identity_mismatch", False),
        "first_proof_at": profile.get("first_seen"),
        "last_proof_at": profile.get("last_transaction"),
        "total_proofs": total_proofs,
        "succeeded_proofs": succeeded,
        "unique_services": profile.get("services_used", []),
        "active_days_30d": active_days,
        "amount_total_eur": profile.get("amount_total_eur", 0.0),
        "lost_disputes": lost_disputes,
        "scores": {
            "volume": round(s_volume, 1),
            "regularity": round(s_regularity, 1),
            "seniority": round(s_seniority, 1),
            "diversity": round(s_diversity, 1),
            "success": round(s_success, 1),
        },
        "reputation_score": score,
        "signature": signature,
        "computed_at": computed_at,
    }


def get_reputation(agent_id: str) -> dict | None:
    """Get reputation for an agent. Uses cache with TTL. Returns None if unknown agent."""
    _ensure_reputation_dir()
    clean_id = agent_id.replace("sha256:", "")

    # Check cache
    cache = _cache_path(clean_id)
    if cache.exists():
        cached = load_json(cache)
        computed_at = cached.get("computed_at", "")
        if computed_at:
            try:
                cached_dt = datetime.fromisoformat(computed_at)
                if cached_dt.tzinfo is None:
                    cached_dt = cached_dt.replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - cached_dt).total_seconds()
                if age < REPUTATION_CONFIG["cache_ttl_seconds"]:
                    return cached
            except (ValueError, TypeError):
                pass

    # Load agent profile
    profile = _find_agent_profile(clean_id)
    if profile is None:
        return None

    # Compute and cache
    result = compute_reputation(f"sha256:{clean_id}", profile)
    save_json(cache, result)
    return result


def invalidate_cache(agent_id: str):
    """Invalidate reputation cache for an agent."""
    _ensure_reputation_dir()
    clean_id = agent_id.replace("sha256:", "")
    cache = _cache_path(clean_id)
    if cache.exists():
        cache.unlink(missing_ok=True)


def get_public_reputation(rep: dict) -> dict:
    """Return public-safe reputation data (no amount, no service list)."""
    return {
        "agent_id": rep["agent_id"],
        "declared_identity": rep.get("declared_identity"),
        "reputation_score": rep["reputation_score"],
        "scores": rep["scores"],
        "total_proofs": rep["total_proofs"],
        "first_proof_at": rep.get("first_proof_at"),
        "last_proof_at": rep.get("last_proof_at"),
        "unique_services_count": len(rep.get("unique_services", [])),
        "lost_disputes": rep.get("lost_disputes", 0),
        "signature": rep.get("signature"),
        "computed_at": rep["computed_at"],
    }
