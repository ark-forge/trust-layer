"""Reputation Score — deterministic 0-100 score based on agent proof history.

Score is computed from 5 dimensions: volume, regularity, seniority, diversity, success.
Penalties apply for identity mismatches and lost disputes.
Score is signed with Ed25519 for verifiable authenticity.
"""

import math
from datetime import datetime, timezone
from pathlib import Path

from .config import AGENTS_DIR, get_signing_key, ARKFORGE_PUBLIC_KEY
from .crypto import sign_proof
from .persistence import load_json, save_json

REPUTATION_CONFIG = {
    # Scoring caps (low at launch to reward early adopters, raise as volume grows)
    "volume_cap": 100,
    "regularity_cap": 20,
    "seniority_cap_days": 30,
    "diversity_cap": 10,
    # Weights (total = 1.00)
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

REPUTATION_DIR: Path = AGENTS_DIR.parent / "reputation"
_FINGERPRINT_INDEX_PATH: Path = AGENTS_DIR / "_fingerprint_index.json"


# ---------------------------------------------------------------------------
# Agent profile resolution (fingerprint → key_prefix → profile)
# ---------------------------------------------------------------------------

def resolve_agent_profile(agent_id: str) -> tuple[Path | None, dict | None]:
    """Resolve an agent fingerprint to its profile.

    Agent profiles are stored by API key prefix (e.g. mcp_test_93f29be.json).
    Public identifiers are fingerprints (SHA-256 of the API key).
    The fingerprint index bridges the two.

    Returns (path, profile) or (None, None) if agent unknown.
    """
    clean_id = agent_id.replace("sha256:", "")
    index = load_json(_FINGERPRINT_INDEX_PATH, {})
    key_prefix = index.get(clean_id)
    if not key_prefix:
        return None, None
    path = AGENTS_DIR / f"{key_prefix}.json"
    if not path.exists():
        return None, None
    return path, load_json(path, {})


# ---------------------------------------------------------------------------
# Score computation
# ---------------------------------------------------------------------------

def _sub_score(value: float, cap: float) -> float:
    """Compute a sub-score: linear 0-100 capped at `cap`."""
    if cap <= 0:
        return 0.0
    return min(100.0, (value / cap) * 100.0)


def _parse_timestamp(ts: str | None) -> datetime | None:
    """Parse an ISO timestamp, returning None on failure."""
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def compute_reputation(agent_id: str, profile: dict) -> dict:
    """Compute reputation score from agent profile. Returns full reputation record."""
    cfg = REPUTATION_CONFIG
    now = datetime.now(timezone.utc)

    total_proofs = profile.get("transactions_total", 0)
    succeeded = profile.get("transactions_succeeded", 0)
    active_days = len(profile.get("proof_dates_30d", []))
    unique_services = profile.get("services_used", [])
    lost_disputes = profile.get("lost_disputes", 0)

    # Seniority: days since first proof
    first_dt = _parse_timestamp(profile.get("first_seen"))
    days_since = (now - first_dt).days if first_dt else 0

    # Five sub-scores (0-100 each)
    s_volume = _sub_score(total_proofs, cfg["volume_cap"])
    s_regularity = _sub_score(active_days, cfg["regularity_cap"])
    s_seniority = _sub_score(days_since, cfg["seniority_cap_days"])
    s_diversity = _sub_score(len(unique_services), cfg["diversity_cap"])
    s_success = (succeeded / total_proofs * 100.0) if total_proofs > 0 else 0.0

    # Weighted total
    score = (
        cfg["w_volume"] * s_volume
        + cfg["w_regularity"] * s_regularity
        + cfg["w_seniority"] * s_seniority
        + cfg["w_diversity"] * s_diversity
        + cfg["w_success"] * s_success
    )

    # Penalties (multiplicative)
    if profile.get("identity_mismatch"):
        score *= cfg["identity_penalty"]
    if lost_disputes > 0:
        penalty = max(cfg["dispute_penalty_floor"],
                      1.0 - lost_disputes * cfg["dispute_penalty_per_loss"])
        score *= penalty

    score = math.floor(score)
    computed_at = now.isoformat()

    # Sign: "{agent_id}:{score}:{computed_at}" with Ed25519
    canonical_id = agent_id if agent_id.startswith("sha256:") else f"sha256:{agent_id}"
    sign_payload = f"{canonical_id}:{score}:{computed_at}"
    signing_key = get_signing_key()
    signature = sign_proof(signing_key, sign_payload) if signing_key else None

    return {
        "agent_id": canonical_id,
        "declared_identity": profile.get("declared_identity"),
        "identity_mismatch": profile.get("identity_mismatch", False),
        "first_proof_at": profile.get("first_seen"),
        "last_proof_at": profile.get("last_transaction"),
        "total_proofs": total_proofs,
        "succeeded_proofs": succeeded,
        "unique_services": list(unique_services),
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


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------

def _ensure_reputation_dir():
    REPUTATION_DIR.mkdir(parents=True, exist_ok=True)


def _cache_path(agent_id: str) -> Path:
    clean_id = agent_id.replace("sha256:", "")[:16]
    return REPUTATION_DIR / f"{clean_id}.json"


def get_reputation(agent_id: str) -> dict | None:
    """Get reputation for an agent. Uses cache with TTL. Returns None if unknown."""
    _ensure_reputation_dir()

    # Check cache
    cache = _cache_path(agent_id)
    if cache.exists():
        cached = load_json(cache)
        cached_dt = _parse_timestamp(cached.get("computed_at"))
        if cached_dt:
            age = (datetime.now(timezone.utc) - cached_dt).total_seconds()
            if age < REPUTATION_CONFIG["cache_ttl_seconds"]:
                return cached

    # Resolve agent profile via fingerprint index
    _, profile = resolve_agent_profile(agent_id)
    if profile is None:
        return None

    clean_id = agent_id.replace("sha256:", "")
    result = compute_reputation(f"sha256:{clean_id}", profile)
    save_json(cache, result)
    return result


def invalidate_cache(agent_id: str):
    """Invalidate reputation cache for an agent."""
    _ensure_reputation_dir()
    cache = _cache_path(agent_id)
    cache.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Public-safe response (strips sensitive fields)
# ---------------------------------------------------------------------------

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
