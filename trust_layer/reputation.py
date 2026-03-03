"""Reputation Score — deterministic 0-100 score based on agent proof history.

Formula (public, auditable from proof history alone):
    score = floor(success_rate × confidence) − penalties

    success_rate  = succeeded_proofs / total_proofs × 100
    confidence    = f(total_proofs): 0-1→0.60, 2-4→0.75, 5-19→0.85, 20+→1.00
    penalty       = −15 if identity mismatch (X-Agent-Identity changed between calls)

Score is signed with Ed25519 for verifiable authenticity.
"""

import math
from datetime import datetime, timezone
from pathlib import Path

from .config import AGENTS_DIR, get_signing_key, ARKFORGE_PUBLIC_KEY
from .crypto import sign_proof
from .persistence import load_json, save_json

REPUTATION_CONFIG = {
    # Confidence thresholds (volume → confidence factor)
    # score = floor(success_rate × confidence) − penalties
    # Rules are public — any party can recompute the score from the proof history.
    "confidence_thresholds": [
        # (upper_bound_exclusive, factor) — first matching rule wins
        (2,  0.60),   # 0-1 proofs  → 60% confidence (provisional)
        (5,  0.75),   # 2-4         → 75%
        (20, 0.85),   # 5-19        → 85%
        (None, 1.00), # 20+         → 100% (full confidence)
    ],
    # Penalties (additive, applied after confidence scaling)
    "identity_mismatch_penalty": 15,   # X-Agent-Identity changed — deducted once
    # Cache
    "cache_ttl_seconds": 3600,
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
    """Compute reputation score from agent profile. Returns full reputation record.

    Formula (public, auditable):
        score = floor(success_rate × confidence) − penalties

    success_rate = succeeded / total × 100  (0–100)
    confidence   = function of total proofs (volume → confidence):
        1 proof  → 0.60  (provisional)
        2–4      → 0.75
        5–19     → 0.85
        20+      → 1.00  (full confidence)
    penalties (additive, after scaling):
        identity mismatch  → −15 (once)
    """
    cfg = REPUTATION_CONFIG
    now = datetime.now(timezone.utc)

    total_proofs = profile.get("transactions_total", 0)
    succeeded = profile.get("transactions_succeeded", 0)
    unique_services = profile.get("services_used", [])

    # Success rate (0–100)
    success_rate = (succeeded / total_proofs * 100.0) if total_proofs > 0 else 0.0

    # Confidence factor from volume thresholds (iterate until threshold not exceeded)
    confidence = 1.00
    for threshold, factor in cfg["confidence_thresholds"]:
        if threshold is None or total_proofs < threshold:
            confidence = factor
            break

    score = math.floor(success_rate * confidence)

    # Penalty (additive, applied after scaling)
    if profile.get("identity_mismatch"):
        score = max(0, score - cfg["identity_mismatch_penalty"])

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
        "active_days_30d": len(profile.get("proof_dates_30d", [])),
        "amount_total_eur": profile.get("amount_total_eur", 0.0),
        "scoring": {
            "success_rate": round(success_rate, 1),
            "confidence": confidence,
            "formula": "floor(success_rate × confidence) − penalties",
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
        "scoring": rep.get("scoring"),
        "total_proofs": rep["total_proofs"],
        "first_proof_at": rep.get("first_proof_at"),
        "last_proof_at": rep.get("last_proof_at"),
        "unique_services_count": len(rep.get("unique_services", [])),
        "signature": rep.get("signature"),
        "computed_at": rep["computed_at"],
    }
