"""Dispute System — automatic resolution of proof contestations."""

import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path

from .config import AGENTS_DIR
from .persistence import load_json, save_json
from .proofs import load_proof, store_proof
from .reputation import REPUTATION_CONFIG, invalidate_cache

# Directory for dispute files
DISPUTES_DIR: Path = AGENTS_DIR.parent / "disputes"


def _ensure_disputes_dir():
    DISPUTES_DIR.mkdir(parents=True, exist_ok=True)


def _generate_dispute_id() -> str:
    return f"disp_{secrets.token_hex(4)}"


def _get_buyer_fingerprint(api_key: str) -> str:
    """SHA-256 of API key = buyer fingerprint."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _load_agent_profile(agent_id: str) -> tuple[Path, dict]:
    """Load agent profile by fingerprint. Returns (path, profile)."""
    clean_id = agent_id.replace("sha256:", "")
    prefix = clean_id[:16]
    path = AGENTS_DIR / f"{prefix}.json"
    return path, load_json(path, {})


def _save_agent_profile(path: Path, profile: dict):
    save_json(path, profile)


def _get_open_disputes_count(agent_id: str) -> int:
    """Count open disputes filed by this agent."""
    _ensure_disputes_dir()
    count = 0
    clean_id = agent_id.replace("sha256:", "")
    for f in DISPUTES_DIR.glob("disp_*.json"):
        d = load_json(f, {})
        contestant = d.get("contestant_id", "").replace("sha256:", "")
        if contestant == clean_id and d.get("status") in ("PENDING",):
            count += 1
    return count


def _get_last_dispute_time(agent_id: str) -> datetime | None:
    """Find the most recent dispute timestamp for an agent."""
    _ensure_disputes_dir()
    clean_id = agent_id.replace("sha256:", "")
    latest = None
    for f in DISPUTES_DIR.glob("disp_*.json"):
        d = load_json(f, {})
        contestant = d.get("contestant_id", "").replace("sha256:", "")
        if contestant == clean_id:
            created = d.get("created_at", "")
            if created:
                try:
                    dt = datetime.fromisoformat(created)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    if latest is None or dt > latest:
                        latest = dt
                except (ValueError, TypeError):
                    pass
    return latest


def _check_already_disputed(proof_id: str) -> bool:
    """Check if a proof has already been disputed."""
    _ensure_disputes_dir()
    for f in DISPUTES_DIR.glob("disp_*.json"):
        d = load_json(f, {})
        if d.get("proof_id") == proof_id:
            return True
    return False


def resolve_dispute(proof: dict, contestant_id: str, contestant_role: str, dispute_type: str) -> tuple[str, str, bool]:
    """Resolve a dispute. Returns (status, details, proof_corrected).

    status: UPHELD, DENIED, REJECTED
    """
    buyer = proof.get("parties", {}).get("buyer_fingerprint", "")
    seller = proof.get("parties", {}).get("seller", "")

    clean_contestant = contestant_id.replace("sha256:", "")

    # Check contestant is a party
    if clean_contestant != buyer and clean_contestant != seller:
        return "REJECTED", "Contestant is not a party to this proof", False

    recorded_status = proof.get("upstream_status_code")
    if recorded_status is None:
        return "DENIED", "Proof does not contain upstream status code; cannot verify", False

    if dispute_type == "buyer_contests_success":
        if recorded_status >= 400:
            return "UPHELD", f"upstream_status_code={recorded_status} confirms failure", True
        else:
            return "DENIED", f"upstream_status_code={recorded_status} contradicts claim", False
    elif dispute_type == "seller_contests_failure":
        if recorded_status < 400:
            return "UPHELD", f"upstream_status_code={recorded_status} confirms success", True
        else:
            return "DENIED", f"upstream_status_code={recorded_status} contradicts claim", False

    return "DENIED", "Unknown dispute type", False


def create_dispute(api_key: str, proof_id: str, reason: str) -> dict:
    """Create and resolve a dispute. Returns dispute record or error dict."""
    _ensure_disputes_dir()
    cfg = REPUTATION_CONFIG
    now = datetime.now(timezone.utc)

    contestant_id = f"sha256:{_get_buyer_fingerprint(api_key)}"

    # Validate reason
    if not reason or not reason.strip():
        return {"error": "reason_required", "message": "Reason cannot be empty", "status": 400}

    # Load proof
    proof = load_proof(proof_id)
    if proof is None:
        return {"error": "proof_not_found", "message": f"Proof '{proof_id}' not found", "status": 404}

    # Check contestant is a party to the proof
    buyer = proof.get("parties", {}).get("buyer_fingerprint", "")
    seller = proof.get("parties", {}).get("seller", "")
    clean_contestant = contestant_id.replace("sha256:", "")

    if clean_contestant != buyer and clean_contestant != seller:
        return {"error": "not_party", "message": "You are not a party to this proof", "status": 403}

    # Check dispute window (7 days)
    proof_ts = proof.get("timestamp", "")
    if proof_ts:
        try:
            proof_dt = datetime.fromisoformat(proof_ts.replace("Z", "+00:00"))
            if (now - proof_dt).days > cfg["dispute_window_days"]:
                return {"error": "window_expired", "message": f"Dispute window expired (>{cfg['dispute_window_days']} days)", "status": 409}
        except (ValueError, TypeError):
            pass

    # Check already disputed
    if _check_already_disputed(proof_id):
        return {"error": "already_disputed", "message": "This proof has already been disputed", "status": 409}

    # Check cooldown
    last_time = _get_last_dispute_time(contestant_id)
    if last_time:
        elapsed = (now - last_time).total_seconds()
        if elapsed < cfg["dispute_cooldown_seconds"]:
            return {"error": "cooldown", "message": f"Cooldown active ({int(cfg['dispute_cooldown_seconds'] - elapsed)}s remaining)", "status": 429}

    # Check max open disputes
    open_count = _get_open_disputes_count(contestant_id)
    if open_count >= cfg["max_open_disputes_per_agent"]:
        return {"error": "too_many_disputes", "message": f"Max {cfg['max_open_disputes_per_agent']} open disputes", "status": 429}

    # Check proof has upstream_status_code (proofs created before dispute system don't)
    if proof.get("upstream_status_code") is None:
        return {"error": "legacy_proof", "message": "This proof predates the dispute system and lacks verification data (no upstream_status_code)", "status": 422}

    # Determine contestant role and dispute type
    if clean_contestant == buyer:
        contestant_role = "buyer"
        transaction_success = proof.get("transaction_success", True)
        dispute_type = "buyer_contests_success" if transaction_success else "seller_contests_failure"
    else:
        contestant_role = "seller"
        transaction_success = proof.get("transaction_success", True)
        dispute_type = "seller_contests_failure" if not transaction_success else "buyer_contests_success"

    # Resolve instantly
    resolution, details, proof_corrected = resolve_dispute(proof, contestant_id, contestant_role, dispute_type)

    dispute_id = _generate_dispute_id()
    dispute_record = {
        "dispute_id": dispute_id,
        "proof_id": proof_id,
        "contestant_id": contestant_id,
        "contestant_role": contestant_role,
        "type": dispute_type,
        "reason": reason,
        "status": resolution,
        "resolution_details": details,
        "created_at": now.isoformat(),
        "resolved_at": now.isoformat(),
        "proof_corrected": proof_corrected,
    }

    # Save dispute
    save_json(DISPUTES_DIR / f"{dispute_id}.json", dispute_record)

    # Apply consequences
    if resolution == "UPHELD":
        # Correct the proof
        if proof_corrected:
            current_success = proof.get("transaction_success", True)
            proof["transaction_success"] = not current_success
            store_proof(proof_id, proof)

        # Loser = the other party
        if contestant_role == "buyer":
            loser_id = f"sha256:{seller}"
        else:
            loser_id = contestant_id

        _increment_lost_disputes(loser_id)
        invalidate_cache(contestant_id)
        invalidate_cache(loser_id)

    elif resolution == "DENIED":
        # Contestant loses
        _increment_lost_disputes(contestant_id)
        invalidate_cache(contestant_id)

    # Update contestant dispute stats
    _update_dispute_stats(contestant_id, resolution)

    return dispute_record


def _increment_lost_disputes(agent_id: str):
    """Increment lost_disputes counter in agent profile."""
    path, profile = _load_agent_profile(agent_id)
    if profile:
        profile["lost_disputes"] = profile.get("lost_disputes", 0) + 1
        _save_agent_profile(path, profile)


def _update_dispute_stats(agent_id: str, resolution: str):
    """Update disputes_filed, disputes_won, disputes_lost in agent profile."""
    path, profile = _load_agent_profile(agent_id)
    if profile:
        profile["disputes_filed"] = profile.get("disputes_filed", 0) + 1
        if resolution == "UPHELD":
            profile["disputes_won"] = profile.get("disputes_won", 0) + 1
        elif resolution == "DENIED":
            profile["disputes_lost"] = profile.get("disputes_lost", 0) + 1
        _save_agent_profile(path, profile)


def get_agent_disputes(agent_id: str) -> dict:
    """Get dispute summary for an agent."""
    _ensure_disputes_dir()
    clean_id = agent_id.replace("sha256:", "")

    path, profile = _load_agent_profile(agent_id)
    disputes_filed = profile.get("disputes_filed", 0) if profile else 0
    disputes_won = profile.get("disputes_won", 0) if profile else 0
    disputes_lost = profile.get("disputes_lost", 0) if profile else 0

    # Collect recent disputes
    recent = []
    for f in sorted(DISPUTES_DIR.glob("disp_*.json"), reverse=True):
        d = load_json(f, {})
        contestant = d.get("contestant_id", "").replace("sha256:", "")
        if contestant == clean_id:
            recent.append({
                "dispute_id": d.get("dispute_id"),
                "proof_id": d.get("proof_id"),
                "type": d.get("type"),
                "status": d.get("status"),
                "created_at": d.get("created_at"),
            })
            if len(recent) >= 10:
                break

    return {
        "agent_id": f"sha256:{clean_id}",
        "disputes_filed": disputes_filed,
        "disputes_won": disputes_won,
        "disputes_lost": disputes_lost,
        "recent_disputes": recent,
    }
