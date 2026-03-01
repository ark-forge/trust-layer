"""Dispute System — automatic resolution of proof contestations.

Rules:
- Only parties to a proof (buyer or seller) can file a dispute.
- Resolution is instant and deterministic: re-check upstream_status_code.
- Losing a dispute costs -5% reputation (floor 50%).
- Anti-abuse: 1h cooldown between disputes, 7-day window, one dispute per proof.
- Sellers are services (domains), not agents — they don't have reputation profiles.
"""

import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path

from .persistence import load_json, save_json
from .proofs import load_proof, store_proof
from .reputation import REPUTATION_CONFIG, invalidate_cache, resolve_agent_profile

DISPUTES_DIR: Path = Path(__file__).parent.parent / "data" / "disputes"


def _ensure_disputes_dir():
    DISPUTES_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Resolution logic (pure function, no side effects)
# ---------------------------------------------------------------------------

def resolve_dispute(
    proof: dict, contestant_fingerprint: str, dispute_type: str,
) -> tuple[str, str, bool]:
    """Resolve a dispute from proof data alone.

    Returns (status, details, proof_corrected):
        UPHELD  — contestant is right, proof will be corrected
        DENIED  — proof data contradicts the claim
        REJECTED — contestant is not a party to this proof
    """
    buyer = proof.get("parties", {}).get("buyer_fingerprint", "")
    seller = proof.get("parties", {}).get("seller", "")

    if contestant_fingerprint != buyer and contestant_fingerprint != seller:
        return "REJECTED", "Contestant is not a party to this proof", False

    status_code = proof.get("upstream_status_code")
    if status_code is None:
        return "DENIED", "Proof lacks upstream_status_code; cannot verify", False

    if dispute_type == "buyer_contests_success":
        if status_code >= 400:
            return "UPHELD", f"upstream_status_code={status_code} confirms failure", True
        return "DENIED", f"upstream_status_code={status_code} contradicts claim", False

    if dispute_type == "seller_contests_failure":
        if status_code < 400:
            return "UPHELD", f"upstream_status_code={status_code} confirms success", True
        return "DENIED", f"upstream_status_code={status_code} contradicts claim", False

    return "DENIED", "Unknown dispute type", False


# ---------------------------------------------------------------------------
# Dispute creation (validation → resolution → consequences)
# ---------------------------------------------------------------------------

def create_dispute(api_key: str, proof_id: str, reason: str) -> dict:
    """Create and instantly resolve a dispute.

    Returns dispute record on success, or {"error": ..., "status": ...} on failure.
    """
    _ensure_disputes_dir()
    cfg = REPUTATION_CONFIG
    now = datetime.now(timezone.utc)

    contestant_fp = hashlib.sha256(api_key.encode("utf-8")).hexdigest()

    # --- Validation ---

    if not reason or not reason.strip():
        return {"error": "reason_required", "message": "Reason cannot be empty", "status": 400}

    proof = load_proof(proof_id)
    if proof is None:
        return {"error": "proof_not_found", "message": f"Proof '{proof_id}' not found", "status": 404}

    # Already disputed? (O(1) check via proof field, no file scan)
    if proof.get("disputed"):
        return {"error": "already_disputed", "message": "This proof has already been disputed", "status": 409}

    # Contestant must be a party
    buyer_fp = proof.get("parties", {}).get("buyer_fingerprint", "")
    seller_domain = proof.get("parties", {}).get("seller", "")
    if contestant_fp != buyer_fp and contestant_fp != seller_domain:
        return {"error": "not_party", "message": "You are not a party to this proof", "status": 403}

    # Dispute window (7 days from proof creation)
    proof_ts = proof.get("timestamp", "")
    if proof_ts:
        try:
            proof_dt = datetime.fromisoformat(proof_ts.replace("Z", "+00:00"))
            if (now - proof_dt).days > cfg["dispute_window_days"]:
                return {
                    "error": "window_expired",
                    "message": f"Dispute window expired (>{cfg['dispute_window_days']} days)",
                    "status": 409,
                }
        except (ValueError, TypeError):
            pass

    # Cooldown (O(1) check via agent profile, no file scan)
    profile_path, profile = resolve_agent_profile(f"sha256:{contestant_fp}")
    if profile:
        last_dispute = profile.get("last_dispute_at")
        if last_dispute:
            try:
                last_dt = datetime.fromisoformat(last_dispute)
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=timezone.utc)
                elapsed = (now - last_dt).total_seconds()
                if elapsed < cfg["dispute_cooldown_seconds"]:
                    remaining = int(cfg["dispute_cooldown_seconds"] - elapsed)
                    return {
                        "error": "cooldown",
                        "message": f"Cooldown active ({remaining}s remaining)",
                        "status": 429,
                    }
            except (ValueError, TypeError):
                pass

    # Legacy proofs without upstream_status_code can't be disputed
    if proof.get("upstream_status_code") is None:
        return {
            "error": "legacy_proof",
            "message": "This proof predates the dispute system and lacks verification data",
            "status": 422,
        }

    # Determine dispute type — contestant can only contest the current status
    tx_success = proof.get("transaction_success", True)
    if contestant_fp == buyer_fp:
        contestant_role = "buyer"
        if not tx_success:
            return {
                "error": "nothing_to_contest",
                "message": "Transaction already marked as failed",
                "status": 400,
            }
        dispute_type = "buyer_contests_success"
    else:
        contestant_role = "seller"
        if tx_success:
            return {
                "error": "nothing_to_contest",
                "message": "Transaction already marked as successful",
                "status": 400,
            }
        dispute_type = "seller_contests_failure"

    # --- Resolution (instant, deterministic) ---

    resolution, details, proof_corrected = resolve_dispute(
        proof, contestant_fp, dispute_type,
    )

    dispute_id = f"disp_{secrets.token_hex(4)}"
    dispute_record = {
        "dispute_id": dispute_id,
        "proof_id": proof_id,
        "contestant_id": f"sha256:{contestant_fp}",
        "contestant_role": contestant_role,
        "type": dispute_type,
        "reason": reason,
        "status": resolution,
        "resolution_details": details,
        "created_at": now.isoformat(),
        "resolved_at": now.isoformat(),
        "proof_corrected": proof_corrected,
    }
    save_json(DISPUTES_DIR / f"{dispute_id}.json", dispute_record)

    # --- Consequences ---

    # Mark proof as disputed (prevents duplicate disputes, O(1) check)
    proof["disputed"] = True
    proof["dispute_id"] = dispute_id

    if resolution == "UPHELD" and proof_corrected:
        # Flip the transaction status
        proof["transaction_success"] = not tx_success
        # Loser is the other party.
        # If buyer won → loser is seller. Sellers are services (domains), not agents.
        # They don't have reputation profiles, so no penalty to apply.
        if contestant_role == "seller":
            # Seller won → buyer loses
            _increment_lost_disputes(f"sha256:{buyer_fp}")
        # Invalidate both caches
        invalidate_cache(f"sha256:{contestant_fp}")
        invalidate_cache(f"sha256:{buyer_fp}")

    elif resolution == "DENIED":
        # Contestant filed a bad dispute → they pay the cost
        _increment_lost_disputes(f"sha256:{contestant_fp}")
        invalidate_cache(f"sha256:{contestant_fp}")

    # Save updated proof (disputed flag + optional status correction)
    store_proof(proof_id, proof)

    # Update contestant stats
    _update_dispute_stats(f"sha256:{contestant_fp}", resolution, now)

    return dispute_record


# ---------------------------------------------------------------------------
# Agent profile updates (O(1), no file scans)
# ---------------------------------------------------------------------------

def _increment_lost_disputes(agent_id: str):
    """Increment lost_disputes counter in agent profile."""
    path, profile = resolve_agent_profile(agent_id)
    if path and profile:
        profile["lost_disputes"] = profile.get("lost_disputes", 0) + 1
        save_json(path, profile)


def _update_dispute_stats(agent_id: str, resolution: str, timestamp: datetime):
    """Update dispute stats in agent profile."""
    path, profile = resolve_agent_profile(agent_id)
    if path and profile:
        profile["disputes_filed"] = profile.get("disputes_filed", 0) + 1
        if resolution == "UPHELD":
            profile["disputes_won"] = profile.get("disputes_won", 0) + 1
        elif resolution == "DENIED":
            profile["disputes_lost"] = profile.get("disputes_lost", 0) + 1
        profile["last_dispute_at"] = timestamp.isoformat()
        save_json(path, profile)


# ---------------------------------------------------------------------------
# Public dispute history
# ---------------------------------------------------------------------------

def get_agent_disputes(agent_id: str) -> dict:
    """Get dispute summary for an agent (public, no reason text exposed)."""
    _ensure_disputes_dir()
    clean_id = agent_id.replace("sha256:", "")

    _, profile = resolve_agent_profile(agent_id)
    disputes_filed = profile.get("disputes_filed", 0) if profile else 0
    disputes_won = profile.get("disputes_won", 0) if profile else 0
    disputes_lost = profile.get("disputes_lost", 0) if profile else 0

    # Collect recent disputes (sorted by file name = chronological)
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
