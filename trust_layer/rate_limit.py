"""Per-API-key rate limiting — daily counter with auto-reset."""

import logging
from datetime import datetime, timezone

from .config import RATE_LIMITS_FILE, RATE_LIMIT_PER_KEY_PER_DAY
from .persistence import load_json, save_json

logger = logging.getLogger("trust_layer.rate_limit")


def check_rate_limit(api_key: str, limit: int = RATE_LIMIT_PER_KEY_PER_DAY) -> tuple[bool, int]:
    """Check if API key is within daily limit. Returns (allowed, remaining)."""
    limits = load_json(RATE_LIMITS_FILE, {})
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Clean old entries
    limits = {k: v for k, v in limits.items() if v.get("date") == today}

    key_id = api_key[:16]  # use prefix as identifier
    entry = limits.get(key_id, {"date": today, "count": 0})
    if entry.get("date") != today:
        entry = {"date": today, "count": 0}

    remaining = max(0, limit - entry["count"])
    allowed = remaining > 0

    if allowed:
        entry["count"] += 1
        entry["date"] = today
        limits[key_id] = entry
        save_json(RATE_LIMITS_FILE, limits)
        remaining -= 1

    return allowed, remaining


def get_usage(api_key: str, limit: int = RATE_LIMIT_PER_KEY_PER_DAY) -> dict:
    """Get current usage for an API key."""
    limits = load_json(RATE_LIMITS_FILE, {})
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key_id = api_key[:16]
    entry = limits.get(key_id, {"date": today, "count": 0})
    if entry.get("date") != today:
        return {"used": 0, "limit": limit, "remaining": limit}
    used = entry.get("count", 0)
    return {"used": used, "limit": limit, "remaining": max(0, limit - used)}
