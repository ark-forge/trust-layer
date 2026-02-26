"""Per-API-key rate limiting — daily counter + monthly free tier."""

import logging
from datetime import datetime, timezone, timedelta

from .config import RATE_LIMITS_FILE, RATE_LIMIT_PER_KEY_PER_DAY, FREE_TIER_MONTHLY_LIMIT
from .keys import is_free_key, get_key_plan
from .persistence import load_json, save_json

logger = logging.getLogger("trust_layer.rate_limit")


def check_rate_limit(api_key: str, limit: int = RATE_LIMIT_PER_KEY_PER_DAY) -> tuple[bool, int]:
    """Check if API key is within limits. Returns (allowed, remaining).

    - All keys: daily limit (default 100/day, safety cap)
    - Free keys: additional monthly limit (100/month)
    """
    limits = load_json(RATE_LIMITS_FILE, {})
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    month = datetime.now(timezone.utc).strftime("%Y-%m")

    key_id = api_key[:16]
    entry = limits.get(key_id, {"date": today, "count": 0, "month": month, "month_count": 0})

    # Reset daily counter
    if entry.get("date") != today:
        entry["date"] = today
        entry["count"] = 0

    # Reset monthly counter
    if entry.get("month") != month:
        entry["month"] = month
        entry["month_count"] = 0

    # Check daily limit (all keys)
    daily_remaining = max(0, limit - entry["count"])
    if daily_remaining <= 0:
        limits[key_id] = entry
        save_json(RATE_LIMITS_FILE, limits)
        return False, 0

    # Check monthly limit (free keys only)
    if is_free_key(api_key):
        monthly_remaining = max(0, FREE_TIER_MONTHLY_LIMIT - entry.get("month_count", 0))
        if monthly_remaining <= 0:
            limits[key_id] = entry
            save_json(RATE_LIMITS_FILE, limits)
            return False, 0

    # Allowed — increment both counters
    entry["count"] += 1
    entry["month_count"] = entry.get("month_count", 0) + 1
    limits[key_id] = entry

    # Clean stale entries (different day AND different month)
    limits = {k: v for k, v in limits.items()
              if v.get("date") == today or v.get("month") == month}
    save_json(RATE_LIMITS_FILE, limits)

    if is_free_key(api_key):
        remaining = min(daily_remaining - 1, FREE_TIER_MONTHLY_LIMIT - entry["month_count"])
    else:
        remaining = daily_remaining - 1

    return True, max(0, remaining)


def get_usage(api_key: str, limit: int = RATE_LIMIT_PER_KEY_PER_DAY) -> dict:
    """Get current usage for an API key."""
    limits = load_json(RATE_LIMITS_FILE, {})
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    key_id = api_key[:16]
    entry = limits.get(key_id, {"date": today, "count": 0, "month": month, "month_count": 0})

    plan = get_key_plan(api_key)

    daily_used = entry.get("count", 0) if entry.get("date") == today else 0
    monthly_used = entry.get("month_count", 0) if entry.get("month") == month else 0

    result = {
        "plan": plan,
        "daily": {"used": daily_used, "limit": limit, "remaining": max(0, limit - daily_used)},
    }

    if plan == "free":
        result["monthly"] = {
            "used": monthly_used,
            "limit": FREE_TIER_MONTHLY_LIMIT,
            "remaining": max(0, FREE_TIER_MONTHLY_LIMIT - monthly_used),
        }

    return result


def check_quota_alerts(limit: int = RATE_LIMIT_PER_KEY_PER_DAY) -> list[dict]:
    """Check all keys for >80% daily quota usage. Returns list of alerts."""
    limits = load_json(RATE_LIMITS_FILE, {})
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    alerts = []
    for key_id, entry in limits.items():
        if entry.get("date") != today:
            continue
        used = entry.get("count", 0)
        if used >= limit * 0.8:
            alerts.append({
                "key_prefix": key_id,
                "used": used,
                "limit": limit,
                "pct": round(used / limit * 100, 1),
            })
            logger.info("API key %s at %d%% of daily quota (%d/%d)", key_id, round(used / limit * 100), used, limit)
    return alerts


def rotate_stale_entries(max_age_days: int = 30):
    """Purge rate limit entries older than max_age_days."""
    limits = load_json(RATE_LIMITS_FILE, {})
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).strftime("%Y-%m-%d")
    before = len(limits)
    limits = {k: v for k, v in limits.items() if v.get("date", "9999") >= cutoff}
    after = len(limits)
    if before != after:
        save_json(RATE_LIMITS_FILE, limits)
        logger.info("Rate limits rotation: removed %d stale entries (>%d days)", before - after, max_age_days)
    return before - after
