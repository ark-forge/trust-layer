"""Per-API-key rate limiting — safety daily cap + monthly quota by plan."""

import logging
import threading
from datetime import datetime, timezone, timedelta

from .config import (
    RATE_LIMITS_FILE, RATE_LIMIT_PER_KEY_PER_DAY,
    FREE_TIER_MONTHLY_LIMIT, PRO_MONTHLY_LIMIT, ENTERPRISE_MONTHLY_LIMIT,
)
from .keys import get_key_plan, validate_api_key
from .persistence import load_json, save_json

logger = logging.getLogger("trust_layer.rate_limit")

_ALERT_THRESHOLD = 0.80  # send alert when usage crosses this fraction

# Monthly quotas per plan
_MONTHLY_LIMITS = {
    "free": FREE_TIER_MONTHLY_LIMIT,
    "pro": PRO_MONTHLY_LIMIT,
    "enterprise": ENTERPRISE_MONTHLY_LIMIT,
    "test": None,  # no monthly limit for test keys
}

# Global lock — serialises all rate_limits.json write operations.
# Prevents TOCTOU races when concurrent threads call check_rate_limit simultaneously.
_RATE_LIMIT_LOCK = threading.Lock()


def _get_monthly_limit(plan: str) -> int | None:
    """Return monthly proof quota for a plan, or None if unlimited."""
    return _MONTHLY_LIMITS.get(plan)


def check_rate_limit(api_key: str, limit: int = RATE_LIMIT_PER_KEY_PER_DAY) -> tuple[bool, int]:
    """Check if API key is within limits. Returns (allowed, remaining).

    - All keys: daily safety cap (RATE_LIMIT_PER_KEY_PER_DAY)
    - free/pro/enterprise: monthly quota (enforced hard limit)
    - test: no monthly limit
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    key_id = api_key[:16]
    plan = get_key_plan(api_key)
    monthly_limit = _get_monthly_limit(plan)
    remaining = 0

    with _RATE_LIMIT_LOCK:
        limits = load_json(RATE_LIMITS_FILE, {})
        entry = limits.get(key_id, {"date": today, "count": 0, "month": month, "month_count": 0})

        # Reset daily counter
        if entry.get("date") != today:
            entry["date"] = today
            entry["count"] = 0

        # Reset monthly counter
        if entry.get("month") != month:
            entry["month"] = month
            entry["month_count"] = 0

        # Check daily safety cap (all keys)
        daily_remaining = max(0, limit - entry["count"])
        if daily_remaining <= 0:
            limits[key_id] = entry
            save_json(RATE_LIMITS_FILE, limits)
            return False, 0

        # Check monthly quota (free / pro / enterprise)
        if monthly_limit is not None:
            monthly_remaining = max(0, monthly_limit - entry.get("month_count", 0))
            if monthly_remaining <= 0:
                limits[key_id] = entry
                save_json(RATE_LIMITS_FILE, limits)
                return False, 0
        else:
            monthly_remaining = None

        # Allowed — increment counters
        entry["count"] += 1
        entry["month_count"] = entry.get("month_count", 0) + 1

        if monthly_remaining is not None:
            remaining = min(daily_remaining - 1, monthly_limit - entry["month_count"])
        else:
            remaining = daily_remaining - 1

        limits[key_id] = entry
        # Clean stale entries (different day AND different month)
        limits = {k: v for k, v in limits.items()
                  if v.get("date") == today or v.get("month") == month}
        save_json(RATE_LIMITS_FILE, limits)

    # Quota alert: fire once when usage crosses 80% threshold (outside lock — I/O)
    _maybe_send_quota_alert(api_key, plan, entry, limit, today, month)

    return True, max(0, remaining)


def _maybe_send_quota_alert(api_key: str, plan: str, entry: dict, daily_limit: int, today: str, month: str):
    """Send a one-time quota alert email when monthly usage first crosses 80%."""
    try:
        from .email_notify import send_quota_alert_email

        key_info = validate_api_key(api_key)
        email = (key_info or {}).get("email", "")
        if not email:
            return

        monthly_limit = _get_monthly_limit(plan)
        if monthly_limit is not None:
            month_count = entry.get("month_count", 0)
            alert_key = f"alert_monthly_{month}"
            if (month_count >= monthly_limit * _ALERT_THRESHOLD
                    and not entry.get(alert_key)):
                entry[alert_key] = True
                send_quota_alert_email(email, api_key, month_count, monthly_limit, "monthly")
                logger.info("Monthly quota alert sent to %s (%d/%d)", email, month_count, monthly_limit)
    except Exception as e:
        logger.warning("Quota alert skipped: %s", e)


def get_usage(api_key: str, limit: int = RATE_LIMIT_PER_KEY_PER_DAY) -> dict:
    """Get current usage for an API key."""
    limits = load_json(RATE_LIMITS_FILE, {})
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    key_id = api_key[:16]
    entry = limits.get(key_id, {"date": today, "count": 0, "month": month, "month_count": 0})

    plan = get_key_plan(api_key)
    monthly_limit = _get_monthly_limit(plan)

    daily_used = entry.get("count", 0) if entry.get("date") == today else 0
    monthly_used = entry.get("month_count", 0) if entry.get("month") == month else 0

    result = {
        "plan": plan,
        "daily": {"used": daily_used, "limit": limit, "remaining": max(0, limit - daily_used)},
    }

    if monthly_limit is not None:
        result["monthly"] = {
            "used": monthly_used,
            "limit": monthly_limit,
            "remaining": max(0, monthly_limit - monthly_used),
        }

    return result


def check_quota_alerts(limit: int = RATE_LIMIT_PER_KEY_PER_DAY) -> list[dict]:
    """Check all keys for >80% monthly quota usage. Returns list of alerts."""
    limits = load_json(RATE_LIMITS_FILE, {})
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    alerts = []
    for key_id, entry in limits.items():
        if entry.get("month") != month:
            continue
        month_count = entry.get("month_count", 0)
        # We don't have the plan from key_id prefix alone — use daily count as proxy
        used = entry.get("count", 0)
        if used >= limit * 0.8:
            alerts.append({
                "key_prefix": key_id,
                "used": used,
                "limit": limit,
                "pct": round(used / limit * 100, 1),
                "month_count": month_count,
            })
            logger.info("API key %s at %d%% of daily cap (%d/%d)", key_id, round(used / limit * 100), used, limit)
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
