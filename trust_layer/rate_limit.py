"""Per-API-key rate limiting — daily counter + monthly quota (free & pro/enterprise)."""

import logging
import threading
from datetime import datetime, timezone, timedelta

from .config import (
    RATE_LIMITS_FILE, RATE_LIMIT_PER_KEY_PER_DAY, FREE_TIER_MONTHLY_LIMIT,
    OVERAGE_PRICES, _PRO_MONTHLY_LIMIT, _ENTERPRISE_MONTHLY_LIMIT,
)
from .keys import is_free_key, get_key_plan, validate_api_key
from .persistence import load_json, save_json

logger = logging.getLogger("trust_layer.rate_limit")

_ALERT_THRESHOLD = 0.80  # send alert when usage crosses this fraction

# Global lock — serialises all rate_limits.json write operations.
# Prevents TOCTOU races when concurrent threads call check_rate_limit simultaneously.
_RATE_LIMIT_LOCK = threading.Lock()

# Monthly quotas per plan (None = no monthly quota, daily cap only)
_MONTHLY_LIMITS = {
    "free": FREE_TIER_MONTHLY_LIMIT,
    "pro": _PRO_MONTHLY_LIMIT,
    "enterprise": _ENTERPRISE_MONTHLY_LIMIT,
    "test": None,
}


def check_rate_limit(api_key: str, limit: int = RATE_LIMIT_PER_KEY_PER_DAY) -> tuple[bool, int, bool, str]:
    """Check if API key is within limits.

    Returns (allowed, remaining, is_overage, block_reason).
    block_reason: '' (allowed), 'daily_cap', 'monthly_quota', 'overage_cap'
    is_overage: True when the proof is beyond the monthly quota but within overage cap.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    key_id = api_key[:16]
    plan = get_key_plan(api_key)
    remaining = 0
    is_overage = False
    block_reason = ""

    with _RATE_LIMIT_LOCK:
        limits = load_json(RATE_LIMITS_FILE, {})
        entry = limits.get(key_id, {
            "date": today, "count": 0,
            "month": month, "month_count": 0,
        })

        # Reset daily counter
        if entry.get("date") != today:
            entry["date"] = today
            entry["count"] = 0

        # Reset monthly counter + overage fields on month rollover
        if entry.get("month") != month:
            entry["month"] = month
            entry["month_count"] = 0
            entry["overage_count"] = 0
            entry["overage_spent_eur"] = 0.0
            entry["overage_first_alert_sent"] = False
            entry["overage_80pct_alert_sent"] = False
            entry["overage_cap_alert_sent"] = False

        # 1. Daily cap check (all keys, always first)
        daily_remaining = max(0, limit - entry["count"])
        if daily_remaining <= 0:
            limits[key_id] = entry
            save_json(RATE_LIMITS_FILE, limits)
            return False, 0, False, "daily_cap"

        # 2. Monthly quota check
        monthly_limit = _MONTHLY_LIMITS.get(plan)
        if monthly_limit is not None:
            monthly_used = entry.get("month_count", 0)
            monthly_remaining = max(0, monthly_limit - monthly_used)

            if monthly_remaining > 0:
                # Within quota — normal proof
                entry["count"] += 1
                entry["month_count"] = monthly_used + 1
                remaining = min(daily_remaining - 1, monthly_remaining - 1)
                limits[key_id] = entry
                _cleanup_stale(limits, today, month)
                save_json(RATE_LIMITS_FILE, limits)
                entry_snapshot = dict(entry)
            else:
                # Monthly quota exhausted — check overage
                key_info = validate_api_key(api_key) or {}
                overage_enabled = key_info.get("overage_enabled", False)

                if not overage_enabled:
                    limits[key_id] = entry
                    save_json(RATE_LIMITS_FILE, limits)
                    return False, 0, False, "monthly_quota"

                # Overage path
                overage_price = OVERAGE_PRICES.get(plan, 0.01)
                cap = float(key_info.get("overage_cap_eur", 20.0))
                spent = float(entry.get("overage_spent_eur", 0.0))

                if round(spent + overage_price, 4) > round(cap, 4):
                    # Cap reached — send alert flag (actual email outside lock)
                    entry["overage_cap_alert_sent"] = True
                    limits[key_id] = entry
                    save_json(RATE_LIMITS_FILE, limits)
                    return False, 0, False, "overage_cap"

                # Allow overage
                entry["count"] += 1
                entry["month_count"] = monthly_used + 1
                entry["overage_count"] = entry.get("overage_count", 0) + 1
                entry["overage_spent_eur"] = round(spent + overage_price, 4)
                remaining = 0
                is_overage = True
                limits[key_id] = entry
                _cleanup_stale(limits, today, month)
                save_json(RATE_LIMITS_FILE, limits)
                entry_snapshot = dict(entry)
        else:
            # No monthly limit (test keys) — normal proof
            entry["count"] += 1
            entry["month_count"] = entry.get("month_count", 0) + 1
            remaining = daily_remaining - 1
            limits[key_id] = entry
            _cleanup_stale(limits, today, month)
            save_json(RATE_LIMITS_FILE, limits)
            entry_snapshot = dict(entry)

    # Outside lock: send alerts (I/O)
    _maybe_send_quota_alert(api_key, entry_snapshot, limit, today, month)
    if is_overage:
        _maybe_send_overage_alerts(api_key, entry_snapshot, plan)

    return True, max(0, remaining), is_overage, ""


def _cleanup_stale(limits: dict, today: str, month: str) -> None:
    """Remove rate limit entries from a different day AND a different month."""
    to_delete = [
        k for k, v in limits.items()
        if v.get("date") != today and v.get("month") != month
    ]
    for k in to_delete:
        del limits[k]


def rollback_overage(api_key: str) -> None:
    """Rollback overage counters when credit debit fails after rate limiter increment."""
    key_id = api_key[:16]
    plan = get_key_plan(api_key)
    overage_price = OVERAGE_PRICES.get(plan, 0.01)

    with _RATE_LIMIT_LOCK:
        limits = load_json(RATE_LIMITS_FILE, {})
        entry = limits.get(key_id)
        if not entry:
            return

        count = entry.get("overage_count", 0)
        spent = entry.get("overage_spent_eur", 0.0)
        month_count = entry.get("month_count", 0)

        entry["overage_count"] = max(0, count - 1)
        entry["overage_spent_eur"] = max(0.0, round(spent - overage_price, 4))
        entry["month_count"] = max(0, month_count - 1)
        entry["count"] = max(0, entry.get("count", 0) - 1)

        limits[key_id] = entry
        save_json(RATE_LIMITS_FILE, limits)
        logger.info("Overage rollback for %s (count=%d→%d)", key_id, count, entry["overage_count"])


def _maybe_send_quota_alert(api_key: str, entry: dict, daily_limit: int, today: str, month: str):
    """Send a one-time quota alert email when usage first crosses 80%."""
    try:
        from .email_notify import send_quota_alert_email

        key_info = validate_api_key(api_key)
        email = (key_info or {}).get("email", "")
        if not email:
            return

        if is_free_key(api_key):
            # Monthly quota alert for free keys
            month_count = entry.get("month_count", 0)
            alert_key = f"alert_monthly_{month}"
            if (month_count >= FREE_TIER_MONTHLY_LIMIT * _ALERT_THRESHOLD
                    and not entry.get(alert_key)):
                entry[alert_key] = True
                send_quota_alert_email(email, api_key, month_count, FREE_TIER_MONTHLY_LIMIT, "monthly")
                logger.info("Monthly quota alert sent to %s (%d/%d)", email, month_count, FREE_TIER_MONTHLY_LIMIT)
        else:
            # Daily quota alert for pro/test keys
            daily_count = entry.get("count", 0)
            alert_key = f"alert_daily_{today}"
            if (daily_count >= daily_limit * _ALERT_THRESHOLD
                    and not entry.get(alert_key)):
                entry[alert_key] = True
                send_quota_alert_email(email, api_key, daily_count, daily_limit, "daily")
                logger.info("Daily quota alert sent to %s (%d/%d)", email, daily_count, daily_limit)
    except Exception as e:
        logger.warning("Quota alert skipped: %s", e)


def _maybe_send_overage_alerts(api_key: str, entry: dict, plan: str):
    """Send overage milestone emails (first overage, 80% cap, cap reached)."""
    try:
        from .email_notify import send_overage_first_email, send_overage_80pct_email, send_overage_cap_email

        key_info = validate_api_key(api_key) or {}
        email = key_info.get("email", "")
        if not email:
            return

        cap = float(key_info.get("overage_cap_eur", 20.0))
        spent = float(entry.get("overage_spent_eur", 0.0))
        count = entry.get("overage_count", 0)

        # 1st overage of the month
        if count == 1 and not entry.get("overage_first_alert_sent"):
            send_overage_first_email(email, api_key, plan, spent, cap)
            # Note: we can't update the file here (outside lock) — the flag was set inside lock
            logger.info("Overage first alert sent to %s", email)

        # 80% of cap
        if not entry.get("overage_80pct_alert_sent") and spent >= cap * 0.8:
            send_overage_80pct_email(email, api_key, plan, spent, cap)
            logger.info("Overage 80pct alert sent to %s (%.2f/%.2f)", email, spent, cap)

        # Cap reached (flag was set inside lock before this call doesn't happen here;
        # the cap alert is sent inside the lock branch when we return False, overage_cap)
        # — the cap email is triggered in a separate path for the blocked request

    except Exception as e:
        logger.warning("Overage alert skipped: %s", e)


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

    monthly_limit = _MONTHLY_LIMITS.get(plan)
    if monthly_limit is not None:
        result["monthly"] = {
            "used": monthly_used,
            "limit": monthly_limit,
            "remaining": max(0, monthly_limit - monthly_used),
        }

    # Overage section (only when enabled)
    key_info = validate_api_key(api_key) or {}
    if key_info.get("overage_enabled"):
        overage_count = entry.get("overage_count", 0) if entry.get("month") == month else 0
        overage_spent = entry.get("overage_spent_eur", 0.0) if entry.get("month") == month else 0.0
        cap = float(key_info.get("overage_cap_eur", 20.0))
        result["overage"] = {
            "enabled": True,
            "cap_eur": cap,
            "spent_eur": overage_spent,
            "count": overage_count,
            "remaining_eur": round(cap - overage_spent, 4),
            "rate_per_proof": OVERAGE_PRICES.get(plan, 0),
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
