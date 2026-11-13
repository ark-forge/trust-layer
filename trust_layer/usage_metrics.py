"""Aggregated daily usage measurement (totals only, no identifier kept).

Per UTC day, in Redis:
- tl:m:<day>:free_keys_created, :proofs, :verifications  plain counters
- tl:m:<day>:active_keys                                  HyperLogLog of salted key hashes

A HyperLogLog answers "how many distinct keys" and cannot list them back, so no
per-key or per-IP figure exists anywhere, even hashed. Without TL_METRICS_SALT the
active-key sketch is skipped rather than fed with unsalted digests.

Measurement is best effort: a Redis failure is logged and never blocks a request
(it is not a guard). Internal IPs and internal keys are excluded by the callers.
"""

import logging
from datetime import datetime, timedelta, timezone

from .free_tier_guard import hash_identifier
from .redis_client import get_redis

logger = logging.getLogger("trust_layer.usage_metrics")

_RETENTION = 400 * 86400
MAX_DAYS = 90


def _name(day: str, metric: str) -> str:
    return f"tl:m:{day}:{metric}"


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _bump(metric: str) -> None:
    r = get_redis()
    if r is None:
        return
    name = _name(_today(), metric)
    try:
        pipe = r.pipeline(transaction=True)
        pipe.incr(name)
        pipe.expire(name, _RETENTION)
        pipe.execute()
    except Exception as e:
        logger.warning("Metric %s not recorded: %s", metric, e)


def record_free_signup() -> None:
    _bump("free_keys_created")


def record_verification() -> None:
    _bump("verifications")


def record_proof(api_key: str) -> None:
    """Count one proof and mark the key active today (salted hash, sketch only)."""
    _bump("proofs")
    key_id = hash_identifier(api_key)
    r = get_redis()
    if r is None or not key_id:
        return
    name = _name(_today(), "active_keys")
    try:
        pipe = r.pipeline(transaction=True)
        pipe.pfadd(name, key_id)
        pipe.expire(name, _RETENTION)
        pipe.execute()
    except Exception as e:
        logger.warning("Active key sketch not updated: %s", e)


class MetricsUnavailable(RuntimeError):
    """Redis cannot be read: a failed read must not look like a day of zeros."""


def snapshot(days: int) -> dict:
    """Daily totals for the last `days` days, oldest first. Totals only."""
    days = max(1, min(int(days), MAX_DAYS))
    r = get_redis()
    if r is None:
        raise MetricsUnavailable("Redis unavailable")
    today = datetime.now(timezone.utc).date()
    rows = []
    for offset in range(days - 1, -1, -1):
        day = (today - timedelta(days=offset)).strftime("%Y-%m-%d")
        row = {"date": day, "free_keys_created": 0, "active_keys": 0, "proofs": 0,
               "external_verifications": 0}
        try:
            row["free_keys_created"] = int(r.get(_name(day, "free_keys_created")) or 0)
            row["proofs"] = int(r.get(_name(day, "proofs")) or 0)
            row["external_verifications"] = int(r.get(_name(day, "verifications")) or 0)
            row["active_keys"] = int(r.pfcount(_name(day, "active_keys")))
        except Exception as e:
            logger.warning("Metrics read failed for %s: %s", day, e)
            raise MetricsUnavailable(str(e)) from e
        rows.append(row)
    return {"days": rows}
