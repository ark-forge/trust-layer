"""Free-mode guards: reversible paid-plans flag, global daily cap, kill switch, caps.

Every guard here fails closed: when Redis cannot be read or a setting cannot be
parsed, the free write is refused (503), never let through unlimited. A zero read
is told apart from a failed read.

Settings are read from the environment at call time so they can be flipped by the
operator without a code change:

- TL_PAID_PLANS_ENABLED    default true; false -> subscription routes answer 410
- TL_FREE_DAILY_GLOBAL_CAP default 20000 free proofs/day across all free keys
- TL_WRITES_PAUSED         env or Redis key of the same name; truthy -> free writes 503
                           (separate from the failover switch and from PROVE IT)
- TL_PROOF_EMAIL_DAILY_MAX default 20 proof emails/day per key
- TL_METRICS_SALT          salt for hashed identifiers; never in the repo
"""

import hashlib
import logging
import os
from datetime import UTC, datetime

from .redis_client import get_redis

logger = logging.getLogger("trust_layer.free_tier_guard")

_FALSE_VALUES = frozenset({"0", "false", "no", "off"})
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})

DEFAULT_FREE_DAILY_GLOBAL_CAP = 20000
DEFAULT_PROOF_EMAIL_DAILY_MAX = 20

# Counters outlive their UTC day by a margin; Redis drops them afterwards.
_DAY_TTL = 26 * 3600
_SIGNUP_WINDOW = 3600

PAUSED_REDIS_KEY = "TL_WRITES_PAUSED"


class GuardError(Exception):
    """A guard refused the request. Carries the HTTP status to answer."""

    def __init__(self, code: str, message: str, status: int):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _today() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def paid_plans_enabled() -> bool:
    """True unless TL_PAID_PLANS_ENABLED is explicitly false (default: true)."""
    return os.environ.get("TL_PAID_PLANS_ENABLED", "").strip().lower() not in _FALSE_VALUES


def hash_identifier(value: str) -> str:
    """Salted SHA-256 of an identifier (IP, email, key). Empty when no salt is set.

    No salt means no hash: callers then store nothing rather than an unsalted
    digest that a dictionary of IPv4 addresses would reverse.
    """
    salt = os.environ.get("TL_METRICS_SALT", "")
    if not salt or not value:
        return ""
    return hashlib.sha256(f"{salt}\x00{value}".encode()).hexdigest()


def _int_setting(name: str, default: int) -> int | None:
    """Integer setting; default when unset, None when set but unusable."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        return None
    return value if value >= 0 else None


def _cap_key() -> str:
    return f"tl:free_cap:{_today()}"


def _truthy(raw) -> bool:
    return str(raw).strip().lower() in _TRUE_VALUES


def _refuse_unavailable(reason: str) -> GuardError:
    return GuardError(
        "service_degraded",
        f"Free proof creation is temporarily unavailable ({reason}). Retry later.",
        503,
    )


def writes_paused() -> bool:
    """True when the kill switch is on (environment variable or Redis key)."""
    if _truthy(os.environ.get(PAUSED_REDIS_KEY, "")):
        return True
    r = get_redis()
    if r is None:
        return False
    try:
        return _truthy(r.get(PAUSED_REDIS_KEY) or "")
    except Exception:
        return False


def reserve_free_proof() -> str:
    """Count one free proof BEFORE the write; raise GuardError when it must not happen.

    One INCR (inside a MULTI with its EXPIRE) per proof, so two concurrent requests
    at cap - 1 cannot both pass. Returns the counter key actually incremented: the
    caller hands it back to release_free_proof so a release after midnight UTC hits
    the same day's counter.
    """
    if _truthy(os.environ.get(PAUSED_REDIS_KEY, "")):
        raise _refuse_unavailable("writes paused")
    cap = _int_setting("TL_FREE_DAILY_GLOBAL_CAP", DEFAULT_FREE_DAILY_GLOBAL_CAP)
    if cap is None:
        logger.error("TL_FREE_DAILY_GLOBAL_CAP is not a non-negative integer: free writes refused")
        raise _refuse_unavailable("cap misconfigured")
    r = get_redis()
    if r is None:
        raise _refuse_unavailable("counter unavailable")
    try:
        if _truthy(r.get(PAUSED_REDIS_KEY) or ""):
            raise _refuse_unavailable("writes paused")
        pipe = r.pipeline(transaction=True)
        cap_key = _cap_key()
        pipe.incr(cap_key)
        pipe.expire(cap_key, _DAY_TTL)
        count = int(pipe.execute()[0])
    except GuardError:
        raise
    except Exception as e:
        logger.error("Free cap counter failed, free write refused: %s", e)
        raise _refuse_unavailable("counter unavailable") from e
    if count > cap:
        release_free_proof(cap_key)
        raise GuardError(
            "free_daily_cap_reached",
            "The global daily limit of free proofs is reached. Retry tomorrow (UTC).",
            429,
        )
    return cap_key


def release_free_proof(cap_key: str) -> None:
    """Give back a slot taken by reserve_free_proof (nothing was stored)."""
    r = get_redis()
    if r is None or not cap_key:
        return
    try:
        pipe = r.pipeline(transaction=True)
        pipe.decr(cap_key)
        pipe.expire(cap_key, _DAY_TTL)
        pipe.execute()
    except Exception as e:
        logger.error("Free cap release failed: %s", e)


def proof_email_allowed(key_fingerprint: str) -> bool:
    """True when this key may still send a proof email today. False when undecidable."""
    cap = _int_setting("TL_PROOF_EMAIL_DAILY_MAX", DEFAULT_PROOF_EMAIL_DAILY_MAX)
    if cap is None or not key_fingerprint:
        return False
    r = get_redis()
    if r is None:
        return False
    name = f"tl:proof_mail:{_today()}:{key_fingerprint}"
    try:
        pipe = r.pipeline(transaction=True)
        pipe.incr(name)
        pipe.expire(name, _DAY_TTL)
        return int(pipe.execute()[0]) <= cap
    except Exception as e:
        logger.warning("Proof email counter failed, email skipped: %s", e)
        return False


def signup_count(ip_id: str) -> int | None:
    """Count one signup for this IP in the current UTC hour; None when Redis cannot say.

    Fixed hourly bucket in the key name, so the EXPIRE can ride in the same
    transaction as the INCR and a counter can never be left without a TTL.
    """
    r = get_redis()
    if r is None:
        return None
    name = f"tl:signup_ip:{datetime.now(UTC).strftime('%Y%m%d%H')}:{ip_id}"
    try:
        pipe = r.pipeline(transaction=True)
        pipe.incr(name)
        pipe.expire(name, _SIGNUP_WINDOW + 60)
        return int(pipe.execute()[0])
    except Exception as e:
        logger.warning("Signup counter failed, using the node-local limit: %s", e)
        return None
