"""Free API key registration with address confirmation (TLREG).

No key exists before the mailbox owner confirms. The flow:

1. request_registration(): validate nothing about the address (the endpoints do),
   count the limits, store a pending record under reg_pending:{sha256(token)} with a
   24 h TTL, and return the token for the caller to mail.
2. confirm_registration(): consume the token atomically (GETDEL), then
   get_or_create_free_key() under the keys lock.

Everything fails closed: no Redis or no TL_METRICS_SALT means 503, before any mail
or key. Only a salted hash of the address and never the token reach the logs.
"""

import hashlib
import json
import logging
import re
import secrets
import time
from datetime import UTC, datetime

from . import free_tier_guard as guard
from .free_tier_guard import hash_identifier
from .keys import get_or_create_free_key

logger = logging.getLogger("trust_layer.registration")

REQUEST_MAX_PER_IP_PER_HOUR = 5
CONFIRM_MAX_PER_IP_PER_HOUR = 20
ADDRESS_MAX_PER_DAY = 3
DEFAULT_MAIL_DAILY_MAX = 500

PENDING_TTL = 24 * 3600
_ADDRESS_WINDOW = 24 * 3600
_HOUR = 3600
_DAY_TTL = 26 * 3600

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{20,128}$")
_META_FIELDS = {"source": 64, "scan_id": 32, "utm_source": 64, "utm_medium": 64, "utm_campaign": 64, "referrer": 300}


class RegistrationError(Exception):
    """A guard refused the request. Carries the HTTP status and a public code."""

    def __init__(self, code: str, message: str, status: int):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _unavailable() -> RegistrationError:
    return RegistrationError(
        "service_degraded", "Registration is temporarily unavailable. Retry later.", 503
    )


def _invalid_token() -> RegistrationError:
    return RegistrationError("invalid_token", "This confirmation link is invalid or has expired.", 400)


def _now() -> float:
    return time.time()


def _today() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _ready():
    """Return the Redis client; raise 503 when Redis or the salt is missing."""
    r = guard.get_redis()
    if r is None or not hash_identifier("probe"):
        raise _unavailable()
    return r


def _token_key(token: str) -> str:
    return "reg_pending:" + hashlib.sha256(token.encode()).hexdigest()


def _hourly_count(r, prefix: str, ip_id: str) -> int:
    name = f"{prefix}:{datetime.now(UTC).strftime('%Y%m%d%H')}:{ip_id}"
    pipe = r.pipeline(transaction=True)
    pipe.incr(name)
    pipe.expire(name, _HOUR + 60)
    return int(pipe.execute()[0])


def _address_count(r, addr_hash: str) -> int:
    """Count one request for this address in a 24 h window that blocked requests do not extend."""
    name = f"tl:reg_addr:{addr_hash}"
    pipe = r.pipeline(transaction=True)
    # SET NX EX creates the counter with its TTL in the same transaction as INCR:
    # no window where the counter exists without expiry, and blocked requests do not extend it.
    pipe.set(name, 0, ex=_ADDRESS_WINDOW, nx=True)
    pipe.incr(name)
    count = pipe.execute()[1]
    return int(count)


def _release(r, name: str) -> None:
    try:
        r.decr(name)
    except Exception as e:
        logger.error("Registration counter release failed: %s", type(e).__name__)


def _clean_meta(meta: dict | None) -> dict:
    meta = meta or {}
    return {k: str(meta.get(k) or "")[:n] for k, n in _META_FIELDS.items()}


def request_registration(email: str, ip: str, meta: dict | None = None) -> tuple[str, str] | None:
    """Store a pending record and return (email, token) to mail; None when no mail must go out.

    None is the silent refusal of the per-address cap: the caller still answers 202, so the
    answer tells nothing about the address. Raises RegistrationError for 429 (IP) and 503.
    """
    r = _ready()
    email = email.strip().lower()
    addr_hash = hash_identifier(email)
    ip_id = hash_identifier(ip)[:32]
    cap = guard._int_setting("TL_REG_MAIL_DAILY_MAX", DEFAULT_MAIL_DAILY_MAX)
    if cap is None:
        logger.error("TL_REG_MAIL_DAILY_MAX is not a non-negative integer: registration refused")
        raise _unavailable()
    addr_name = f"tl:reg_addr:{addr_hash}"
    mail_name = f"tl:reg_mail:{_today()}"
    took_addr = took_mail = False
    try:
        if _hourly_count(r, "tl:signup_ip", ip_id) > REQUEST_MAX_PER_IP_PER_HOUR:
            raise RegistrationError("rate_limited", "Too many signups. Try again later.", 429)
        if _address_count(r, addr_hash) > ADDRESS_MAX_PER_DAY:
            logger.info("Registration over the per-address cap: addr=%s", addr_hash[:12])
            return None
        took_addr = True
        pipe = r.pipeline(transaction=True)
        pipe.incr(mail_name)
        pipe.expire(mail_name, _DAY_TTL)
        took_mail = True
        if int(pipe.execute()[0]) > cap:
            logger.warning("Daily confirmation mail cap reached: registration refused")
            raise _unavailable()
        token = secrets.token_urlsafe(32)
        record = {"email": email, "expires_at": _now() + PENDING_TTL, "meta": _clean_meta(meta)}
        r.set(_token_key(token), json.dumps(record), ex=PENDING_TTL)
    except RegistrationError:
        if took_mail:
            _release(r, mail_name)
        if took_addr:
            _release(r, addr_name)
        raise
    except Exception as e:
        logger.error("Registration store failed: %s", type(e).__name__)
        if took_mail:
            _release(r, mail_name)
        if took_addr:
            _release(r, addr_name)
        raise _unavailable() from e
    logger.info("Registration pending: addr=%s", addr_hash[:12])
    return email, token


def confirm_registration(token, ip: str) -> dict:
    """Consume the token and return {"email", "key", "created", "meta"}.

    Raises RegistrationError: 503 (Redis, salt, key store), 429 (IP limit, token untouched),
    400 (unknown, used, expired or malformed token, all the same answer).
    """
    r = _ready()
    ip_id = hash_identifier(ip)[:32]
    try:
        over = _hourly_count(r, "tl:reg_confirm_ip", ip_id) > CONFIRM_MAX_PER_IP_PER_HOUR
    except Exception as e:
        logger.error("Confirm counter failed: %s", type(e).__name__)
        raise _unavailable() from e
    if over:
        raise RegistrationError("rate_limited", "Too many attempts. Try again later.", 429)
    if not isinstance(token, str) or not _TOKEN_RE.match(token):
        raise _invalid_token()
    name = _token_key(token)
    try:
        raw = r.getdel(name)
    except Exception as e:
        logger.error("Pending record read failed: %s", type(e).__name__)
        raise _unavailable() from e
    if raw is None:
        raise _invalid_token()
    try:
        record = json.loads(raw)
        email = record["email"]
        remaining = float(record["expires_at"]) - _now()
    except (ValueError, KeyError, TypeError) as e:
        logger.error("Malformed pending record dropped: %s", type(e).__name__)
        raise _invalid_token() from e
    if remaining <= 0:
        raise _invalid_token()
    try:
        key, created = get_or_create_free_key(email, f"free_signup_{email}")
    except Exception as e:
        logger.error("Key creation failed at confirm: %s", type(e).__name__)
        try:
            r.set(name, raw, ex=max(1, int(remaining)))  # give the token back: nothing was created
        except Exception as e2:
            logger.error("Pending record restore failed: %s", type(e2).__name__)
        raise _unavailable() from e
    return {"email": email, "key": key, "created": created, "meta": record.get("meta") or {}}


def log_funnel(event: str, ip: str, email: str, meta: dict, conversion: bool = False) -> None:
    """Append a funnel (or conversion) event; hashes only. Best effort."""
    # Lazy import: app.py owns the log paths (tests move them) and imports this package.
    from . import app as app_mod
    path = app_mod.CONVERSION_EVENTS_LOG if conversion else app_mod.FUNNEL_EVENTS_LOG
    record = {
        "ts": datetime.now(UTC).isoformat(),
        "event": event,
        "scan_id": meta.get("scan_id", ""),
        "source": meta.get("source", ""),
        "client_ip_hash": hashlib.sha256(ip.encode()).hexdigest()[:12],
        "email_hash": hash_identifier(email)[:32],
    }
    if conversion:
        record["plan"] = "free"
        record.update({k: meta.get(k, "") for k in ("utm_source", "utm_medium", "utm_campaign", "referrer")})
    try:
        with open(path, "a") as f:
            f.write(json.dumps(record) + "\n")
    except OSError:
        pass
