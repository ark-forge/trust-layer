"""FastAPI app — all routes for the Trust Layer."""

import asyncio
import hashlib
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

import stripe
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse, Response, HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

# Failover read-only mode — actif si FAILOVER_MODE=true dans l'env systemd
_FAILOVER_MODE = os.environ.get("FAILOVER_MODE", "").lower() == "true"

# Endpoints d'écriture bloqués en mode failover
_FAILOVER_BLOCKED_PATHS = {
    "/v1/proxy",
    "/v1/keys/setup",
    "/v1/keys/portal",
    "/v1/keys/free-signup",
    "/v1/keys/overage",
    "/v1/keys/bind-did",
    "/v1/keys/bind-did/confirm",
    "/v1/credits/buy",
    "/v1/disputes",
}


class HeadToGetMiddleware(BaseHTTPMiddleware):
    """Convert HEAD requests to GET and strip the response body.

    Starlette 0.20+ no longer generates HEAD handlers automatically for @app.get()
    routes. This middleware provides RFC 7231-compliant HEAD support globally.
    """
    async def dispatch(self, request: Request, call_next):
        if request.method == "HEAD":
            # Rewrite scope to GET so the route handler matches
            request.scope["method"] = "GET"
            response = await call_next(request)
            # Return headers only — no body
            return Response(
                status_code=response.status_code,
                headers=dict(response.headers),
            )
        return await call_next(request)


class FailoverReadOnlyMiddleware(BaseHTTPMiddleware):
    """Bloque les écritures en mode failover pour éviter le split-brain."""
    async def dispatch(self, request: Request, call_next):
        if _FAILOVER_MODE and request.method == "POST":
            path = request.url.path.rstrip("/")
            if path in _FAILOVER_BLOCKED_PATHS:
                return JSONResponse(
                    status_code=503,
                    content={
                        "error": {
                            "code": "service_degraded",
                            "message": (
                                "Proof creation is temporarily unavailable. "
                                "The primary server is undergoing maintenance. "
                                "Please retry in a few minutes."
                            ),
                            "status": 503,
                            "failover_mode": True,
                        }
                    },
                )
        return await call_next(request)

import re
from . import __version__
from collections import defaultdict
from .config import (
    STRIPE_WEBHOOK_SECRET_LIVE,
    STRIPE_WEBHOOK_SECRET_TEST,
    STRIPE_TEST_KEY,
    STRIPE_LIVE_KEY,
    PROOFS_DIR,
    TRUST_LAYER_BASE_URL,
    SUPPORTED_CURRENCIES,
    PROOF_PRICE,
    MIN_CREDIT_PURCHASE,
    MAX_CREDIT_PURCHASE,
    PRO_SETUP_MIN_AMOUNT,
    RATE_LIMIT_PER_KEY_PER_DAY, DAILY_LIMITS_PER_PLAN,
    FREE_TIER_MONTHLY_LIMIT,
    PRO_MONTHLY_LIMIT,
    ENTERPRISE_MONTHLY_LIMIT,
    PRO_OVERAGE_PRICE,
    ENTERPRISE_OVERAGE_PRICE,
    PROOF_ACCESS_LOG,
    ARKFORGE_PUBLIC_KEY,
    WEBHOOK_IDEMPOTENCY_FILE,
    CONVERSION_EVENTS_LOG,
    CORS_ALLOWED_ORIGINS,
    PRO_OVERAGE_PRICE,
    ENTERPRISE_OVERAGE_PRICE,
    OVERAGE_PRICES,
    OVERAGE_CAP_MIN,
    OVERAGE_CAP_MAX,
    OVERAGE_CAP_DEFAULT,

    STRIPE_PRO_PRICE_ID,
    STRIPE_PRO_PRICE_ID_TEST,
    STRIPE_PRO_PRODUCT_ID,
    STRIPE_ENTERPRISE_PRICE_ID,
    STRIPE_ENTERPRISE_PRICE_ID_TEST,
)
from .keys import (
    validate_api_key, create_api_key, deactivate_key_by_ref, reactivate_key_by_ref, is_test_key, is_free_key,
    get_overage_settings, update_overage_settings, get_key_plan, is_internal_key, find_key_info_by_ref,
)
from .credits import add_credits, get_balance
from .proofs import load_proof, store_proof, get_public_proof, get_full_proof, verify_proof_integrity, sha256_hex
from .attestation import (
    build_attestation, store_attestation, load_attestation,
    find_by_record_id, attestation_to_encina_response,
)
from .proxy import execute_proxy, ProxyError, drain_background_tasks, _track_task, _log_background_task
from .templates import render_proof_page
from .rate_limit import get_usage, get_daily_limit
from .redis_client import get_redis
from .email_notify import (
    send_welcome_email,
    send_welcome_email_pro,
    send_trial_ended_email,
    send_subscription_suspended_email,
    send_subscription_reactivated_email,
)
from .timestamps import submit_hash
from .reputation import get_reputation, get_public_reputation
from .disputes import create_dispute, get_agent_disputes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .did_resolver import (
    validate_did, resolve_did, extract_ed25519_pubkey_bytes,
    create_challenge, consume_challenge, check_bind_rate,
    verify_oatr_delegation, bind_did_to_key, DIDResolutionError,
)

logger = logging.getLogger("trust_layer.app")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

# --- Log sanitization: redact secrets before they reach journald ---
_LOG_REDACT = [
    re.compile(r"(Authorization:\s*)\S{10,}", re.IGNORECASE),
    re.compile(r"(Bearer\s+)\S{10,}", re.IGNORECASE),
    re.compile(r"(X-Api-Key:\s*)\S{10,}", re.IGNORECASE),
    re.compile(r"(sk[-_](?:live|test)[-_])\w{20,}"),
    re.compile(r"(ghp_)\w{30,}"),
    re.compile(r"(mcp_(?:free|pro|ent|test)_)\w{20,}"),
]


class _SensitiveDataFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for pat in _LOG_REDACT:
                record.msg = pat.sub(r"\g<1>[REDACTED]", record.msg)
        if record.args:
            try:
                safe = tuple(
                    pat.sub(r"\g<1>[REDACTED]", str(a)) if isinstance(a, str) else a
                    for a in (record.args if isinstance(record.args, tuple) else (record.args,))
                    for pat in [_LOG_REDACT[0]]  # apply first pattern as sample — full loop below
                )
                # Full redaction on all args
                redacted = []
                for a in (record.args if isinstance(record.args, tuple) else (record.args,)):
                    if isinstance(a, str):
                        for pat in _LOG_REDACT:
                            a = pat.sub(r"\g<1>[REDACTED]", a)
                    redacted.append(a)
                record.args = tuple(redacted) if isinstance(record.args, tuple) else redacted[0]
            except Exception:
                pass
        return True


_sensitive_filter = _SensitiveDataFilter()
for _log_name in ("uvicorn", "uvicorn.access", "uvicorn.error", "trust_layer", "fastapi"):
    logging.getLogger(_log_name).addFilter(_sensitive_filter)
logging.getLogger().addFilter(_sensitive_filter)

# --- Proof access tracking (Redis-backed, in-memory fallback) ---
_proof_access_counts: dict[str, list[float]] = defaultdict(list)  # fallback only
_ABUSE_THRESHOLD = 100  # max requests per hour per IP
_ABUSE_WINDOW = 3600

# --- Failed auth rate limiting (brute-force protection on API key endpoints) ---
# Redis-backed: shared across all uvicorn workers. In-memory fallback if Redis unavailable.
_failed_auth_fallback: dict[str, list[float]] = defaultdict(list)
_FAILED_AUTH_MAX = 10      # max failures in window before lockout
_FAILED_AUTH_WINDOW = 300  # sliding window seconds (5 min)


def _is_auth_locked(ip: str) -> bool:
    """Returns True if IP has exceeded failed auth threshold. Redis-first, in-memory fallback."""
    try:
        r = get_redis()
        if r is not None:
            count = r.get(f"failed_auth:{ip}")
            return int(count) >= _FAILED_AUTH_MAX if count else False
    except Exception:
        pass
    # Fallback: in-memory sliding window
    import time as _time
    cutoff = _time.time() - _FAILED_AUTH_WINDOW
    _failed_auth_fallback[ip] = [t for t in _failed_auth_fallback[ip] if t > cutoff]
    return len(_failed_auth_fallback[ip]) >= _FAILED_AUTH_MAX


def _record_failed_auth(ip: str):
    """Increment failed auth counter for IP. Redis-first, in-memory fallback."""
    try:
        r = get_redis()
        if r is not None:
            key = f"failed_auth:{ip}"
            count = r.incr(key)
            if count == 1:
                r.expire(key, _FAILED_AUTH_WINDOW)
            logger.warning("Failed auth from IP %s (count=%d, via Redis)", ip, count)
            return
    except Exception:
        pass
    # Fallback
    import time as _time
    _failed_auth_fallback[ip].append(_time.time())
    logger.warning("Failed auth from IP %s (count=%d, in-memory)", ip, len(_failed_auth_fallback[ip]))


def _restore_abuse_counters():
    """Restore in-memory abuse counters from JSONL (fallback path only — Redis skips this)."""
    import time
    r = get_redis()
    if r is not None:
        return  # Redis persists across restarts — no need to restore
    now = time.time()
    cutoff = now - _ABUSE_WINDOW
    restored = 0
    try:
        with open(PROOF_ACCESS_LOG, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts_str = entry.get("ts", "")
                ip = entry.get("ip", "")
                if not ts_str or not ip:
                    continue
                try:
                    entry_ts = datetime.fromisoformat(ts_str).timestamp()
                except (ValueError, OSError):
                    continue
                if entry_ts > cutoff:
                    _proof_access_counts[ip].append(entry_ts)
                    restored += 1
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.warning("Failed to restore abuse counters: %s", e)
    if restored:
        logger.info("Restored %d abuse counter entries for %d IPs from JSONL", restored, len(_proof_access_counts))


def _log_proof_access(proof_id: str, ip: str, user_agent: str):
    """Log proof access to JSONL and check for abuse."""
    import time
    now = time.time()
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "proof_id": proof_id,
        "ip": ip,
        "ua": (user_agent or "")[:200],
    }
    try:
        with open(PROOF_ACCESS_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        logger.debug("Proof access log write failed: %s", e)

    # Abuse detection: Redis-first, in-memory fallback
    try:
        r = get_redis()
        if r is not None:
            key = f"proof_abuse:{ip}"
            count = r.incr(key)
            if count == 1:
                r.expire(key, _ABUSE_WINDOW)
            if count > _ABUSE_THRESHOLD:
                logger.warning("ABUSE DETECTED: IP %s made %d proof requests in 1h (Redis)", ip, count)
        else:
            raise RuntimeError("Redis unavailable")
    except Exception:
        timestamps = _proof_access_counts[ip]
        timestamps.append(now)
        cutoff = now - _ABUSE_WINDOW
        _proof_access_counts[ip] = [t for t in timestamps if t > cutoff]
        if len(_proof_access_counts[ip]) > _ABUSE_THRESHOLD:
            logger.warning("ABUSE DETECTED: IP %s made %d proof requests in 1h (in-memory)", ip, len(_proof_access_counts[ip]))


async def _recover_pending_tsa():
    """Startup task: retry TSA for recent proofs stuck in 'submitted' status."""
    import base64 as _b64
    from .proofs import load_proof, store_proof as _store_proof
    recovered = 0
    failed = 0
    try:
        cutoff = datetime.now(timezone.utc).timestamp() - 86400  # last 24h
        for proof_file in PROOFS_DIR.glob("prf_*.json"):
            if proof_file.stat().st_mtime < cutoff:
                continue
            proof = load_proof(proof_file.stem)
            if not proof:
                continue
            tsa = proof.get("timestamp_authority", {})
            if tsa.get("status") != "submitted":
                continue
            # This proof never got its TSA — retry
            chain_hash = proof.get("hashes", {}).get("chain", "").replace("sha256:", "")
            if not chain_hash:
                continue
            proof_id = proof.get("proof_id", proof_file.stem)
            logger.info("TSA recovery: retrying %s", proof_id)
            loop = asyncio.get_running_loop()
            tsr_bytes = await loop.run_in_executor(None, submit_hash, chain_hash)
            if tsr_bytes:
                (PROOFS_DIR / f"{proof_id}.tsr").write_bytes(tsr_bytes)
                proof["timestamp_authority"]["status"] = "verified"
                proof["timestamp_authority"]["tsr_base64"] = _b64.b64encode(tsr_bytes).decode("ascii")
                _store_proof(proof_id, proof)
                _log_background_task(proof_id, "tsa_recovery", "success")
                recovered += 1
            else:
                _log_background_task(proof_id, "tsa_recovery", "failure", "submit_hash returned None")
                failed += 1
    except Exception as e:
        logger.warning("TSA recovery error: %s", e)
    if recovered or failed:
        logger.info("TSA recovery complete: %d recovered, %d still failed", recovered, failed)


@asynccontextmanager
async def lifespan(app):
    """Startup: recover pending TSA, restore abuse counters. Shutdown: drain background tasks."""
    # Startup — prune stale webhook idempotency entries (>7 days old)
    _prune_webhook_idempotency()
    # Startup — restore abuse detection sliding window from JSONL
    _restore_abuse_counters()
    # Startup — fire TSA recovery in background (non-blocking)
    recovery_task = asyncio.create_task(_recover_pending_tsa())
    _track_task(recovery_task)
    yield
    # Shutdown — wait for active tasks to finish (10s grace)
    drained = await drain_background_tasks(timeout=10.0)
    logger.info("Shutdown: %d background tasks drained", drained)


app = FastAPI(
    title="ArkForge Trust Layer",
    description="Certifying proxy for agent-to-agent payments. Pay any API, get cryptographic proof.",
    version=__version__,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(HeadToGetMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "X-Api-Key", "X-Idempotency-Key", "X-Agent-Identity", "X-Agent-Version", "Content-Type"],
    allow_credentials=False,
)

if _FAILOVER_MODE:
    app.add_middleware(FailoverReadOnlyMiddleware)
    logger.warning("FAILOVER_MODE=true — service en lecture seule (POST /v1/proxy bloqué)")


# --- Helpers ---

def _get_api_key(authorization: Optional[str] = None, x_api_key: Optional[str] = None) -> Optional[str]:
    if x_api_key:
        return x_api_key
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:]
    return None


def _error_response(code: str, message: str, status: int, proof: dict = None) -> JSONResponse:
    body = {"error": {"code": code, "message": message, "status": status}}
    if proof:
        body["proof"] = proof
    return JSONResponse(status_code=status, content=body)


# --- POST /v1/proxy ---

@app.post("/v1/proxy")
async def proxy_endpoint(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
    x_idempotency_key: Optional[str] = Header(None),
    x_agent_identity: Optional[str] = Header(None),
    x_agent_version: Optional[str] = Header(None),
):
    """The core endpoint — charge, forward, prove."""
    client_ip = request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown")

    if _is_auth_locked(client_ip):
        return _error_response("rate_limited", "Too many failed authentication attempts. Try again in 5 minutes.", 429)

    api_key = _get_api_key(authorization, x_api_key)
    if not api_key:
        _record_failed_auth(client_ip)
        return _error_response("invalid_api_key", "API key required. Use Authorization: Bearer <key>", 401)

    key_info = validate_api_key(api_key)
    if not key_info:
        _record_failed_auth(client_ip)
        return _error_response("invalid_api_key", "Invalid or inactive API key", 401)

    try:
        body = await request.json()
    except Exception:
        return _error_response("invalid_request", "Invalid JSON body", 400)

    target = body.get("target", "")
    amount = body.get("amount")
    currency = body.get("currency", "eur")
    payload = body.get("payload", {})
    method = body.get("method", "POST")
    description = body.get("description", "")
    provider_payment = body.get("provider_payment")
    extra_headers = body.get("extra_headers")  # Optional: headers forwarded to target API

    if not target:
        return _error_response("invalid_target", "Missing 'target' field", 400)
    if not isinstance(payload, dict):
        return _error_response("invalid_request", "'payload' must be a JSON object", 400)
    if not isinstance(method, str) or method.upper() not in ("GET", "POST"):
        return _error_response("invalid_request", "'method' must be 'GET' or 'POST'", 400)
    if not isinstance(currency, str):
        return _error_response("invalid_request", "'currency' must be a string", 400)
    if extra_headers is not None and not isinstance(extra_headers, dict):
        return _error_response("invalid_request", "'extra_headers' must be a JSON object or null", 400)

    # Amount is recalculated inside execute_proxy based on plan + overage status.
    # Pass 0.0 here — execute_proxy determines the real debit amount.
    amount = 0.0

    try:
        result = await execute_proxy(
            target=target,
            method=method,
            payload=payload,
            amount=amount,
            currency=currency,
            api_key=api_key,
            description=description,
            idempotency_key=x_idempotency_key,
            agent_identity=x_agent_identity,
            agent_version=x_agent_version,
            provider_payment=provider_payment,
            extra_headers=extra_headers,
        )
    except ProxyError as e:
        return JSONResponse(status_code=e.status, content=e.to_dict())

    # Determine status code from result
    if "error" in result:
        status_code = result["error"].get("status", 502)
    else:
        status_code = 200

    # Level 2 — Ghost Stamp: inject proof headers
    proof = result.get("proof") or result.get("error", {}).get("proof_data")
    headers = {}
    if proof:
        verification_url = proof.get("verification_url", "")
        proof_id = proof.get("proof_id", "")
        service_ok = "error" not in result and proof.get("transaction_success", True)
        if verification_url:
            headers["X-ArkForge-Proof"] = verification_url
        headers["X-ArkForge-Verified"] = "true" if service_ok else "false"
        if proof_id:
            headers["X-ArkForge-Proof-ID"] = proof_id
            headers["X-ArkForge-Trust-Link"] = f"{TRUST_LAYER_BASE_URL}/v/{proof_id}"
        buyer_score = proof.get("buyer_reputation_score")
        if buyer_score is not None:
            headers["X-ArkForge-Buyer-Score"] = str(buyer_score)

    return JSONResponse(status_code=status_code, content=result, headers=headers)


# --- GET /v1/proof/{proof_id}/full ---

@app.get("/v1/proof/{proof_id}/full")
async def get_proof_full(
    proof_id: str,
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """Authenticated full proof — owner only. Returns all fields including payment details."""
    api_key = _get_api_key(authorization, x_api_key)
    if not api_key:
        return _error_response("auth_required", "API key required", 401)
    key_info = validate_api_key(api_key)
    if not key_info:
        return _error_response("invalid_key", "Invalid API key", 403)

    if not _PROOF_ID_RE.match(proof_id):
        return _error_response("invalid_request", "Invalid proof ID format", 400)
    proof = load_proof(proof_id)
    if not proof:
        return _error_response("not_found", f"Proof '{proof_id}' not found", 404)

    # Ownership check: sha256(api_key) must match buyer_fingerprint
    caller_fp = sha256_hex(api_key)
    proof_fp = proof.get("parties", {}).get("buyer_fingerprint", "")
    if caller_fp != proof_fp:
        return _error_response("forbidden", "You are not the owner of this proof", 403)

    full = get_full_proof(proof)
    full["integrity_verified"] = verify_proof_integrity(proof)
    return full


# --- GET /v1/proof/{proof_id} ---

@app.get("/v1/proof/{proof_id}")
async def get_proof(proof_id: str, request: Request):
    """Public proof verification — no auth required. Lazy-upgrades OTS on access.

    Content negotiation (Level 3 — Visual Stamp):
    - Accept: text/html (without application/json) → HTML proof page
    - Otherwise → JSON (backward compat)
    """
    if not _PROOF_ID_RE.match(proof_id):
        return _error_response("invalid_request", "Invalid proof ID format", 400)

    # Abuse check — block before serving if IP exceeded threshold
    client_ip = request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown")
    try:
        r = get_redis()
        if r is not None:
            count = r.get(f"proof_abuse:{client_ip}")
            if count and int(count) > _ABUSE_THRESHOLD:
                logger.warning("ABUSE BLOCKED: IP %s blocked on proof access (%s req/h)", client_ip, count)
                return _error_response("rate_limited", "Too many proof requests. Try again later.", 429)
    except Exception:
        pass

    user_agent = request.headers.get("user-agent", "")
    _log_proof_access(proof_id, client_ip, user_agent)

    proof = load_proof(proof_id)
    if not proof:
        return _error_response("not_found", f"Proof '{proof_id}' not found", 404)

    # Increment views_count in proof metadata
    proof["views_count"] = proof.get("views_count", 0) + 1
    try:
        store_proof(proof_id, proof)
    except OSError as e:
        logger.debug("Proof view tracking failed: %s", e)

    public = get_public_proof(proof)
    integrity_verified = verify_proof_integrity(proof)
    public["integrity_verified"] = integrity_verified

    # Level 3 — Visual Stamp: content negotiation
    # ?format=json forces JSON (for "Verify via API" button in HTML page)
    fmt = request.query_params.get("format", "")
    accept = request.headers.get("accept", "")
    if fmt != "json" and "text/html" in accept and "application/json" not in accept:
        html_content = render_proof_page(public, integrity_verified)
        return HTMLResponse(content=html_content)

    return public


# --- GET /v1/proof/{proof_id}/verify — Lightweight verification ---

@app.get("/v1/proof/{proof_id}/verify")
async def verify_proof_endpoint(proof_id: str):
    """Lightweight proof verification — no auth, no view increment.

    Returns integrity check result with chain hash and timestamp info.
    Useful for automated verification pipelines.
    """
    if not _PROOF_ID_RE.match(proof_id):
        return _error_response("invalid_request", "Invalid proof ID format", 400)

    proof = load_proof(proof_id)
    if not proof:
        return _error_response("not_found", f"Proof '{proof_id}' not found", 404)

    integrity_ok = verify_proof_integrity(proof)
    hashes = proof.get("hashes", {})
    tsa = proof.get("timestamp_authority", {})
    rekor = proof.get("transparency_log", {})
    sig = proof.get("arkforge_signature")

    return {
        "proof_id": proof_id,
        "integrity_verified": integrity_ok,
        "chain_hash": hashes.get("chain"),
        "timestamp": proof.get("timestamp"),
        "spec_version": proof.get("spec_version"),
        "timestamp_authority": {
            "status": tsa.get("status", "none"),
            "provider": tsa.get("provider"),
        },
        "transparency_log": {
            "status": rekor.get("status", "none") if rekor else "none",
        },
        "signature_present": sig is not None,
        "verification_url": f"{TRUST_LAYER_BASE_URL}/v1/proof/{proof_id}",
    }


# --- GET /v/{proof_id} — Short URL redirect ---

@app.get("/v/{proof_id}")
async def short_proof_url(proof_id: str):
    """Short URL redirect to full proof endpoint. 302 with cache."""
    if not _PROOF_ID_RE.match(proof_id):
        return _error_response("invalid_request", "Invalid proof ID format", 400)
    proof = load_proof(proof_id)
    if not proof:
        return _error_response("not_found", f"Proof '{proof_id}' not found", 404)
    return RedirectResponse(
        url=f"{TRUST_LAYER_BASE_URL}/v1/proof/{proof_id}",
        status_code=302,
        headers={"Cache-Control": "public, max-age=86400"},
    )


# --- GET /v1/proof/{proof_id}/tsr ---

@app.api_route("/v1/proof/{proof_id}/tsr", methods=["GET", "HEAD"])
async def get_proof_tsr(proof_id: str, request: Request):
    """Return raw .tsr file (RFC 3161 timestamp response) for independent verification."""
    tsr_path = PROOFS_DIR / f"{proof_id}.tsr"
    if not tsr_path.exists():
        return _error_response("not_found", f"TSR file for '{proof_id}' not found", 404)

    return Response(
        content=tsr_path.read_bytes(),
        media_type="application/timestamp-reply",
        headers={"Content-Disposition": f"attachment; filename={proof_id}.tsr"},
    )


# --- POST /v1/keys/setup ---

@app.post("/v1/keys/setup")
async def setup_key(request: Request):
    """Create a Stripe Checkout Session (subscription mode) for the Pro plan at 29 EUR/month.

    On success, Stripe fires checkout.session.completed with a subscription_id.
    The webhook creates the API key and sends the welcome email.
    """
    try:
        body = await request.json()
    except Exception:
        return _error_response("invalid_request", "Invalid JSON body", 400)

    email = (body.get("email") or "").strip().lower()
    if not email or not _EMAIL_RE.match(email):
        return _error_response("invalid_request", "A valid email is required", 400)
    local_part = email.split("@")[0]
    if len(email) > 320 or len(local_part) > 64:
        return _error_response("invalid_request", "Email address exceeds maximum allowed length", 400)

    req_mode = body.get("mode", "live")
    lang = body.get("lang", "fr")
    if lang not in ("en", "fr"):
        lang = "fr"
    sk = STRIPE_TEST_KEY if req_mode == "test" else STRIPE_LIVE_KEY
    if not sk:
        return _error_response("internal_error", f"Stripe {req_mode} key not configured", 500)

    plan = (body.get("plan") or "pro").lower()
    if plan not in ("pro", "enterprise"):
        plan = "pro"

    if plan == "enterprise":
        price_id = STRIPE_ENTERPRISE_PRICE_ID_TEST if req_mode == "test" else STRIPE_ENTERPRISE_PRICE_ID
        plan_name = "enterprise"
        price_monthly = 149.0
        proofs_per_month = 50000
    else:
        price_id = STRIPE_PRO_PRICE_ID_TEST if req_mode == "test" else STRIPE_PRO_PRICE_ID
        plan_name = "pro"
        price_monthly = 29.0
        proofs_per_month = 5000

    if not price_id:
        return _error_response("internal_error", f"Stripe {plan_name} price ID not configured", 500)

    try:
        customers = stripe.Customer.list(email=email, limit=1, api_key=sk)
        if customers.data:
            customer = customers.data[0]
        else:
            customer = stripe.Customer.create(
                email=email,
                metadata={"source": "trust-layer-pro"},
                api_key=sk,
            )

        session = stripe.checkout.Session.create(
            mode="subscription",
            payment_method_types=["card"],
            customer=customer.id,
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=f"https://arkforge.tech/{lang}/tl-pro-success.html?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"https://arkforge.tech/{lang}/pricing.html?intent={plan_name}",
            metadata={
                "product": f"trust_layer_{plan_name}_subscription",
                "email": email,
                "stripe_mode": req_mode,
                "lang": lang,
                "plan": plan_name,
            },
            subscription_data={
                "trial_period_days": 14,
                "metadata": {
                    "product": f"trust_layer_{plan_name}_subscription",
                    "email": email,
                    "plan": plan_name,
                }
            },
            api_key=sk,
        )

        return {
            "checkout_url": session.url,
            "session_id": session.id,
            "customer_id": customer.id,
            "mode": req_mode,
            "plan": plan_name,
            "price_monthly_eur": price_monthly,
            "proofs_per_month": proofs_per_month,
        }

    except stripe.StripeError as e:
        logger.error("Stripe setup error: %s", e)
        return _error_response("internal_error", f"Stripe error: {str(e)}", 500)


# --- POST /v1/keys/portal ---

@app.post("/v1/keys/portal")
async def billing_portal(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """Create a Stripe Billing Portal session for card/billing management.

    Accepts either:
    - Body field `customer_id` (explicit)
    - API key via Authorization or X-Api-Key header (Trust Layer resolves customer_id automatically)

    Returns a portal_url the client should redirect to. The portal lets users
    update their payment method, view invoices, and manage billing details.
    Requires the Stripe Customer Portal to be configured in the Stripe dashboard.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    req_mode = body.get("mode", "live")
    lang = body.get("lang", "fr")
    if lang not in ("en", "fr"):
        lang = "fr"

    # Resolve customer_id: explicit body field OR from API key
    customer_id = body.get("customer_id", "")
    if not customer_id:
        api_key = _get_api_key(authorization, x_api_key)
        if api_key:
            key_info = validate_api_key(api_key)
            if key_info:
                customer_id = key_info.get("stripe_customer_id", "")
                # Infer mode from key prefix
                if not body.get("mode"):
                    req_mode = "test" if is_test_key(api_key) else "live"

    if not customer_id:
        return _error_response(
            "invalid_request",
            "Provide customer_id in body or authenticate with your API key",
            400,
        )

    sk = STRIPE_TEST_KEY if req_mode == "test" else STRIPE_LIVE_KEY
    if not sk:
        return _error_response("internal_error", f"Stripe {req_mode} key not configured", 500)

    try:
        portal_session = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=f"https://arkforge.tech/{lang}/pricing.html",
            api_key=sk,
        )
        return {
            "portal_url": portal_session.url,
            "customer_id": customer_id,
        }
    except stripe.StripeError as e:
        logger.error("Stripe portal error: %s", e)
        return _error_response("internal_error", f"Stripe error: {str(e)}", 500)


# --- POST /v1/keys/free-signup ---

import re as _re

# RFC 5321-compatible email regex: local@domain.tld
# - local part: alphanum + ._%+- (no consecutive dots, no leading/trailing dot)
# - domain: alphanum + .- labels
# - TLD: at least 2 alpha chars
_EMAIL_RE = _re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9._%+\-]*[a-zA-Z0-9])?@[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$"
)

# Valid proof ID format: prf_YYYYMMDD_HHMMSS_<6hex>
_PROOF_ID_RE = _re.compile(r"^prf_\d{8}_\d{6}_[0-9a-f]{6}$")

_FREE_SIGNUP_RATE: dict[str, list[float]] = {}  # IP -> timestamps (sliding 1h)
_FREE_SIGNUP_MAX_PER_HOUR = 5


def _classify_referrer_source(referrer: str) -> str:
    """Classify a raw Referer URL into an acquisition source for attribution."""
    if not referrer or referrer == "-":
        return "direct"
    r = referrer.lower()
    if "google." in r:
        return "google_organic"
    if "t.co/" in r or "twitter.com" in r or "x.com" in r:
        return "x_twitter"
    if "dev.to" in r:
        return "devto"
    if "news.ycombinator.com" in r:
        return "hn"
    if "github.com" in r:
        return "github"
    if "linkedin.com" in r:
        return "linkedin"
    if "smithery" in r or "glama.ai" in r:
        return "mcp_directory"
    if "arkforge" in r:
        return "direct"
    return "other"

@app.post("/v1/keys/free-signup")
async def free_signup(request: Request):
    """Create a free-tier API key with email only — no credit card required."""
    import time

    try:
        body = await request.json()
    except Exception:
        return _error_response("invalid_request", "Invalid JSON body", 400)

    email = (body.get("email") or "").strip().lower()
    if not email or not _EMAIL_RE.match(email):
        return _error_response("invalid_request", "A valid email is required", 400)
    # RFC 5321: total ≤ 320 chars, local part ≤ 64 chars
    local_part = email.split("@")[0]
    if len(email) > 320 or len(local_part) > 64:
        return _error_response("invalid_request", "Email address exceeds maximum allowed length", 400)

    # Rate limit: max 5 signups per IP per hour.
    # X-Real-IP is set by nginx from $remote_addr and cannot be forged by clients.
    # Fall back to direct connection IP if the header is absent.
    client_ip = (
        request.headers.get("x-real-ip")
        or (request.client.host if request.client else "unknown")
    )
    now = time.time()
    timestamps = _FREE_SIGNUP_RATE.get(client_ip, [])
    timestamps = [t for t in timestamps if t > now - 3600]
    if len(timestamps) >= _FREE_SIGNUP_MAX_PER_HOUR:
        return _error_response("rate_limited", "Too many signups. Try again later.", 429)
    timestamps.append(now)
    _FREE_SIGNUP_RATE[client_ip] = timestamps

    # Check if email already has a free key
    from .keys import load_api_keys
    existing_keys = load_api_keys()
    for key, info in existing_keys.items():
        if info.get("email", "").lower() == email and info.get("plan") == "free" and info.get("active"):
            return _error_response("already_exists", "A free API key already exists for this email. Check your inbox or contact support.", 409)

    # Create free-tier key (no Stripe customer needed)
    api_key = create_api_key(
        stripe_customer_id="",
        ref_id=f"free_signup_{email}",
        email=email,
        test_mode=False,
        plan="free",
    )
    logger.info("Free API key created for %s", email)

    try:
        send_welcome_email(email, api_key)
    except (OSError, RuntimeError) as e:
        logger.warning("Welcome email failed for free signup %s: %s", email, e)

    # Attribution event: capture referrer + UTM for funnel tracking
    try:
        referrer = request.headers.get("referer", "")
        utm_source = body.get("utm_source", "")
        utm_medium = body.get("utm_medium", "")
        utm_campaign = body.get("utm_campaign", "")
        with open(CONVERSION_EVENTS_LOG, "a") as _cel:
            _cel.write(json.dumps({
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": "signup_attributed",
                "plan": "free",
                "email_hash": email[:3] + "***" if email else "",
                "source": utm_source or _classify_referrer_source(referrer),
                "utm_source": utm_source,
                "utm_medium": utm_medium,
                "utm_campaign": utm_campaign,
                "referrer": referrer,
                "client_ip_hash": hashlib.sha256(client_ip.encode()).hexdigest()[:12],
            }) + "\n")
    except OSError:
        pass

    return {
        "api_key": api_key,
        "plan": "free",
        "limit": f"{FREE_TIER_MONTHLY_LIMIT} proofs/month",
        "email": email,
        "message": "Your free API key is ready. It has also been sent to your email.",
    }


# --- POST /v1/keys/bind-did ---

@app.post("/v1/keys/bind-did")
async def bind_did_initiate(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """Initiate DID binding for the API key.

    Path A (challenge-response): returns a challenge to sign.
    Path B (OATR delegation): if oatr_issuer_id provided, verifies via registry and binds immediately.
    """
    api_key = _get_api_key(authorization, x_api_key)
    if not api_key:
        return _error_response("invalid_api_key", "API key required", 401)

    key_info = validate_api_key(api_key)
    if not key_info:
        return _error_response("invalid_api_key", "Invalid or inactive API key", 401)

    if not check_bind_rate(api_key):
        return _error_response("rate_limited", "Too many DID bind attempts. Try again later.", 429)

    try:
        body = await request.json()
    except Exception:
        body = {}

    did = body.get("did", "")
    if not did or not validate_did(did):
        return _error_response("invalid_did", "A valid did:web or did:key is required", 400)

    oatr_issuer_id = body.get("oatr_issuer_id")

    # Resolve DID (sync function — run in executor to avoid blocking event loop)
    loop = asyncio.get_running_loop()
    try:
        did_doc = await loop.run_in_executor(None, resolve_did, did)
        pub_bytes = await loop.run_in_executor(None, extract_ed25519_pubkey_bytes, did_doc)
    except DIDResolutionError as e:
        status = e.status if e.status in (400, 404) else 503
        return _error_response("did_resolution_failed", e.message, status)

    # Path B: OATR delegation — verify and bind immediately
    if oatr_issuer_id:
        try:
            valid = await loop.run_in_executor(
                None, verify_oatr_delegation, did, oatr_issuer_id, pub_bytes
            )
        except Exception:
            valid = False

        if not valid:
            return _error_response(
                "oatr_delegation_failed",
                "OATR issuer not found, inactive, or key does not match DID",
                400,
            )

        try:
            bound_at = await loop.run_in_executor(None, bind_did_to_key, api_key, did)
        except DIDResolutionError as e:
            return _error_response("bind_failed", e.message, e.status)

        return JSONResponse({"verified_did": did, "bound_at": bound_at, "method": "oatr_delegation"})

    # Path A: challenge-response
    challenge = create_challenge(api_key, did, pub_bytes)
    return JSONResponse({"challenge": challenge, "expires_in": 300})


# --- POST /v1/keys/bind-did/confirm ---

@app.post("/v1/keys/bind-did/confirm")
async def bind_did_confirm(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """Confirm DID binding by submitting a signature over the challenge."""
    api_key = _get_api_key(authorization, x_api_key)
    if not api_key:
        return _error_response("invalid_api_key", "API key required", 401)

    key_info = validate_api_key(api_key)
    if not key_info:
        return _error_response("invalid_api_key", "Invalid or inactive API key", 401)

    try:
        body = await request.json()
    except Exception:
        body = {}

    challenge = body.get("challenge", "")
    signature_b64 = body.get("signature", "")

    if not challenge or not signature_b64:
        return _error_response("missing_fields", "Both 'challenge' and 'signature' are required", 400)

    payload = consume_challenge(challenge)
    if payload is None:
        return _error_response("challenge_expired", "Challenge not found or expired", 410)

    if payload["api_key"] != api_key:
        return _error_response("key_mismatch", "Challenge was issued for a different API key", 400)

    try:
        import base64
        padding = 4 - len(signature_b64) % 4
        if padding != 4:
            signature_b64 += "=" * padding
        sig_bytes = base64.urlsafe_b64decode(signature_b64)
        pub_bytes = bytes.fromhex(payload["pub_bytes_hex"])
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        public_key.verify(sig_bytes, challenge.encode())
    except Exception:
        return _error_response("invalid_signature", "Signature verification failed", 400)

    loop = asyncio.get_running_loop()
    try:
        bound_at = await loop.run_in_executor(None, bind_did_to_key, api_key, payload["did"])
    except DIDResolutionError as e:
        return _error_response("bind_failed", e.message, e.status)

    return JSONResponse({"verified_did": payload["did"], "bound_at": bound_at, "method": "challenge_response"})


# --- POST /v1/credits/buy ---

@app.post("/v1/credits/buy")
async def buy_credits(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """Buy prepaid credits by charging the saved card off-session."""
    api_key = _get_api_key(authorization, x_api_key)
    if not api_key:
        return _error_response("invalid_api_key", "API key required", 401)

    key_info = validate_api_key(api_key)
    if not key_info:
        return _error_response("invalid_api_key", "Invalid or inactive API key", 401)

    if is_free_key(api_key):
        return _error_response("invalid_plan", "Free tier keys cannot buy credits. Upgrade to Pro.", 403)

    if is_internal_key(api_key):
        return _error_response("invalid_plan", "Internal keys do not use prepaid credits.", 403)

    try:
        body = await request.json()
    except Exception:
        body = {}

    amount = body.get("amount", 10.00)
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        return _error_response("invalid_amount", f"Amount must be a number, got '{amount}'", 400)

    if amount < MIN_CREDIT_PURCHASE:
        return _error_response("invalid_amount", f"Minimum credit purchase is {MIN_CREDIT_PURCHASE} EUR", 400)
    if amount > MAX_CREDIT_PURCHASE:
        return _error_response("invalid_amount", f"Maximum credit purchase is {MAX_CREDIT_PURCHASE} EUR", 400)

    customer_id = key_info.get("stripe_customer_id", "")
    if not customer_id:
        return _error_response("no_payment_method", "No payment method linked. Use /v1/keys/setup first.", 400)

    # Charge off-session via Stripe
    from .payments import get_provider
    provider = get_provider(api_key)
    try:
        charge_result = await provider.charge(
            amount=amount,
            currency="eur",
            customer_id=customer_id,
            description=f"ArkForge Trust Layer — {amount:.2f} EUR credits",
            metadata={
                "product": "trust_layer_credits",
                "api_key_prefix": api_key[:12],
            },
        )
    except stripe.InvalidRequestError as e:
        logger.error("Credit purchase invalid request: %s", e)
        return _error_response("no_payment_method", "Payment method not found. Use /v1/keys/setup to register a card.", 400)
    except (stripe.StripeError, OSError, RuntimeError) as e:
        logger.error("Credit purchase payment failed: %s", e)
        return _error_response("payment_failed", f"Payment failed: {str(e)}", 402)

    if charge_result.status != "succeeded":
        return _error_response("payment_failed", f"Payment status: {charge_result.status}", 402)

    # Add credits
    new_balance = add_credits(api_key, amount, charge_result.transaction_id)
    plan = get_key_plan(api_key)
    overage_price = OVERAGE_PRICES.get(plan, PROOF_PRICE)
    proofs_available = int(new_balance / overage_price)

    logger.info("Credits purchased: %.2f EUR (pi=%s)", amount, charge_result.transaction_id)

    return {
        "credits_added": amount,
        "balance": new_balance,
        "proofs_available": proofs_available,
        "receipt_url": charge_result.receipt_url,
        "transaction_id": charge_result.transaction_id,
    }


# --- Webhook idempotency helpers ---

def _prune_webhook_idempotency(max_age_days: int = 7) -> int:
    """Remove entries older than max_age_days from the webhook idempotency log.

    Prevents unbounded growth of WEBHOOK_IDEMPOTENCY_FILE. Called at startup.
    Returns number of entries pruned.
    """
    if not WEBHOOK_IDEMPOTENCY_FILE.exists():
        return 0
    cutoff = datetime.now(timezone.utc)
    kept = []
    removed = 0
    try:
        with open(WEBHOOK_IDEMPOTENCY_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                try:
                    ts = datetime.fromisoformat(entry["processed_at"])
                    age_days = (cutoff - ts).total_seconds() / 86400
                    if age_days < max_age_days:
                        kept.append(line)
                    else:
                        removed += 1
                except (KeyError, ValueError):
                    kept.append(line)  # keep entries with invalid timestamps
    except FileNotFoundError:
        return 0
    except OSError as e:
        logger.warning("Webhook idempotency prune read failed: %s", e)
        return 0
    if removed:
        try:
            with open(WEBHOOK_IDEMPOTENCY_FILE, "w") as f:
                for line in kept:
                    f.write(line + "\n")
            logger.info("Webhook idempotency: pruned %d stale entries (>%d days)", removed, max_age_days)
        except OSError as e:
            logger.warning("Webhook idempotency prune write failed: %s", e)
    return removed


def _is_webhook_processed(event_id: str) -> bool:
    """Return True if this Stripe event_id was already processed (7-day TTL).

    Prevents replay attacks: Stripe may re-deliver the same event on retries,
    which could trigger duplicate credit grants or key creations.
    """
    if not event_id:
        return False
    try:
        with open(WEBHOOK_IDEMPOTENCY_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("event_id") != event_id:
                    continue
                try:
                    ts = datetime.fromisoformat(entry["processed_at"])
                    age_days = (datetime.now(timezone.utc) - ts).total_seconds() / 86400
                    if age_days < 7:
                        return True
                except (KeyError, ValueError):
                    continue
    except FileNotFoundError:
        pass
    return False


def _mark_webhook_processed(event_id: str, *, event_type: str = "", session_id: str = "") -> None:
    """Append event_id to the idempotency log so duplicate deliveries are skipped.

    Extra fields (event_type, session_id) enable the CEO Gardien to correlate
    webhook deliveries with Stripe checkout sessions via the rsynced local copy,
    avoiding unnecessary Stripe Events API calls.
    """
    if not event_id:
        return
    entry: dict = {"event_id": event_id, "processed_at": datetime.now(timezone.utc).isoformat()}
    if event_type:
        entry["event_type"] = event_type
    if session_id:
        entry["session_id"] = session_id
    try:
        with open(WEBHOOK_IDEMPOTENCY_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        logger.warning("Webhook idempotency log write failed: %s", e)


# --- POST /v1/webhooks/stripe ---

@app.post("/v1/webhooks/stripe")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events — dual secrets (live + test)."""
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    event = None
    secrets_to_try = [s for s in [STRIPE_WEBHOOK_SECRET_LIVE, STRIPE_WEBHOOK_SECRET_TEST] if s]
    for ws in secrets_to_try:
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, ws)
            break
        except (ValueError, stripe.SignatureVerificationError):
            continue

    if event is None:
        if secrets_to_try:
            logger.error("Webhook signature verification failed")
            raise HTTPException(400, "Invalid signature")
        # No secrets configured — reject all unauthenticated webhook calls.
        # Accepting unsigned events would allow anyone to trigger credit grants.
        raise HTTPException(503, "Webhook secrets not configured — request rejected")

    # Idempotency guard — skip duplicate events (Stripe retries on delivery failure)
    event_id = event.id or ""
    if _is_webhook_processed(event_id):
        logger.info("Duplicate webhook event %s — skipped", event_id)
        return {"received": True}

    event_type = event.type or ""
    data = event.data.object.to_dict()  # stripe 15: StripeObject no longer inherits dict
    is_test = not event.livemode

    logger.info("Stripe webhook: %s (test=%s)", event_type, is_test)

    if event_type == "checkout.session.completed":
        customer_id = data.get("customer", "")
        customer_email = (
            data.get("customer_email", "")
            or data.get("customer_details", {}).get("email", "")
            or data.get("metadata", {}).get("email", "")
        )
        payment_intent_id = data.get("payment_intent", "")
        subscription_id = data.get("subscription", "")
        metadata = data.get("metadata", {})
        ref_id = subscription_id or payment_intent_id or customer_id
        product = metadata.get("product", "")

        if customer_id or customer_email:
            if product == "trust_layer_pro_subscription":
                api_key = create_api_key(customer_id, ref_id, customer_email, test_mode=is_test, plan="pro")
                logger.info("Pro subscription activated for %s (sub=%s)", customer_email, subscription_id)
            elif product == "trust_layer_enterprise_subscription":
                api_key = create_api_key(customer_id, ref_id, customer_email, test_mode=is_test, plan="enterprise")
                logger.info("Enterprise subscription activated for %s (sub=%s)", customer_email, subscription_id)
            else:
                # Fallback : free tier ou checkout inconnu
                api_key = create_api_key(customer_id, ref_id, customer_email, test_mode=is_test)
                logger.info("API key created for %s (ref=%s, product=%s)", customer_email, ref_id, product)

            try:
                if product in ("trust_layer_pro_subscription", "trust_layer_enterprise_subscription"):
                    plan_label = metadata.get("plan", "pro")
                    send_welcome_email_pro(customer_email, api_key, plan_name=plan_label)
                else:
                    send_welcome_email(customer_email, api_key)
            except (OSError, RuntimeError) as e:
                logger.error("Welcome email failed: %s", e)

            # Server-side conversion event (authoritative — Stripe-verified, not fakeable)
            try:
                with open(CONVERSION_EVENTS_LOG, "a") as _cel:
                    _cel.write(json.dumps({
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "event": "checkout_completed",
                        "product": product or "free",
                        "email_hash": customer_email[:3] + "***" if customer_email else "",
                        "subscription_id": subscription_id,
                        "test_mode": is_test,
                    }) + "\n")
                    # Also emit signup_attributed for paid conversions
                    _cel.write(json.dumps({
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "event": "signup_attributed",
                        "plan": product.replace("trust_layer_", "").replace("_subscription", "") if product else "pro",
                        "email_hash": customer_email[:3] + "***" if customer_email else "",
                        "source": "stripe_checkout",
                        "utm_source": metadata.get("utm_source", ""),
                        "utm_medium": metadata.get("utm_medium", ""),
                        "utm_campaign": metadata.get("utm_campaign", ""),
                        "referrer": "",
                        "test_mode": is_test,
                    }) + "\n")
            except OSError:
                pass  # Non-critical — don't break webhook on log failure

    elif event_type == "customer.subscription.deleted":
        subscription_id = data.get("id", "")
        key_record = find_key_info_by_ref(subscription_id)
        deactivate_key_by_ref(subscription_id)
        if key_record:
            _email = key_record.get("email", "")
            _api_key = key_record["_key"]
            trial_end = data.get("trial_end")  # unix timestamp or None
            in_trial = trial_end and datetime.now(timezone.utc).timestamp() <= float(trial_end)
            try:
                if in_trial:
                    send_trial_ended_email(_email, _api_key)
                else:
                    send_subscription_suspended_email(_email, _api_key)
            except Exception as _e:
                logger.warning("Subscription deleted email failed: %s", _e)

    elif event_type == "customer.subscription.updated":
        subscription_id = data.get("id", "")
        status = data.get("status", "")
        if status in ("canceled", "unpaid", "past_due"):
            key_record = find_key_info_by_ref(subscription_id)
            deactivate_key_by_ref(subscription_id)
            if key_record and status in ("past_due", "unpaid"):
                try:
                    send_subscription_suspended_email(key_record.get("email", ""), key_record["_key"])
                except Exception as _e:
                    logger.warning("Subscription updated email failed: %s", _e)

    elif event_type == "invoice.paid":
        # Subscription renewal confirmed — reactivate key if it was suspended for past_due
        subscription_id = data.get("subscription", "")
        billing_reason = data.get("billing_reason", "")
        if subscription_id and billing_reason in ("subscription_cycle", "subscription_update"):
            key_record = find_key_info_by_ref(subscription_id)
            was_inactive = key_record and not key_record.get("active", True)
            reactivate_key_by_ref(subscription_id)
            logger.info("Invoice paid (renewal) for sub=%s — key confirmed active", subscription_id)
            if was_inactive and key_record:
                try:
                    send_subscription_reactivated_email(key_record.get("email", ""), key_record["_key"])
                except Exception as _e:
                    logger.warning("Subscription reactivated email failed: %s", _e)

    elif event_type == "invoice.payment_failed":
        # Payment failed — Stripe will retry; log and let subscription.updated handle deactivation
        subscription_id = data.get("subscription", "")
        attempt = data.get("attempt_count", 1)
        customer_id = data.get("customer", "")
        logger.warning(
            "Invoice payment failed for sub=%s customer=%s attempt=%s",
            subscription_id, customer_id, attempt
        )
        # On final failure (attempt_count >= 4 typically), Stripe sets subscription past_due
        # which fires customer.subscription.updated → deactivate_key_by_ref

    _checkout_sid = data.get("id", "") if event_type == "checkout.session.completed" else ""
    _mark_webhook_processed(event_id, event_type=event_type, session_id=_checkout_sid)
    return {"received": True}


# --- GET / (root) ---

@app.get("/")
async def root():
    """Root endpoint — service info."""
    return {
        "service": "arkforge-trust-layer",
        "version": __version__,
        "docs": "https://github.com/ark-forge/trust-layer",
        "endpoints": {
            "proxy": "POST /v1/proxy",
            "credits_buy": "POST /v1/credits/buy",
            "setup_pro": "POST /v1/keys/setup",
            "billing_portal": "POST /v1/keys/portal",
            "overage": "POST|GET /v1/keys/overage",
            "proof": "GET /v1/proof/{proof_id}",
            "reputation": "GET /v1/agent/{agent_id}/reputation",
            "disputes": "POST /v1/disputes",
            "agent_disputes": "GET /v1/agent/{agent_id}/disputes",
            "usage": "GET /v1/usage",
            "pubkey": "GET /v1/pubkey",
            "did": "GET /.well-known/did.json",
            "agent_json": "GET /.well-known/agent.json",
            "bind_did": "POST /v1/keys/bind-did",
            "bind_did_confirm": "POST /v1/keys/bind-did/confirm",
            "health": "GET /v1/health",
            "pricing": "GET /v1/pricing",
        },
    }


# --- GET /v1/health (+ /health alias) ---

@app.get("/health")
@app.get("/v1/health")
async def health():
    from .config import TRUST_LAYER_ENV
    resp = {
        "status": "ok",
        "service": "arkforge-trust-layer",
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": TRUST_LAYER_ENV,
    }
    if _FAILOVER_MODE:
        resp["mode"] = "failover"
        resp["write_enabled"] = False
    return resp


# --- POST /v1/keys/overage ---

@app.post("/v1/keys/overage")
async def set_overage(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """Enable or disable overage billing for the requesting API key.

    Body: {"enabled": true/false, "cap_eur": <5–100>}
    Only available for Pro and Enterprise plans.
    """
    api_key = _get_api_key(authorization, x_api_key)
    if not api_key:
        return _error_response("invalid_api_key", "API key required", 401)

    key_info = validate_api_key(api_key)
    if not key_info:
        return _error_response("invalid_api_key", "Invalid or inactive API key", 401)

    plan = get_key_plan(api_key)
    if plan not in ("pro", "enterprise"):
        return _error_response(
            "invalid_plan",
            "Overage billing is only available for Pro and Enterprise plans.",
            403,
        )

    try:
        body = await request.json()
    except Exception:
        return _error_response("invalid_request", "Invalid JSON body", 400)

    if "enabled" not in body:
        return _error_response("invalid_request", "'enabled' field is required (true/false)", 400)

    enabled = body.get("enabled")
    if not isinstance(enabled, bool):
        return _error_response("invalid_request", "'enabled' must be a boolean", 400)

    cap_eur = body.get("cap_eur", OVERAGE_CAP_DEFAULT)
    try:
        cap_eur = float(cap_eur)
    except (TypeError, ValueError):
        return _error_response("invalid_request", "'cap_eur' must be a number", 400)

    overage_rate = OVERAGE_PRICES.get(plan, PRO_OVERAGE_PRICE)

    try:
        settings = update_overage_settings(api_key, enabled=enabled, cap_eur=cap_eur,
                                           overage_rate=overage_rate)
    except ValueError as e:
        return _error_response("invalid_request", str(e), 400)

    msg = (
        f"Overage billing enabled. Proofs beyond quota billed at {overage_rate} EUR/proof "
        f"from prepaid credits, cap {cap_eur:.2f} EUR/month."
        if enabled
        else "Overage billing disabled. Requests beyond quota will be rejected (HTTP 429)."
    )

    return {
        "overage_enabled": settings["overage_enabled"],
        "overage_cap_eur": settings["overage_cap_eur"],
        "overage_rate_per_proof": overage_rate,
        "consent_at": settings["overage_consent_at"],
        "message": msg,
    }


# --- GET /v1/keys/overage ---

@app.get("/v1/keys/overage")
async def get_overage(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """Return current overage settings for the requesting API key."""
    api_key = _get_api_key(authorization, x_api_key)
    if not api_key:
        return _error_response("invalid_api_key", "API key required", 401)

    key_info = validate_api_key(api_key)
    if not key_info:
        return _error_response("invalid_api_key", "Invalid or inactive API key", 401)

    return get_overage_settings(api_key)


# --- GET /v1/usage ---

@app.get("/v1/usage")
async def usage(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """Return current usage for the requesting API key."""
    api_key = _get_api_key(authorization, x_api_key)
    if not api_key:
        return _error_response("invalid_api_key", "API key required", 401)
    if not validate_api_key(api_key):
        return _error_response("invalid_api_key", "Invalid or inactive API key", 401)
    result = get_usage(api_key)
    # Add overage credit balance for subscription plans (not free/test/internal)
    if not is_free_key(api_key) and result.get("plan") not in ("test", "internal"):
        balance = get_balance(api_key)
        result["overage_credits_eur"] = round(balance, 4)
    return result


# --- GET /v1/pricing ---

@app.get("/v1/pricing")
async def pricing():
    return {
        "plans": {
            "free": {
                "price": "0 EUR/month",
                "monthly_quota": FREE_TIER_MONTHLY_LIMIT,
                "daily_cap": DAILY_LIMITS_PER_PLAN["free"],
                "overage": None,
                "witnesses": "3 (Ed25519, RFC 3161 TSA, Sigstore Rekor)",
                "setup": f"{TRUST_LAYER_BASE_URL}/v1/keys/free-signup",
                "credit_card_required": False,
            },
            "pro": {
                "price": "29 EUR/month",
                "monthly_quota": PRO_MONTHLY_LIMIT,
                "daily_cap": DAILY_LIMITS_PER_PLAN["pro"],
                "overage": f"{PRO_OVERAGE_PRICE} EUR/proof (opt-in)",
                "witnesses": "3 (Ed25519, RFC 3161 TSA, Sigstore Rekor)",
                "setup": f"{TRUST_LAYER_BASE_URL}/v1/keys/setup",
                "buy_credits": f"{TRUST_LAYER_BASE_URL}/v1/credits/buy",
                "overage_config": {
                    "rate": PRO_OVERAGE_PRICE,
                    "opt_in": True,
                    "default_cap_eur": OVERAGE_CAP_DEFAULT,
                    "cap_range": [OVERAGE_CAP_MIN, OVERAGE_CAP_MAX],
                    "enable_endpoint": "/v1/keys/overage",
                },
            },
            "enterprise": {
                "price": "149 EUR/month",
                "monthly_quota": ENTERPRISE_MONTHLY_LIMIT,
                "daily_cap": DAILY_LIMITS_PER_PLAN["enterprise"],
                "overage": f"{ENTERPRISE_OVERAGE_PRICE} EUR/proof (opt-in)",
                "witnesses": "3 (Ed25519, RFC 3161 QTSP eIDAS, Sigstore Rekor)",
                "setup": f"{TRUST_LAYER_BASE_URL}/v1/keys/enterprise-setup",
                "credit_card_required": True,
                "overage_config": {
                    "rate": ENTERPRISE_OVERAGE_PRICE,
                    "opt_in": True,
                    "default_cap_eur": OVERAGE_CAP_DEFAULT,
                    "cap_range": [OVERAGE_CAP_MIN, OVERAGE_CAP_MAX],
                    "enable_endpoint": "/v1/keys/overage",
                },
            },
        },
        "contact": "contact@arkforge.fr",
    }


# --- GET /v1/pubkey ---

@app.get("/v1/pubkey")
async def get_pubkey():
    """Return ArkForge's Ed25519 public key for proof signature verification."""
    if not ARKFORGE_PUBLIC_KEY:
        return _error_response("not_configured", "Signing key not configured", 503)
    return {"pubkey": ARKFORGE_PUBLIC_KEY, "algorithm": "Ed25519"}


# --- GET /.well-known/did.json ---

@app.get("/.well-known/did.json")
async def get_did_document():
    """W3C DID Document for did:web:trust.arkforge.tech."""
    if not TRUST_LAYER_BASE_URL or not ARKFORGE_PUBLIC_KEY:
        return _error_response("not_configured", "Trust layer not fully configured", 503)

    # did:web strips the https:// scheme
    did = "did:web:" + TRUST_LAYER_BASE_URL.removeprefix("https://").removeprefix("http://")
    key_id = f"{did}#key-1"

    # ARKFORGE_PUBLIC_KEY format: "ed25519:<base64url_43chars>"
    pubkey_b64url = ARKFORGE_PUBLIC_KEY.split(":", 1)[1] if ":" in ARKFORGE_PUBLIC_KEY else ARKFORGE_PUBLIC_KEY

    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": pubkey_b64url,
                },
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
    }


# --- GET /.well-known/agent.json ---

@app.get("/.well-known/agent.json")
async def get_agent_json():
    """agent.json v1.4 capability manifest for trust.arkforge.tech."""
    if not TRUST_LAYER_BASE_URL or not ARKFORGE_PUBLIC_KEY:
        return _error_response("not_configured", "Trust layer not fully configured", 503)

    origin = TRUST_LAYER_BASE_URL.removeprefix("https://").removeprefix("http://")
    did = "did:web:" + origin
    pubkey_b64url = ARKFORGE_PUBLIC_KEY.split(":", 1)[1] if ":" in ARKFORGE_PUBLIC_KEY else ARKFORGE_PUBLIC_KEY
    base = f"https://{origin}"

    return {
        "version": "1.4",
        "origin": origin,
        "payout_address": "0x0000000000000000000000000000000000000000",
        "identity": {
            "did": did,
            "public_key": pubkey_b64url,
            "oatr_issuer_id": "arkforge",
        },
        "intents": [
            {
                "name": "certify_proxy",
                "description": "Certify an agent-to-agent API call and produce a verifiable execution proof",
                "endpoint": f"{base}/v1/proxy",
                "method": "POST",
                "parameters": {
                    "target_url": {"type": "string", "description": "URL of the upstream service"},
                    "payload": {"type": "object", "description": "Request body to forward"},
                },
                "returns": {"type": "object", "description": "Upstream response with proof_id and signed receipt"},
            },
            {
                "name": "get_proof",
                "description": "Retrieve a verifiable execution proof by ID",
                "endpoint": f"{base}/v1/proof/{{proof_id}}",
                "method": "GET",
                "parameters": {
                    "proof_id": {"type": "string", "description": "Proof identifier (e.g. prf_20260324_...)"},
                },
                "returns": {"type": "object", "description": "Proof JSON with chain hash, Ed25519 signature, and TSA timestamps"},
            },
            {
                "name": "bind_did",
                "description": "Bind a DID to an API key via Ed25519 challenge-response (Path A) or OATR delegation (Path B)",
                "endpoint": f"{base}/v1/keys/bind-did",
                "method": "POST",
                "parameters": {
                    "did": {"type": "string", "description": "DID to bind (e.g. did:web:example.com)"},
                    "oatr_issuer_id": {"type": "string", "description": "OATR issuer ID for Path B delegation (optional)"},
                },
                "returns": {"type": "object", "description": "Challenge for Ed25519 signing (Path A) or immediate binding (Path B)"},
            },
            {
                "name": "free_signup",
                "description": "Create a free-tier API key (500 proofs/month, no credit card required)",
                "endpoint": f"{base}/v1/keys/free-signup",
                "method": "POST",
                "parameters": {},
                "returns": {"type": "object", "description": "API key and usage quota"},
            },
        ],
        "pricing": {
            "model": "tiered",
            "free_tier": {"monthly_quota": 500, "per_call_eur": 0.0},
            "pro": {"monthly_eur": 29.0, "monthly_quota": 5000, "overage_per_call_eur": 0.01},
            "enterprise": {"monthly_eur": 149.0, "monthly_quota": 50000, "overage_per_call_eur": 0.005},
        },
        "commitments": {
            "schema_version": "1.0",
            "entries": [
                {
                    "type": "proof_format",
                    "constraint": "All proofs conform to ArkForge Proof Specification v2.1+",
                    "verifiable": True,
                    "ref": "https://github.com/ark-forge/proof-spec/blob/main/SPEC.md",
                },
                {
                    "type": "did_binding_verification",
                    "constraint": "agent_identity_verified=true only when DID bound via Ed25519 challenge-response or OATR delegation; self-declared values always produce agent_identity_verified=false",
                    "verifiable": True,
                },
                {
                    "type": "audit_immutability",
                    "constraint": "Proofs are immutable post-creation; chain hash is deterministic and independently recomputable without ArkForge infrastructure",
                    "verifiable": True,
                },
                {
                    "type": "witness_count",
                    "constraint": "All proofs carry minimum 3 independent witnesses: Ed25519 signature, RFC 3161 TSA, Sigstore Rekor",
                    "verifiable": True,
                },
            ],
        },
    }


# --- GET /v1/stats ---

@app.get("/v1/stats")
async def get_stats():
    """Public proof count — no auth required. Cached 60s."""
    from .config import PROOFS_DIR
    import time
    cache = getattr(get_stats, "_cache", None)
    now = time.monotonic()
    if cache and now - cache["ts"] < 60:
        return cache["data"]
    count = sum(1 for f in PROOFS_DIR.iterdir() if f.suffix == ".json") if PROOFS_DIR.exists() else 0
    data = {"proofs_generated": count}
    get_stats._cache = {"ts": now, "data": data}
    return data


# --- GET /v1/agent/{agent_id}/reputation ---

@app.get("/v1/agent/{agent_id}/reputation")
async def agent_reputation(agent_id: str):
    """Public reputation score for an agent. No auth required."""
    rep = get_reputation(agent_id)
    if rep is None:
        return _error_response("not_found", f"Agent '{agent_id}' not found (no proofs)", 404)
    return get_public_reputation(rep)


# --- POST /v1/disputes ---

@app.post("/v1/disputes")
async def file_dispute(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """File a dispute against a proof. Resolved instantly."""
    api_key = _get_api_key(authorization, x_api_key)
    if not api_key:
        return _error_response("invalid_api_key", "API key required", 401)

    key_info = validate_api_key(api_key)
    if not key_info:
        return _error_response("invalid_api_key", "Invalid or inactive API key", 401)

    try:
        body = await request.json()
    except Exception:
        return _error_response("invalid_request", "Invalid JSON body", 400)

    proof_id = body.get("proof_id", "")
    reason = body.get("reason", "")

    if not proof_id:
        return _error_response("invalid_request", "proof_id is required", 400)
    if not reason or not reason.strip():
        return _error_response("invalid_request", "reason is required", 400)

    result = create_dispute(api_key, proof_id, reason)

    if "error" in result:
        return _error_response(result["error"], result["message"], result["status"])

    return JSONResponse(status_code=201, content={
        "dispute_id": result["dispute_id"],
        "proof_id": result["proof_id"],
        "status": result["status"],
        "resolution_details": result["resolution_details"],
        "impact": _dispute_impact_message(result),
        "created_at": result["created_at"],
    })


def _dispute_impact_message(dispute: dict) -> str:
    """Human-readable impact description."""
    status = dispute["status"]
    if status == "UPHELD":
        return f"{dispute['contestant_role'].title()} wins. Proof corrected. Loser +1 lost_dispute."
    elif status == "DENIED":
        return f"Dispute denied. Contestant +1 lost_dispute."
    return "No impact."


# --- GET /v1/agent/{agent_id}/disputes ---

@app.get("/v1/agent/{agent_id}/disputes")
async def agent_disputes(agent_id: str):
    """Public dispute history for an agent. No auth required."""
    return get_agent_disputes(agent_id)


# --- POST /attest ---

@app.post("/attest")
async def attest_endpoint(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """Provider-agnostic execution attestation — Encina HttpAttestationProvider compatible.

    Body: {recordId, recordType, occurredAtUtc, contentHash}
    Returns: {attestationId, auditRecordId, signature, attestedAtUtc, proofMetadata}
    Idempotent: same recordId from same API key returns existing receipt.
    """
    api_key = _get_api_key(authorization, x_api_key)
    if not api_key:
        return _error_response("invalid_api_key", "API key required. Use Authorization: Bearer <key>", 401)

    key_info = validate_api_key(api_key)
    if not key_info:
        return _error_response("invalid_api_key", "Invalid or inactive API key", 401)

    try:
        body = await request.json()
    except Exception:
        return _error_response("invalid_request", "Invalid JSON body", 400)

    record_id = body.get("recordId", "")
    record_type = body.get("recordType", "")
    occurred_at_utc = body.get("occurredAtUtc", "")
    content_hash = body.get("contentHash", "")

    if not record_id or not record_type or not occurred_at_utc or not content_hash:
        missing = [f for f, v in [
            ("recordId", record_id), ("recordType", record_type),
            ("occurredAtUtc", occurred_at_utc), ("contentHash", content_hash),
        ] if not v]
        return _error_response("invalid_request", f"Missing required fields: {', '.join(missing)}", 400)

    attester_fingerprint = sha256_hex(api_key)

    # Idempotency: same recordId + same API key → return existing receipt
    existing = find_by_record_id(record_id, f"sha256:{attester_fingerprint}")
    if existing:
        return JSONResponse(status_code=200, content=attestation_to_encina_response(existing))

    try:
        from .config import get_signing_key
        attestation = build_attestation(
            record_id=record_id,
            record_type=record_type,
            occurred_at_utc=occurred_at_utc,
            content_hash=content_hash,
            attester_fingerprint=f"sha256:{attester_fingerprint}",
            signing_key=get_signing_key(),
        )
    except ValueError as e:
        return _error_response("invalid_request", str(e), 400)

    store_attestation(attestation)
    return JSONResponse(status_code=200, content=attestation_to_encina_response(attestation))


# --- GET /receipt/{attestation_id} ---

@app.get("/receipt/{attestation_id}")
async def get_receipt_endpoint(
    attestation_id: str,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """Retrieve a stored attestation receipt by ID.

    Returns: {attestationId, auditRecordId, signature, attestedAtUtc, proofMetadata}
    """
    api_key = _get_api_key(authorization, x_api_key)
    if not api_key:
        return _error_response("invalid_api_key", "API key required. Use Authorization: Bearer <key>", 401)

    key_info = validate_api_key(api_key)
    if not key_info:
        return _error_response("invalid_api_key", "Invalid or inactive API key", 401)

    attestation = load_attestation(attestation_id)
    if not attestation:
        return _error_response("not_found", f"Attestation {attestation_id!r} not found", 404)

    return JSONResponse(status_code=200, content=attestation_to_encina_response(attestation))


# --- Main ---

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8092, log_level="info")  # nosec B104
