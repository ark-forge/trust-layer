"""FastAPI app — all routes for the Trust Layer."""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import stripe
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse, Response, HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

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
    MIN_AMOUNT,
    MAX_AMOUNT,
    RATE_LIMIT_PER_KEY_PER_DAY,
    FREE_TIER_MONTHLY_LIMIT,
    PROOF_ACCESS_LOG,
)
from .keys import validate_api_key, create_api_key, deactivate_key_by_ref, is_test_key
from .proofs import load_proof, store_proof, get_public_proof, verify_proof_integrity
from .proxy import execute_proxy, ProxyError
from .templates import render_proof_page
from .rate_limit import get_usage
from .email_notify import send_welcome_email

logger = logging.getLogger("trust_layer.app")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

# --- Proof access tracking (in-memory for abuse detection, JSONL for persistence) ---
_proof_access_counts: dict[str, list[float]] = defaultdict(list)  # IP -> list of timestamps
_ABUSE_THRESHOLD = 100  # max requests per hour per IP


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
    except Exception:
        pass

    # Abuse detection: track per-IP access rate (sliding 1h window)
    timestamps = _proof_access_counts[ip]
    timestamps.append(now)
    # Prune entries older than 1 hour
    cutoff = now - 3600
    _proof_access_counts[ip] = [t for t in timestamps if t > cutoff]
    if len(_proof_access_counts[ip]) > _ABUSE_THRESHOLD:
        logger.warning("ABUSE DETECTED: IP %s made %d proof requests in 1h", ip, len(_proof_access_counts[ip]))


app = FastAPI(
    title="ArkForge Trust Layer",
    description="Certifying proxy for agent-to-agent payments. Pay any API, get cryptographic proof.",
    version=__version__,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    api_key = _get_api_key(authorization, x_api_key)
    if not api_key:
        return _error_response("invalid_api_key", "API key required. Use Authorization: Bearer <key>", 401)

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

    if not target:
        return _error_response("invalid_target", "Missing 'target' field", 400)
    if amount is None:
        return _error_response("invalid_amount", "Missing 'amount' field", 400)

    try:
        amount = float(amount)
    except (TypeError, ValueError):
        return _error_response("invalid_amount", f"Amount must be a number, got '{amount}'", 400)

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
        service_ok = "error" not in result
        if verification_url:
            headers["X-ArkForge-Proof"] = verification_url
        headers["X-ArkForge-Verified"] = "true" if service_ok else "false"
        if proof_id:
            headers["X-ArkForge-Proof-ID"] = proof_id
            headers["X-ArkForge-Trust-Link"] = f"{TRUST_LAYER_BASE_URL}/v/{proof_id}"

    return JSONResponse(status_code=status_code, content=result, headers=headers)


# --- GET /v1/proof/{proof_id} ---

@app.get("/v1/proof/{proof_id}")
async def get_proof(proof_id: str, request: Request):
    """Public proof verification — no auth required. Lazy-upgrades OTS on access.

    Content negotiation (Level 3 — Visual Stamp):
    - Accept: text/html (without application/json) → HTML proof page
    - Otherwise → JSON (backward compat)
    """
    # Log access for security monitoring
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    _log_proof_access(proof_id, client_ip, user_agent)

    proof = load_proof(proof_id)
    if not proof:
        return _error_response("not_found", f"Proof '{proof_id}' not found", 404)

    # Increment views_count in proof metadata
    proof["views_count"] = proof.get("views_count", 0) + 1
    try:
        store_proof(proof_id, proof)
    except Exception:
        pass  # Don't fail the request if view tracking fails

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


# --- GET /v/{proof_id} — Short URL redirect ---

@app.get("/v/{proof_id}")
async def short_proof_url(proof_id: str):
    """Short URL redirect to full proof endpoint. 302 with cache."""
    proof = load_proof(proof_id)
    if not proof:
        return _error_response("not_found", f"Proof '{proof_id}' not found", 404)
    return RedirectResponse(
        url=f"{TRUST_LAYER_BASE_URL}/v1/proof/{proof_id}",
        status_code=302,
        headers={"Cache-Control": "public, max-age=86400"},
    )


# --- GET /v1/proof/{proof_id}/tsr ---

@app.get("/v1/proof/{proof_id}/tsr")
async def get_proof_tsr(proof_id: str):
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
    """Create a Stripe Checkout Session in setup mode to save a card."""
    try:
        body = await request.json()
    except Exception:
        return _error_response("invalid_request", "Invalid JSON body", 400)

    email = body.get("email", "")
    if not email:
        return _error_response("invalid_request", "email is required", 400)

    req_mode = body.get("mode", "live")
    sk = STRIPE_TEST_KEY if req_mode == "test" else STRIPE_LIVE_KEY
    if not sk:
        return _error_response("internal_error", f"Stripe {req_mode} key not configured", 500)

    try:
        customers = stripe.Customer.list(email=email, limit=1, api_key=sk)
        if customers.data:
            customer = customers.data[0]
        else:
            customer = stripe.Customer.create(
                email=email,
                metadata={"source": "trust-layer-setup"},
                api_key=sk,
            )

        session = stripe.checkout.Session.create(
            mode="setup",
            payment_method_types=["card"],
            customer=customer.id,
            success_url=f"{TRUST_LAYER_BASE_URL}/setup-success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{TRUST_LAYER_BASE_URL}/setup-canceled",
            metadata={"product": "trust_layer_setup", "email": email, "stripe_mode": req_mode},
            api_key=sk,
        )

        return {
            "checkout_url": session.url,
            "session_id": session.id,
            "customer_id": customer.id,
            "mode": req_mode,
        }

    except stripe.StripeError as e:
        logger.error("Stripe setup error: %s", e)
        return _error_response("internal_error", f"Stripe error: {str(e)}", 500)


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
        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            raise HTTPException(400, "Invalid JSON")
        logger.warning("Webhook received without signature verification")

    event_type = event.get("type", "")
    data = event.get("data", {}).get("object", {})
    is_test = not event.get("livemode", True)

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
        ref_id = subscription_id or payment_intent_id or customer_id

        if customer_id or customer_email:
            api_key = create_api_key(customer_id, ref_id, customer_email, test_mode=is_test)
            logger.info("API key created for %s (ref=%s)", customer_email, ref_id)
            try:
                send_welcome_email(customer_email, api_key)
            except Exception as e:
                logger.error("Welcome email failed: %s", e)

    elif event_type == "customer.subscription.deleted":
        subscription_id = data.get("id", "")
        deactivate_key_by_ref(subscription_id)

    elif event_type == "customer.subscription.updated":
        subscription_id = data.get("id", "")
        status = data.get("status", "")
        if status in ("canceled", "unpaid", "past_due"):
            deactivate_key_by_ref(subscription_id)

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
            "proof": "GET /v1/proof/{proof_id}",
            "health": "GET /v1/health",
            "pricing": "GET /v1/pricing",
        },
    }


# --- GET /v1/health ---

@app.get("/v1/health")
async def health():
    return {
        "status": "ok",
        "service": "arkforge-trust-layer",
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


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
    return get_usage(api_key)


# --- GET /v1/pricing ---

@app.get("/v1/pricing")
async def pricing():
    return {
        "plans": {
            "free": {
                "price": "0 EUR/month",
                "limit": f"{FREE_TIER_MONTHLY_LIMIT} proofs/month",
                "proofs": "public",
                "setup": f"{TRUST_LAYER_BASE_URL}/v1/keys/setup",
            },
            "pro": {
                "price": "pay-per-proof",
                "limit": f"{RATE_LIMIT_PER_KEY_PER_DAY} proofs/day",
                "proofs": "public",
                "setup": f"{TRUST_LAYER_BASE_URL}/v1/keys/setup",
            },
        },
        "proxy": {
            "description": "Pay any HTTPS API via proxy — charge, forward, prove",
            "min_amount": MIN_AMOUNT,
            "max_amount": MAX_AMOUNT,
            "currencies": SUPPORTED_CURRENCIES,
            "fee": "0% — you pay only the amount you specify",
        },
        "contact": "contact@arkforge.fr",
    }


# --- Main ---

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8092, log_level="info")
