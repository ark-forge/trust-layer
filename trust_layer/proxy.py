"""Core proxy logic — charge, forward, prove."""

import asyncio
import hashlib
import ipaddress
import logging
import socket
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx

from .config import (
    SUPPORTED_CURRENCIES,
    MIN_AMOUNT,
    MAX_AMOUNT,
    PROOF_PRICE,
    PROXY_TIMEOUT_SECONDS,
    MAX_RESPONSE_STORE_BYTES,
    IDEMPOTENCY_DIR,
    IDEMPOTENCY_TTL_HOURS,
    TRUST_LAYER_BASE_URL,
    AGENTS_DIR,
    SERVICES_DIR,
    BACKGROUND_TASKS_LOG,
    ARKFORGE_PUBLIC_KEY,
    INTERNAL_SECRET,
    get_signing_key,
)
from .keys import validate_api_key, _KEYS_LOCK
from .payments.base import ChargeResult
from .credits import debit_credits, InsufficientCredits
from .proofs import sha256_hex, generate_proof_id, generate_proof, store_proof
from .receipt import fetch_receipt
from .persistence import load_json, save_json
from .rate_limit import check_rate_limit
from .timestamps import submit_hash
from .email_notify import send_proof_email, send_low_credits_email, send_credits_exhausted_email
from .crypto import sign_proof

logger = logging.getLogger("trust_layer.proxy")

# Track active background tasks for graceful shutdown
_active_tasks: set[asyncio.Task] = set()


def _track_task(task: asyncio.Task) -> None:
    """Register a background task and auto-remove it when done."""
    _active_tasks.add(task)
    task.add_done_callback(_active_tasks.discard)


async def drain_background_tasks(timeout: float = 10.0) -> int:
    """Wait for all pending background tasks (up to timeout). Returns count drained."""
    if not _active_tasks:
        return 0
    pending = len(_active_tasks)
    logger.info("Draining %d background tasks (timeout=%.0fs)...", pending, timeout)
    done, still_pending = await asyncio.wait(_active_tasks, timeout=timeout)
    if still_pending:
        logger.warning("%d background tasks did not finish in time, cancelling", len(still_pending))
        for t in still_pending:
            t.cancel()
    return len(done)


def _log_background_task(proof_id: str, task: str, status: str, detail: str = ""):
    """Append one line to background_tasks_log.jsonl for monitoring."""
    import json
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "proof_id": proof_id,
        "task": task,
        "status": status,
    }
    if detail:
        entry["detail"] = detail[:200]
    try:
        with open(BACKGROUND_TASKS_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        logger.debug("Background task log write failed: %s", e)


async def _post_proof_background(proof_id: str, proof_record: dict, chain_hash: str,
                                  verification_url: str, email: str):
    """Background task: TSA + email — none of these block the client response."""
    # RFC 3161 Timestamp (sync but run in thread to avoid blocking event loop)
    try:
        import base64 as _b64
        loop = asyncio.get_running_loop()
        tsr_bytes = await loop.run_in_executor(None, submit_hash, chain_hash)
        if tsr_bytes:
            from .config import PROOFS_DIR
            (PROOFS_DIR / f"{proof_id}.tsr").write_bytes(tsr_bytes)
            proof_record["timestamp_authority"]["status"] = "verified"
            proof_record["timestamp_authority"]["tsr_base64"] = _b64.b64encode(tsr_bytes).decode("ascii")
            store_proof(proof_id, proof_record)
            logger.info("TSA timestamp verified for %s", proof_id)
            _log_background_task(proof_id, "tsa", "success")
        else:
            _log_background_task(proof_id, "tsa", "failure", "submit_hash returned None")
    except (OSError, ValueError, RuntimeError) as e:
        logger.warning("TSA submit skipped: %s", e)
        _log_background_task(proof_id, "tsa", "failure", str(e))

    # Email
    if email:
        try:
            await asyncio.get_running_loop().run_in_executor(
                None, send_proof_email, email, proof_id, proof_record)
            _log_background_task(proof_id, "email", "success")
        except (OSError, RuntimeError) as e:
            logger.warning("Proof email skipped: %s", e)
            _log_background_task(proof_id, "email", "failure", str(e))


def _scrub_internal_secret(body: object) -> object:
    """Remove X-Internal-Secret from service response body (recursive).

    The secret is injected in forward headers only. If the upstream service
    echoes request headers back (e.g. httpbin /anything), the secret would
    appear in the response body. This scrubber removes it before we return
    the body to the client. The chain hash is computed BEFORE this call so
    integrity is not affected.
    """
    if isinstance(body, dict):
        return {
            k: _scrub_internal_secret(v)
            for k, v in body.items()
            if k.lower() != "x-internal-secret"
        }
    if isinstance(body, list):
        return [_scrub_internal_secret(item) for item in body]
    return body


def _inject_digital_stamp(result: dict, proof_record: dict) -> None:
    """Level 1 — Digital Stamp: inject _arkforge_attestation into successful response body.

    Skips injection if:
    - No service_response in result
    - Body is not a dict (non-JSON response)
    - Body contains _raw_text (non-parseable response)
    - Result contains an error path
    """
    sr = result.get("service_response")
    if not sr or not isinstance(sr, dict):
        return
    body = sr.get("body")
    if not isinstance(body, dict):
        return
    if "_raw_text" in body:
        return
    if "error" in result:
        return

    proof_id = proof_record.get("proof_id", "")
    verification_url = proof_record.get("verification_url", "")
    body["_arkforge_attestation"] = {
        "id": proof_id,
        "seal": verification_url,
        "status": "VERIFIED_TRANSACTION",
        "msg": "Payment confirmed, execution anchored.",
    }

# Private IP ranges to block
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


async def _check_no_private_dns(hostname: str) -> None:
    """Resolve hostname and reject if any resolved address is in a private range.

    Guards against DNS rebinding attacks: an attacker-controlled domain may have
    a public IP at syntactic-validation time but resolve to a private IP at request
    time (after TTL expiry). We resolve at request time and re-check every address.
    """
    loop = asyncio.get_running_loop()
    try:
        results = await loop.run_in_executor(None, socket.getaddrinfo, hostname, None)
    except OSError:
        raise ProxyError("invalid_target", f"Could not resolve hostname '{hostname}'", 400)
    for _family, _type, _proto, _canonname, sockaddr in results:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
            for network in _PRIVATE_NETWORKS:
                if addr in network:
                    raise ProxyError("invalid_target", "Target resolves to private IP range", 400)
        except ValueError:
            pass


class ProxyError(Exception):
    """Structured proxy error."""
    def __init__(self, code: str, message: str, status: int, proof: Optional[dict] = None):
        self.code = code
        self.message = message
        self.status = status
        self.proof = proof
        super().__init__(message)

    def to_dict(self) -> dict:
        result = {"error": {"code": self.code, "message": self.message, "status": self.status}}
        if self.proof:
            result["proof"] = self.proof
        return result


def validate_target_url(target: str) -> str:
    """Validate target URL: must be HTTPS, no private IPs, no dangerous schemes."""
    parsed = urlparse(target)

    if parsed.scheme != "https":
        raise ProxyError("invalid_target", f"Only HTTPS targets allowed, got '{parsed.scheme}'", 400)

    hostname = parsed.hostname
    if not hostname:
        raise ProxyError("invalid_target", "Invalid target URL: no hostname", 400)

    if hostname in ("localhost", "0.0.0.0"):
        raise ProxyError("invalid_target", f"Target hostname '{hostname}' is not allowed", 400)

    # Check for private IPs
    try:
        addr = ipaddress.ip_address(hostname)
        for network in _PRIVATE_NETWORKS:
            if addr in network:
                raise ProxyError("invalid_target", f"Target resolves to private IP range", 400)
    except ValueError:
        # hostname is a domain name, not an IP — OK
        pass

    return target


def validate_currency(currency: str) -> str:
    """Validate and normalize currency."""
    currency = currency.lower().strip()
    if currency not in SUPPORTED_CURRENCIES:
        raise ProxyError(
            "invalid_currency",
            f"Currency '{currency}' not supported. Supported: {', '.join(SUPPORTED_CURRENCIES)}",
            400,
        )
    return currency


def validate_amount(amount: float) -> float:
    """Validate amount within limits."""
    if amount < MIN_AMOUNT:
        raise ProxyError("invalid_amount", f"Amount {amount} below minimum {MIN_AMOUNT}", 400)
    if amount > MAX_AMOUNT:
        raise ProxyError("invalid_amount", f"Amount {amount} above maximum {MAX_AMOUNT}", 400)
    return amount


def _idempotency_path(key: str):
    """Get idempotency cache file path."""
    hashed = hashlib.sha256(key.encode()).hexdigest()[:16]
    return IDEMPOTENCY_DIR / f"{hashed}.json"


def _check_idempotency(key: Optional[str]) -> Optional[dict]:
    """Check idempotency cache. Returns cached response or None."""
    if not key:
        return None
    path = _idempotency_path(key)
    if not path.exists():
        return None
    data = load_json(path)
    # Check TTL
    created = data.get("created_at", "")
    if created:
        try:
            created_dt = datetime.fromisoformat(created)
            age_hours = (datetime.now(timezone.utc) - created_dt).total_seconds() / 3600
            if age_hours > IDEMPOTENCY_TTL_HOURS:
                path.unlink(missing_ok=True)
                return None
        except (ValueError, TypeError):
            pass
    return data.get("response")


_MAX_IDEMPOTENCY_BYTES = 512 * 1024  # 512 KB


def _cache_idempotency(key: Optional[str], response: dict):
    """Cache response for idempotency key. Skipped if response exceeds 512 KB."""
    if not key:
        return
    import json as _json
    try:
        encoded = _json.dumps(response).encode()
    except (TypeError, ValueError):
        return
    if len(encoded) > _MAX_IDEMPOTENCY_BYTES:
        logger.debug("Idempotency cache skipped: response too large (%d bytes)", len(encoded))
        return
    path = _idempotency_path(key)
    save_json(path, {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "response": response,
    })


def _update_agent_profile(api_key: str, amount: float, currency: str, target_domain: str, succeeded: bool,
                          agent_identity: Optional[str] = None, agent_version: Optional[str] = None):
    """Update shadow profile for the agent (buyer)."""
    key_prefix = api_key[:16]
    path = AGENTS_DIR / f"{key_prefix}.json"
    profile = load_json(path, {
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "transactions_total": 0,
        "transactions_succeeded": 0,
        "amount_total_eur": 0.0,
        "services_used": [],
        "last_transaction": None,
    })
    profile["transactions_total"] = profile.get("transactions_total", 0) + 1
    if succeeded:
        profile["transactions_succeeded"] = profile.get("transactions_succeeded", 0) + 1
    # Approximate EUR amount (for stats, not exact conversion)
    profile["amount_total_eur"] = round(profile.get("amount_total_eur", 0.0) + amount, 2)
    services = profile.get("services_used", [])
    if target_domain not in services:
        services.append(target_domain)
    profile["services_used"] = services
    profile["last_transaction"] = datetime.now(timezone.utc).isoformat()
    # Rolling 30-day activity index — avoids O(N) proof scan for active_days_30d
    from datetime import timedelta
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cutoff_date = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    dates = profile.get("proof_dates_30d", [])
    if today not in dates:
        dates.append(today)
    profile["proof_dates_30d"] = [d for d in dates if d >= cutoff_date]
    # Track declared identity — detect mismatches (same key, different identity)
    if agent_identity:
        existing = profile.get("declared_identity")
        if existing and existing != agent_identity:
            profile["identity_mismatch"] = True
        profile["declared_identity"] = agent_identity
    if agent_version:
        profile["declared_version"] = agent_version
    # Store buyer fingerprint for reputation/dispute lookups
    fingerprint = sha256_hex(api_key)
    profile["buyer_fingerprint"] = fingerprint
    save_json(path, profile)
    # Maintain fingerprint→key_prefix index (O(1) lookup for reputation/disputes)
    _update_fingerprint_index(fingerprint, key_prefix)


_FINGERPRINT_INDEX_PATH = AGENTS_DIR / "_fingerprint_index.json"


def _update_fingerprint_index(fingerprint: str, key_prefix: str):
    """Maintain fingerprint → key_prefix mapping for reputation/dispute lookups."""
    index = load_json(_FINGERPRINT_INDEX_PATH, {})
    if index.get(fingerprint) != key_prefix:
        index[fingerprint] = key_prefix
        save_json(_FINGERPRINT_INDEX_PATH, index)


def _update_service_profile(target_domain: str, response_time_ms: float, succeeded: bool):
    """Update shadow profile for the service (seller)."""
    domain_hash = hashlib.sha256(target_domain.encode()).hexdigest()[:16]
    path = SERVICES_DIR / f"{domain_hash}.json"
    profile = load_json(path, {
        "domain": target_domain,
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "transactions_total": 0,
        "transactions_succeeded": 0,
        "avg_response_time_ms": 0.0,
        "success_rate": 1.0,
        "last_transaction": None,
    })
    total = profile.get("transactions_total", 0) + 1
    success_count = profile.get("transactions_succeeded", 0) + (1 if succeeded else 0)
    old_avg = profile.get("avg_response_time_ms", 0.0)
    # Running average
    new_avg = ((old_avg * (total - 1)) + response_time_ms) / total if total > 0 else response_time_ms

    profile["transactions_total"] = total
    profile["transactions_succeeded"] = success_count
    profile["avg_response_time_ms"] = round(new_avg, 1)
    profile["success_rate"] = round(success_count / total, 3) if total > 0 else 1.0
    profile["last_transaction"] = datetime.now(timezone.utc).isoformat()
    save_json(path, profile)


def _notify_credits_exhausted(api_key: str, key_info: dict):
    """Send exhausted email once per 24h to avoid spamming."""
    from datetime import timedelta
    from .keys import load_api_keys, save_api_keys
    email = key_info.get("email")
    if not email:
        return
    should_notify = False
    with _KEYS_LOCK:
        keys = load_api_keys()
        info = keys.get(api_key, {})
        last = info.get("credits_exhausted_alert_sent_at")
        if last:
            try:
                last_dt = datetime.fromisoformat(last)
                if datetime.now(timezone.utc) - last_dt < timedelta(hours=24):
                    return  # Already notified in the last 24h
            except (ValueError, AttributeError):
                pass
        should_notify = True
        info["credits_exhausted_alert_sent_at"] = datetime.now(timezone.utc).isoformat()
        keys[api_key] = info
        save_api_keys(keys)
    if should_notify:
        send_credits_exhausted_email(email, api_key)


def _notify_low_credits_if_needed(api_key: str, key_info: dict, balance: float):
    """Send low-credits warning when balance drops below 10 proofs. Once per 24h."""
    from datetime import timedelta
    from .keys import load_api_keys, save_api_keys
    low_threshold = round(PROOF_PRICE * 10, 2)  # 1.00 EUR = 10 proofs
    if balance > low_threshold:
        return
    email = key_info.get("email")
    if not email:
        return
    should_notify = False
    proofs_remaining = max(0, int(balance / PROOF_PRICE))
    with _KEYS_LOCK:
        keys = load_api_keys()
        info = keys.get(api_key, {})
        last = info.get("low_credits_alert_sent_at")
        if last:
            try:
                last_dt = datetime.fromisoformat(last)
                if datetime.now(timezone.utc) - last_dt < timedelta(hours=24):
                    return
            except (ValueError, AttributeError):
                pass
        should_notify = True
        info["low_credits_alert_sent_at"] = datetime.now(timezone.utc).isoformat()
        keys[api_key] = info
        save_api_keys(keys)
    if should_notify:
        send_low_credits_email(email, api_key, balance, proofs_remaining)


async def execute_proxy(
    target: str,
    method: str,
    payload: dict,
    amount: float,
    currency: str,
    api_key: str,
    description: str = "",
    idempotency_key: Optional[str] = None,
    agent_identity: Optional[str] = None,
    agent_version: Optional[str] = None,
    provider_payment: Optional[dict] = None,
) -> dict:
    """Execute the full proxy flow: validate → charge → forward → prove."""

    # 1. Validate API key
    key_info = validate_api_key(api_key)
    if not key_info:
        raise ProxyError("invalid_api_key", "Invalid or inactive API key", 401)

    # 2. Validate inputs
    currency = validate_currency(currency)
    target = validate_target_url(target)
    method = method.upper()

    # 2b. DNS rebinding guard — resolve domain names at request time
    _parsed_host = urlparse(target).hostname or ""
    try:
        ipaddress.ip_address(_parsed_host)
        # IP literal — already validated syntactically in validate_target_url
    except ValueError:
        # Domain name — resolve and verify no address is in a private range
        await _check_no_private_dns(_parsed_host)

    # Detect free tier
    is_free = key_info.get("plan") == "free"

    if is_free:
        amount = 0.0
    else:
        amount = PROOF_PRICE  # Fixed price per proof for pro/test keys

    # 3. Check rate limit
    allowed, remaining = check_rate_limit(api_key)
    if not allowed:
        raise ProxyError("rate_limited", "Daily rate limit reached", 429)

    # 4. Check idempotency
    cached = _check_idempotency(idempotency_key)
    if cached is not None:
        return cached

    # 5. Hash request
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    request_data = {"target": target, "method": method, "payload": payload, "amount": amount, "currency": currency}

    # 6. Charge via payment provider (skip for free tier)
    target_domain = urlparse(target).hostname or "unknown"

    proof_id_for_debit = generate_proof_id()

    if is_free:
        charge_result = ChargeResult(
            provider="free_tier",
            transaction_id="free_tier",
            amount=0.0,
            currency=currency,
            status="free_tier",
            receipt_url=None,
        )
    else:
        # Prepaid credit deduction — atomic check+debit under per-key lock
        try:
            debit_id, new_balance = debit_credits(api_key, PROOF_PRICE, proof_id_for_debit)
        except InsufficientCredits as e:
            _notify_credits_exhausted(api_key, key_info)
            raise ProxyError(
                "insufficient_credits",
                f"Insufficient credits ({e.balance:.2f} EUR). Buy credits at /v1/credits/buy",
                402,
            )
        charge_result = ChargeResult(
            provider="prepaid_credit",
            transaction_id=debit_id,
            amount=PROOF_PRICE,
            currency="eur",
            status="succeeded",
            receipt_url=None,
        )
        # Warn if balance is now low (< 10 proofs remaining)
        _notify_low_credits_if_needed(api_key, key_info, new_balance)

    # Payment OK — from here, always return proof even on service error
    payment_data = {
        "method": charge_result.provider,
        "transaction_id": charge_result.transaction_id,
        "amount": charge_result.amount,
        "currency": charge_result.currency,
        "status": charge_result.status,
    }
    if charge_result.receipt_url:
        payment_data["receipt_url"] = charge_result.receipt_url

    # 6b. Fetch provider receipt if provider_payment provided
    receipt_content_hash = None
    provider_payment_record = None

    if provider_payment and isinstance(provider_payment, dict):
        pe_receipt_url = provider_payment.get("receipt_url", "")
        if pe_receipt_url:
            receipt_result = await fetch_receipt(pe_receipt_url)
            receipt_content_hash = receipt_result.receipt_content_hash
            provider_payment_record = {
                "type": provider_payment.get("type", receipt_result.receipt_type),
                "receipt_url": pe_receipt_url,
                "receipt_fetch_status": receipt_result.receipt_fetch_status,
                "receipt_content_hash": f"sha256:{receipt_content_hash}" if receipt_content_hash else None,
                "parsing_status": receipt_result.parsing_status,
                "parsed_fields": receipt_result.parsed_fields or None,
                "verification_status": "fetched" if receipt_result.receipt_fetch_status == "fetched" else "failed",
            }
            if receipt_result.receipt_fetch_error:
                provider_payment_record["receipt_fetch_error"] = receipt_result.receipt_fetch_error

    # 7. Forward to target service
    import time
    t0 = time.monotonic()
    service_response = None
    service_error = None
    service_status_code = None
    upstream_timestamp = None

    try:
        fwd_headers = {"X-Internal-Secret": INTERNAL_SECRET} if INTERNAL_SECRET else {}
        async with httpx.AsyncClient(timeout=PROXY_TIMEOUT_SECONDS) as client:
            if method == "GET":
                resp = await client.get(target, params=payload, headers=fwd_headers)
            else:
                resp = await client.post(target, json=payload, headers=fwd_headers)

            service_status_code = resp.status_code
            upstream_timestamp = resp.headers.get("Date")
            try:
                service_response = resp.json()
            except ValueError:
                body_text = resp.text[:MAX_RESPONSE_STORE_BYTES]
                service_response = {"_raw_text": body_text}

    except httpx.TimeoutException:
        service_error = "proxy_timeout"
    except (httpx.RequestError, OSError) as e:
        service_error = f"service_error: {str(e)}"

    response_time_ms = (time.monotonic() - t0) * 1000
    service_succeeded = service_status_code is not None and 200 <= service_status_code < 400

    # 8. Build response data for hashing
    response_data = service_response or {"error": service_error}

    # 9. Generate proof (with party identities)
    buyer_fingerprint = sha256_hex(api_key)
    seller = target_domain
    proof_id = proof_id_for_debit
    proof = generate_proof(request_data, response_data, payment_data, timestamp, buyer_fingerprint, seller,
                           agent_identity=agent_identity, agent_version=agent_version,
                           upstream_timestamp=upstream_timestamp,
                           receipt_content_hash=receipt_content_hash,
                           provider_payment=provider_payment_record)

    # Compute identity_consistent flag
    identity_consistent = None
    if agent_identity:
        agent_path = AGENTS_DIR / f"{api_key[:16]}.json"
        existing_profile = load_json(agent_path, {})
        existing_id = existing_profile.get("declared_identity")
        if existing_id and existing_id != agent_identity:
            identity_consistent = False
        elif existing_profile.get("identity_mismatch"):
            identity_consistent = False
        else:
            identity_consistent = True

    verification_url = f"{TRUST_LAYER_BASE_URL}/v1/proof/{proof_id}"
    proof_record = {
        "proof_id": proof_id,
        "spec_version": proof.get("spec_version"),
        "verification_url": verification_url,
        "verification_algorithm": "https://github.com/ark-forge/proof-spec/blob/main/SPEC.md#2-chain-hash-algorithm",
        "hashes": proof["hashes"],
        "parties": proof["parties"],
        "certification_fee": payment_data,
        "timestamp": timestamp,
        "timestamp_authority": {"status": "submitted", "provider": "freetsa.org", "tsr_url": f"{TRUST_LAYER_BASE_URL}/v1/proof/{proof_id}/tsr"},
        "identity_consistent": identity_consistent,
    }
    # Store upstream status for dispute resolution
    proof_record["transaction_success"] = service_succeeded
    if service_status_code is not None:
        proof_record["upstream_status_code"] = service_status_code
    if upstream_timestamp:
        proof_record["upstream_timestamp"] = upstream_timestamp
    if provider_payment_record:
        proof_record["provider_payment"] = provider_payment_record

    # Ed25519 signature: sign the chain hash to prove ArkForge origin
    chain_hash = proof["_raw_chain_hash"]
    signing_key = get_signing_key()
    if signing_key:
        proof_record["arkforge_signature"] = sign_proof(signing_key, chain_hash)
        proof_record["arkforge_pubkey"] = ARKFORGE_PUBLIC_KEY

    # 10. Store proof
    store_proof(proof_id, proof_record)

    # 11. Fire-and-forget background tasks (OTS, Archive.org, email)
    email = key_info.get("email", "")
    task = asyncio.create_task(_post_proof_background(proof_id, proof_record, chain_hash, verification_url, email))
    _track_task(task)

    # 13. Update shadow profiles
    _update_agent_profile(api_key, amount, currency, target_domain, service_succeeded,
                          agent_identity, agent_version)
    _update_service_profile(target_domain, response_time_ms, service_succeeded)

    # Scrub X-Internal-Secret from service response BEFORE returning to client.
    # Hash was already computed above (line generate_proof), so chain integrity is preserved.
    if service_response is not None:
        service_response = _scrub_internal_secret(service_response)

    # 14. Build response
    if service_error == "proxy_timeout":
        result = ProxyError("proxy_timeout", "Target service timed out", 504, proof=proof_record).to_dict()
    elif service_status_code and service_status_code >= 400:
        result = ProxyError(
            "service_error",
            f"Target returned HTTP {service_status_code}",
            502,
            proof=proof_record,
        ).to_dict()
        result["service_response"] = {"status_code": service_status_code, "body": service_response}
    elif service_error:
        result = ProxyError("service_error", service_error, 502, proof=proof_record).to_dict()
    else:
        result = {
            "proof": proof_record,
            "service_response": {
                "status_code": service_status_code,
                "body": service_response,
            },
        }

    # 14b. Level 1 — Digital Stamp (AFTER hashing, does NOT affect chain hash)
    _inject_digital_stamp(result, proof_record)

    # 15. Cache idempotency
    _cache_idempotency(idempotency_key, result)

    return result
