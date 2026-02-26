"""Core proxy logic — charge, forward, prove."""

import asyncio
import hashlib
import ipaddress
import logging
import os
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx

from .config import (
    SUPPORTED_CURRENCIES,
    MIN_AMOUNT,
    MAX_AMOUNT,
    PROXY_TIMEOUT_SECONDS,
    MAX_RESPONSE_STORE_BYTES,
    IDEMPOTENCY_DIR,
    IDEMPOTENCY_TTL_HOURS,
    TRUST_LAYER_BASE_URL,
    AGENTS_DIR,
    SERVICES_DIR,
)
from .keys import validate_api_key
from .payments import get_provider
from .payments.base import ChargeResult
from .proofs import sha256_hex, generate_proof_id, generate_proof, store_proof
from .persistence import load_json, save_json
from .rate_limit import check_rate_limit
from .timestamps import submit_hash
from .email_notify import send_proof_email

logger = logging.getLogger("trust_layer.proxy")


async def _submit_archive_org(proof_url: str, proof_id: str) -> Optional[dict]:
    """Submit proof page to Archive.org Wayback Machine (best-effort, async)."""
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(
                f"https://web.archive.org/save/{proof_url}",
                headers={"User-Agent": "ArkForge Trust Layer (+https://arkforge.fr)"},
            )
        if resp.status_code < 400:
            snapshot_url = resp.headers.get("Content-Location") or resp.headers.get("Location")
            if snapshot_url and not snapshot_url.startswith("http"):
                snapshot_url = f"https://web.archive.org{snapshot_url}"
            return {
                "status": "submitted",
                "snapshot_url": snapshot_url or f"https://web.archive.org/web/{proof_url}",
                "submitted_at": datetime.now(timezone.utc).isoformat(),
            }
        logger.warning("Archive.org returned %d for %s", resp.status_code, proof_id)
        return None
    except Exception as e:
        logger.warning("Archive.org submit skipped for %s: %s", proof_id, e)
        return None


async def _post_proof_background(proof_id: str, proof_record: dict, chain_hash: str,
                                  verification_url: str, email: str):
    """Background task: TSA + Archive.org + email — none of these block the client response."""
    # RFC 3161 Timestamp (sync but run in thread to avoid blocking event loop)
    try:
        loop = asyncio.get_running_loop()
        tsr_bytes = await loop.run_in_executor(None, submit_hash, chain_hash)
        if tsr_bytes:
            from .config import PROOFS_DIR
            (PROOFS_DIR / f"{proof_id}.tsr").write_bytes(tsr_bytes)
            proof_record["timestamp_authority"]["status"] = "verified"
            store_proof(proof_id, proof_record)
            logger.info("TSA timestamp verified for %s", proof_id)
    except Exception as e:
        logger.warning("TSA submit skipped: %s", e)

    # Archive.org
    try:
        result = await _submit_archive_org(verification_url, proof_id)
        if result:
            proof_record["archive_org"] = result
            store_proof(proof_id, proof_record)
            logger.info("Archive.org snapshot saved for %s", proof_id)
    except Exception as e:
        logger.warning("Archive.org background task failed for %s: %s", proof_id, e)

    # Email
    if email:
        try:
            await asyncio.get_running_loop().run_in_executor(
                None, send_proof_email, email, proof_id, proof_record)
        except Exception as e:
            logger.warning("Proof email skipped: %s", e)


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


def _cache_idempotency(key: Optional[str], response: dict):
    """Cache response for idempotency key."""
    if not key:
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
    # Track declared identity — detect mismatches (same key, different identity)
    if agent_identity:
        existing = profile.get("declared_identity")
        if existing and existing != agent_identity:
            profile["identity_mismatch"] = True
        profile["declared_identity"] = agent_identity
    if agent_version:
        profile["declared_version"] = agent_version
    save_json(path, profile)


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
) -> dict:
    """Execute the full proxy flow: validate → charge → forward → prove."""

    # 1. Validate API key
    key_info = validate_api_key(api_key)
    if not key_info:
        raise ProxyError("invalid_api_key", "Invalid or inactive API key", 401)

    # 2. Validate inputs
    currency = validate_currency(currency)
    amount = validate_amount(amount)
    target = validate_target_url(target)
    method = method.upper()

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

    # 6. Charge via payment provider
    target_domain = urlparse(target).hostname or "unknown"
    provider = get_provider(api_key)
    customer_id = key_info.get("stripe_customer_id", "")
    if not customer_id:
        raise ProxyError("invalid_api_key", "No payment method linked to this API key", 400)

    try:
        charge_result: ChargeResult = await provider.charge(
            amount=amount,
            currency=currency,
            customer_id=customer_id,
            description=description or f"ArkForge proxy: {target_domain}",
            metadata={
                "product": "trust_layer_proxy",
                "target_domain": target_domain,
                "api_key_prefix": api_key[:12],
            },
        )
    except Exception as e:
        logger.error("Payment failed: %s", e)
        raise ProxyError("payment_failed", f"Payment failed: {str(e)}", 402)

    if charge_result.status != "succeeded":
        raise ProxyError("payment_failed", f"Payment status: {charge_result.status}", 402)

    # Payment OK — from here, always return proof even on service error
    payment_data = {
        "provider": charge_result.provider,
        "transaction_id": charge_result.transaction_id,
        "amount": charge_result.amount,
        "currency": charge_result.currency,
        "status": charge_result.status,
        "receipt_url": charge_result.receipt_url,
    }

    # 7. Forward to target service
    import time
    t0 = time.monotonic()
    service_response = None
    service_error = None
    service_status_code = None

    try:
        fwd_headers = {"X-Internal-Secret": os.environ.get("TRUST_LAYER_INTERNAL_SECRET", "")}
        async with httpx.AsyncClient(timeout=PROXY_TIMEOUT_SECONDS) as client:
            if method == "GET":
                resp = await client.get(target, params=payload, headers=fwd_headers)
            else:
                resp = await client.post(target, json=payload, headers=fwd_headers)

            service_status_code = resp.status_code
            try:
                service_response = resp.json()
            except Exception:
                body_text = resp.text[:MAX_RESPONSE_STORE_BYTES]
                service_response = {"_raw_text": body_text}

    except httpx.TimeoutException:
        service_error = "proxy_timeout"
    except Exception as e:
        service_error = f"service_error: {str(e)}"

    response_time_ms = (time.monotonic() - t0) * 1000
    service_succeeded = service_status_code is not None and 200 <= service_status_code < 400

    # 8. Build response data for hashing
    response_data = service_response or {"error": service_error}

    # 9. Generate proof (with party identities)
    buyer_fingerprint = sha256_hex(api_key)
    seller = target_domain
    proof_id = generate_proof_id()
    proof = generate_proof(request_data, response_data, payment_data, timestamp, buyer_fingerprint, seller,
                           agent_identity=agent_identity, agent_version=agent_version)

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
        "verification_url": verification_url,
        "verification_algorithm": f"{TRUST_LAYER_BASE_URL}/docs/verification",
        "hashes": proof["hashes"],
        "parties": proof["parties"],
        "payment": payment_data,
        "timestamp": timestamp,
        "timestamp_authority": {"status": "submitted", "provider": "freetsa.org", "tsr_url": f"{TRUST_LAYER_BASE_URL}/v1/proof/{proof_id}/tsr"},
        "identity_consistent": identity_consistent,
    }

    # 10. Store proof
    store_proof(proof_id, proof_record)

    # 11. Fire-and-forget background tasks (OTS, Archive.org, email)
    chain_hash = proof["_raw_chain_hash"]
    email = key_info.get("email", "")
    asyncio.create_task(_post_proof_background(proof_id, proof_record, chain_hash, verification_url, email))

    # 13. Update shadow profiles
    _update_agent_profile(api_key, amount, currency, target_domain, service_succeeded,
                          agent_identity, agent_version)
    _update_service_profile(target_domain, response_time_ms, service_succeeded)

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
