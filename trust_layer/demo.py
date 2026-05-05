"""Public demo endpoint logic — no auth, no upstream fetch, no billing.

Generates a cryptographically signed proof for any target URL using a synthetic
response, allowing prospects to test non-repudiation without an API key.
"""

import time
from collections import defaultdict
from datetime import datetime, timezone

from .proofs import generate_proof_id, generate_proof, store_proof
from .crypto import sign_proof
from .config import get_signing_key, ARKFORGE_PUBLIC_KEY, TRUST_LAYER_BASE_URL

_DEMO_RATE_LIMIT = 10      # max demos per IP per window
_DEMO_WINDOW_S = 3600      # 1-hour fixed window
_PAYLOAD_MAX_BYTES = 4096

_SYNTHETIC_RESPONSE = {
    "demo": True,
    "synthetic": True,
    "note": "No upstream call was made. This is a demo proof.",
}

_demo_fallback: dict[str, list[float]] = defaultdict(list)


def check_demo_rate_limit(ip: str) -> tuple[bool, int]:
    """Increment demo counter and return (is_rate_limited, retry_after_seconds).

    Redis-first (fixed window), in-memory sliding window fallback.
    """
    from .redis_client import get_redis
    try:
        r = get_redis()
        if r is not None:
            key = f"demo_count:{ip}"
            count = r.incr(key)
            if count == 1:
                r.expire(key, _DEMO_WINDOW_S)
            if count > _DEMO_RATE_LIMIT:
                ttl = r.ttl(key)
                return True, max(int(ttl), 1)
            return False, 0
    except Exception:
        pass

    # Sliding window in-memory fallback
    now = time.monotonic()
    cutoff = now - _DEMO_WINDOW_S
    _demo_fallback[ip] = [t for t in _demo_fallback[ip] if t > cutoff]
    if len(_demo_fallback[ip]) >= _DEMO_RATE_LIMIT:
        oldest = min(_demo_fallback[ip])
        retry_after = int(_DEMO_WINDOW_S - (now - oldest)) + 1
        return True, max(retry_after, 1)
    _demo_fallback[ip].append(now)
    return False, 0


def build_demo_proof(target: str, payload: dict) -> dict:
    """Build, sign, and persist a demo proof without upstream fetch.

    The synthetic response is hashed (not fetched) — chain integrity is real,
    upstream call is not. Returns the full proof_record (same structure as real
    proofs, with is_demo=True).
    """
    proof_id = generate_proof_id()
    timestamp = datetime.now(timezone.utc).isoformat()

    request_data = {"target": target, "payload": payload, "method": "POST"}
    payment_data = {
        "transaction_id": "",
        "amount": 0,
        "currency": "eur",
        "status": "demo",
        "method": "demo",
    }

    proof = generate_proof(
        request_data=request_data,
        response_data=_SYNTHETIC_RESPONSE,
        payment_data=payment_data,
        timestamp=timestamp,
        buyer_fingerprint="",
        seller="demo",
    )

    chain_hash = proof["_raw_chain_hash"]
    verification_url = f"{TRUST_LAYER_BASE_URL}/v1/proof/{proof_id}"

    proof_record: dict = {
        "proof_id": proof_id,
        "is_demo": True,
        "spec_version": proof["spec_version"],
        "verification_url": verification_url,
        "verification_algorithm": (
            "https://github.com/ark-forge/proof-spec/blob/main/SPEC.md"
            "#2-chain-hash-algorithm"
        ),
        "hashes": proof["hashes"],
        "parties": {
            "buyer_fingerprint": "",
            "seller": "demo",
            "agent_identity": None,
            "agent_identity_verified": None,
            "did_resolution_status": None,
            "agent_version": None,
        },
        "certification_fee": payment_data,
        "timestamp": timestamp,
        "timestamp_authority": {
            "status": "submitted",
            "provider": "freetsa.org",
            "tsr_url": f"{verification_url}/tsr",
        },
        "transaction_success": True,
        "upstream_status_code": 200,
        "identity_consistent": None,
        "_raw_chain_hash": chain_hash,
    }

    signing_key = get_signing_key()
    if signing_key:
        proof_record["arkforge_signature"] = sign_proof(signing_key, chain_hash)
        proof_record["arkforge_pubkey"] = ARKFORGE_PUBLIC_KEY

    store_proof(proof_id, proof_record)
    return proof_record
