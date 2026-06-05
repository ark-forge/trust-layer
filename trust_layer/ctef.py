"""CTEF tier_upgrade_proof envelope builder (Row 8 — urn:arkforge:verdict)."""

import hashlib
import json
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import sign_jws

GATEWAY_DID = "did:web:trust.arkforge.tech"
KEY_ID = f"{GATEWAY_DID}#key-1"


def _jcs(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def build_tier_upgrade_verdict(
    private_key: Ed25519PrivateKey,
    requester_did: str,
    current_tier: str,
    requested_tier: str,
    facet: str,
    limit: int,
    actual: int,
    session_id: str,
    policy_ref: str,
    ttl_minutes: int = 60,
) -> dict:
    """Build and sign a CTEF tier_upgrade_proof envelope.

    Returns: ctef_envelope, envelope_sha256, envelope_jcs_bytes, verdict_jws.
    The verdict_jws is a compact EdDSA/Ed25519 JWS verifiable against GATEWAY_DID#key-1.
    """
    now = datetime.now(timezone.utc)
    issued_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    valid_until = (now + timedelta(minutes=ttl_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")

    jws_payload = {
        "certified": True,
        "issuer_did": GATEWAY_DID,
        "issued_at": issued_at,
        "constraint_evaluation": {
            "facet": facet,
            "limit": limit,
            "actual": actual,
            "delta": limit - actual,
        },
        "requester_did": requester_did,
        "scope_boundary": session_id,
        "policy_ref": policy_ref,
    }

    verdict_jws = sign_jws(
        private_key,
        {"alg": "EdDSA", "kid": KEY_ID},
        jws_payload,
    )

    ctef_envelope = {
        "claim_type": "authority",
        "claim_subtype": "tier_upgrade",
        "issuer": GATEWAY_DID,
        "issued_at": issued_at,
        "tier_upgrade_proof": {
            "from_tier": current_tier,
            "to_tier": requested_tier,
            "intent_code": "TIER_UPGRADE_REQUEST",
            "requester_did": requester_did,
            "requested_action": {"facet": facet, "limit": limit, "actual": actual},
            "approval_evidence": {
                "verdict_jws": verdict_jws,
                "approver_did": GATEWAY_DID,
                "evaluated_at": issued_at,
                "policy_ref": policy_ref,
            },
            "validity": {
                "valid_until": valid_until,
                "scope_boundary": session_id,
                "use_count_max": 1,
            },
        },
    }

    canonical = _jcs(ctef_envelope)
    return {
        "ctef_envelope": ctef_envelope,
        "envelope_sha256": hashlib.sha256(canonical).hexdigest(),
        "envelope_jcs_bytes": len(canonical),
        "verdict_jws": verdict_jws,
    }
