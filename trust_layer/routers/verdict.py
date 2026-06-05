"""POST /v1/verdict/tier-upgrade — CTEF tier_upgrade_proof endpoint."""

import hashlib
import json
import logging
from typing import Optional

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..config import get_signing_key
from ..keys import validate_api_key
from ..ctef import build_tier_upgrade_verdict, GATEWAY_DID

logger = logging.getLogger("trust_layer.routers.verdict")

router = APIRouter()

VALID_TRANSITIONS = {("T1", "T2"), ("T2", "T3")}


def _get_api_key(authorization=None, x_api_key=None):
    if x_api_key:
        return x_api_key
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:]
    return None


def _error(code: str, message: str, status: int) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "status": status}},
    )


class TierUpgradeRequest(BaseModel):
    requester_did: str = Field(..., description="DID of the requesting agent")
    current_tier: str = Field(..., description="Current tier (e.g. T1)")
    requested_tier: str = Field(..., description="Requested tier (e.g. T2)")
    facet: str = Field(..., description="Action facet being authorized")
    limit: int = Field(..., ge=0, description="Authorized limit for the facet")
    actual: int = Field(0, ge=0, description="Current actual usage (default 0)")
    session_id: str = Field(..., description="Session scope boundary (replay protection)")
    policy_ref: Optional[str] = Field(None, description="sha256:hex of evaluated policy. Auto-computed if omitted.")
    ttl_minutes: int = Field(60, ge=1, le=1440, description="Verdict TTL in minutes")


@router.post("/v1/verdict/tier-upgrade")
async def tier_upgrade_verdict(
    body: TierUpgradeRequest,
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
) -> JSONResponse:
    """Issue a CTEF tier_upgrade_proof verdict signed by did:web:trust.arkforge.tech#key-1."""
    api_key = _get_api_key(authorization, x_api_key)
    if not api_key:
        return _error("invalid_api_key", "API key required.", 401)
    if not validate_api_key(api_key):
        return _error("invalid_api_key", "Invalid or inactive API key.", 401)

    if (body.current_tier, body.requested_tier) not in VALID_TRANSITIONS:
        return _error(
            "invalid_transition",
            f"Transition {body.current_tier} -> {body.requested_tier} not allowed.",
            422,
        )

    if body.actual > body.limit:
        return _error("constraint_violation", "actual must not exceed limit.", 422)

    signing_key = get_signing_key()
    if signing_key is None:
        logger.error("Signing key unavailable for verdict request")
        return _error("signing_unavailable", "Signing key not configured.", 503)

    policy_ref = body.policy_ref
    if not policy_ref:
        policy_obj = {"facet": body.facet, "max_tier": body.requested_tier, "allowed": True}
        policy_bytes = json.dumps(policy_obj, sort_keys=True, separators=(",", ":")).encode()
        policy_ref = f"sha256:{hashlib.sha256(policy_bytes).hexdigest()}"

    try:
        result = build_tier_upgrade_verdict(
            private_key=signing_key,
            requester_did=body.requester_did,
            current_tier=body.current_tier,
            requested_tier=body.requested_tier,
            facet=body.facet,
            limit=body.limit,
            actual=body.actual,
            session_id=body.session_id,
            policy_ref=policy_ref,
            ttl_minutes=body.ttl_minutes,
        )
    except Exception as exc:
        logger.exception("Verdict signing failed")
        return _error("signing_error", f"Failed to sign verdict: {exc}", 500)

    logger.info(
        "Tier upgrade issued: %s->%s for %s (session=%s)",
        body.current_tier, body.requested_tier, body.requester_did[:50], body.session_id[:40],
    )
    return JSONResponse(status_code=200, content={"ok": True, "gateway_did": GATEWAY_DID, **result})
