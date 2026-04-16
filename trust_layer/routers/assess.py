"""POST /v1/assess — MCP server security posture assessment.

Rate limiting: 100 assess calls/day per API key (separate from proof quota).
Auth: X-Api-Key header or Authorization: Bearer <key>.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse

from ..config import DATA_DIR, FUNNEL_EVENTS_LOG
from ..keys import validate_api_key
from ..mcp_assess import build_assessment, ASSESS_DAILY_LIMIT
from ..redis_client import get_redis

SCAN_EVENTS_LOG = DATA_DIR / "scan_events.jsonl"

logger = logging.getLogger("trust_layer.routers.assess")

router = APIRouter()


def _get_api_key(
    authorization: Optional[str] = None,
    x_api_key: Optional[str] = None,
) -> Optional[str]:
    if x_api_key:
        return x_api_key
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:]
    return None


def _fingerprint(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def _check_assess_rate_limit(fingerprint: str) -> bool:
    """Return True if request is allowed. Uses Redis INCR with daily TTL.

    Falls back to allowing the request if Redis is unavailable (fail-open,
    acceptable for v1 — an outage should not block security assessments).
    """
    r = get_redis()
    if r is None:
        return True
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    key = f"rate:assess:{fingerprint}:{today}"
    try:
        count = r.incr(key)
        if count == 1:
            r.expire(key, 86400)
        return count <= ASSESS_DAILY_LIMIT
    except Exception as e:
        logger.warning("Assess rate limit Redis error: %s", e)
        return True


def _error(code: str, message: str, status: int) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "status": status}},
    )


@router.post("/v1/assess")
async def assess_endpoint(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
) -> JSONResponse:
    """Assess an MCP server manifest for security posture.

    Analyzes tools for dangerous capability patterns, detects drift from
    the previous baseline, and tracks server version changes.

    Returns an assessment with risk_score (0-100) and categorized findings.
    The baseline is updated on every successful call.

    Rate limit: 100 calls/day per API key.
    """
    # --- Auth ---
    raw_key = _get_api_key(authorization, x_api_key)
    if not raw_key:
        return _error("missing_api_key", "X-Api-Key header required", 401)

    key_info = validate_api_key(raw_key)
    if not key_info:
        return _error("invalid_api_key", "Invalid or inactive API key", 401)

    fp = _fingerprint(raw_key)

    # --- Rate limit ---
    if not _check_assess_rate_limit(fp):
        return _error(
            "rate_limit_exceeded",
            f"Assess limit reached ({ASSESS_DAILY_LIMIT}/day). Resets at midnight UTC.",
            429,
        )

    # --- Parse body ---
    try:
        body = await request.json()
    except Exception:
        return _error("invalid_json", "Request body must be valid JSON", 400)

    server_id = body.get("server_id", "").strip()
    if not server_id:
        return _error("missing_field", "'server_id' is required", 400)

    manifest = body.get("manifest")
    if not manifest or not isinstance(manifest, dict):
        return _error("missing_field", "'manifest' object is required", 400)

    tools = manifest.get("tools")
    if not isinstance(tools, list):
        return _error("missing_field", "'manifest.tools' must be a list", 400)

    if len(tools) == 0:
        return _error("invalid_request", "'manifest.tools' must not be empty", 400)

    # Validate each tool has at minimum a name
    for i, tool in enumerate(tools):
        if not isinstance(tool, dict) or not tool.get("name"):
            return _error(
                "invalid_request",
                f"tools[{i}] must be an object with a 'name' field",
                400,
            )

    server_version: Optional[str] = body.get("server_version")

    # --- Build assessment ---
    try:
        assessment = build_assessment(fp, server_id, tools, server_version)
    except Exception as e:
        logger.error("Assessment failed for server_id=%s: %s", server_id, e)
        return _error("assessment_error", "Assessment failed. Please retry.", 500)

    # --- Log scan event for server-side analytics ---
    try:
        tool_names = [t.get("name", "") for t in tools]
        with open(SCAN_EVENTS_LOG, "a") as f:
            f.write(json.dumps({
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": "assess",
                "server_id": server_id,
                "tools_count": len(tools),
                "tool_names": tool_names,
                "risk_score": assessment.get("risk_score"),
                "key_hash": fp[:8],
                "plan": key_info.get("plan", "unknown"),
            }) + "\n")
    except Exception:
        pass  # non-critical

    # --- Log funnel event: CTA impression (register link shown in response) ---
    try:
        assess_id = assessment.get("assess_id", "")
        with open(FUNNEL_EVENTS_LOG, "a") as _f:
            _f.write(json.dumps({
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": "cta_impression",
                "assess_id": assess_id,
                "server_id": server_id,
                "key_hash": fp[:8],
                "plan": key_info.get("plan", "unknown"),
            }) + "\n")
    except Exception:
        pass

    return JSONResponse(status_code=200, content=assessment)
