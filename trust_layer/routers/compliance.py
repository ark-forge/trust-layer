"""POST /v1/compliance-report — EU AI Act compliance report.

Aggregates proofs for the authenticated API key over a date range and maps
them to compliance framework articles.

Auth: X-Api-Key header or Authorization: Bearer <key>.
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse

from ..compliance import get_framework, list_frameworks, _article_dict
from ..keys import validate_api_key
from ..proof_index import get_proof_index

logger = logging.getLogger("trust_layer.routers.compliance")

router = APIRouter()

_MAX_PROOFS_PER_REPORT = 10_000  # safety cap to prevent runaway queries


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


def _error(code: str, message: str, status: int) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "status": status}},
    )


def _parse_iso(s: str, field_name: str) -> tuple[Optional[datetime], Optional[JSONResponse]]:
    """Parse ISO 8601 date string, return (datetime, None) or (None, error response)."""
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt, None
    except (ValueError, TypeError):
        return None, _error(
            "invalid_date",
            f"'{field_name}' must be a valid ISO 8601 date (e.g. 2026-01-01 or 2026-01-01T00:00:00Z)",
            400,
        )


@router.post("/v1/compliance-report")
async def compliance_report_endpoint(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
) -> JSONResponse:
    """Generate a compliance report for all proofs in a date range.

    Aggregates proofs certified under this API key and maps them to the
    requested compliance framework's articles.

    Supported frameworks: eu_ai_act

    Returns article-level coverage with status (covered/partial/gap/not_applicable),
    evidence summaries, and a gaps list for remediation planning.
    """
    # --- Auth ---
    raw_key = _get_api_key(authorization, x_api_key)
    if not raw_key:
        return _error("missing_api_key", "X-Api-Key header required", 401)

    key_info = validate_api_key(raw_key)
    if not key_info:
        return _error("invalid_api_key", "Invalid or inactive API key", 401)

    fp = _fingerprint(raw_key)

    # --- Parse body ---
    try:
        body = await request.json()
    except Exception:
        return _error("invalid_json", "Request body must be valid JSON", 400)

    framework_name = body.get("framework", "eu_ai_act")
    if not isinstance(framework_name, str):
        return _error("invalid_field", "'framework' must be a string", 400)

    framework = get_framework(framework_name)
    if framework is None:
        available = ", ".join(list_frameworks())
        return _error(
            "unknown_framework",
            f"Unknown framework '{framework_name}'. Available: {available}",
            400,
        )

    date_from_str = body.get("date_from", "")
    date_to_str = body.get("date_to", "")
    if not date_from_str:
        return _error("missing_field", "'date_from' is required (ISO 8601)", 400)
    if not date_to_str:
        return _error("missing_field", "'date_to' is required (ISO 8601)", 400)

    dt_from, err = _parse_iso(date_from_str, "date_from")
    if err:
        return err
    dt_to, err = _parse_iso(date_to_str, "date_to")
    if err:
        return err

    if dt_from >= dt_to:  # type: ignore[operator]
        return _error("invalid_range", "'date_from' must be before 'date_to'", 400)

    from_unix = dt_from.timestamp()  # type: ignore[union-attr]
    to_unix = dt_to.timestamp()  # type: ignore[union-attr]

    # --- Query proof index ---
    try:
        proof_ids = get_proof_index().query(fp, from_unix, to_unix)
    except Exception as e:
        logger.error("Proof index query failed: %s", e)
        proof_ids = []

    # Cap results to prevent runaway
    proof_ids = proof_ids[:_MAX_PROOFS_PER_REPORT]

    # Determine coverage_since (earliest timestamp in the full index)
    coverage_since: Optional[str] = None
    try:
        all_ids = get_proof_index().query(fp, 0, 9999999999)
        if all_ids:
            # We can't easily get the min timestamp without loading proofs,
            # so we just signal that coverage exists
            coverage_since = "indexed"
    except Exception:
        pass

    date_range = {
        "from": dt_from.isoformat(),  # type: ignore[union-attr]
        "to": dt_to.isoformat(),  # type: ignore[union-attr]
    }

    # --- Generate report ---
    try:
        report = framework.generate_report(proof_ids, date_range, coverage_since)
    except Exception as e:
        logger.error("Compliance report generation failed: %s", e)
        return _error("report_error", "Report generation failed. Please retry.", 500)

    # --- Serialize ---
    response_body = {
        "report_id": report.report_id,
        "framework": report.framework,
        "framework_version": report.framework_version,
        "date_range": report.date_range,
        "proof_count": report.proof_count,
        "articles": [_article_dict(a) for a in report.articles],
        "gaps": report.gaps,
        "summary": report.summary,
    }
    if report.coverage_since:
        response_body["coverage_since"] = report.coverage_since

    return JSONResponse(status_code=200, content=response_body)
