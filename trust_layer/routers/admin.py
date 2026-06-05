"""Admin endpoints — smoke test lifecycle management (internal use only)."""
import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..config import (
    INTERNAL_SECRET,
    STRIPE_WEBHOOK_SECRET_LIVE,
    STRIPE_WEBHOOK_SECRET_TEST,
)
from ..keys import (
    create_api_key,
    deactivate_key_by_ref,
    deactivate_smoke_keys,
)

logger = logging.getLogger(__name__)
router = APIRouter()


def _authorized(request: Request) -> bool:
    if not INTERNAL_SECRET:
        return False
    return request.headers.get("X-Internal-Secret", "") == INTERNAL_SECRET


@router.post("/v1/admin/smoke/setup")
async def smoke_setup(request: Request) -> JSONResponse:
    """Create 4 ephemeral test keys and return them with the webhook secret.

    Protected by X-Internal-Secret header == TRUST_LAYER_INTERNAL_SECRET.
    """
    if not _authorized(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)

    fk = create_api_key("", "smoke_free", "smoke_free@smoke.invalid", plan="free")
    pk = create_api_key("cus_smoke", "smoke_pro", "smoke_pro@smoke.invalid", plan="pro")
    ik = create_api_key("", "smoke_inactive", "smoke_inactive@smoke.invalid", plan="free")
    wk = create_api_key("cus_smoke_wh", "sub_smoke_wh_001", "smoke_wh@smoke.invalid", plan="pro")

    deactivate_key_by_ref("smoke_inactive")
    deactivate_key_by_ref("sub_smoke_wh_001")

    ws = STRIPE_WEBHOOK_SECRET_LIVE or STRIPE_WEBHOOK_SECRET_TEST
    logger.info("smoke/setup: 4 ephemeral keys created")
    return JSONResponse({
        "free_key": fk,
        "pro_key": pk,
        "inactive_key": ik,
        "webhook_key": wk,
        "webhook_secret": ws,
    })


@router.post("/v1/admin/smoke/teardown")
async def smoke_teardown(request: Request) -> JSONResponse:
    """Deactivate all smoke test keys created by /v1/admin/smoke/setup."""
    if not _authorized(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)

    deactivated = deactivate_smoke_keys()
    logger.info("smoke/teardown: %d keys deactivated", len(deactivated))
    return JSONResponse({"deactivated": deactivated, "count": len(deactivated)})
