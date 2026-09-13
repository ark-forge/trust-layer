"""Admin endpoints — smoke test lifecycle and batch anchoring (internal use only)."""
import asyncio
import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..config import INTERNAL_SECRET
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
    """Create 4 ephemeral test keys and return them.

    Protected by X-Internal-Secret header == TRUST_LAYER_INTERNAL_SECRET.

    Never returns the Stripe webhook signing secret: a caller able to read it
    can forge signed Stripe events and mint arbitrary paid keys. The smoke test
    reads it from its own environment instead (TRUST_LAYER_SMOKE_WEBHOOK_SECRET).
    """
    if not _authorized(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)

    fk = create_api_key("", "smoke_free", "smoke_free@smoke.invalid", plan="free")
    pk = create_api_key("cus_smoke", "smoke_pro", "smoke_pro@smoke.invalid", plan="pro")
    ik = create_api_key("", "smoke_inactive", "smoke_inactive@smoke.invalid", plan="free")
    wk = create_api_key("cus_smoke_wh", "sub_smoke_wh_001", "smoke_wh@smoke.invalid", plan="pro")

    deactivate_key_by_ref("smoke_inactive")
    deactivate_key_by_ref("sub_smoke_wh_001")

    logger.info("smoke/setup: 4 ephemeral keys created")
    return JSONResponse({
        "free_key": fk,
        "pro_key": pk,
        "inactive_key": ik,
        "webhook_key": wk,
    })


@router.post("/v1/admin/smoke/teardown")
async def smoke_teardown(request: Request) -> JSONResponse:
    """Deactivate all smoke test keys created by /v1/admin/smoke/setup."""
    if not _authorized(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)

    deactivated = deactivate_smoke_keys()
    logger.info("smoke/teardown: %d keys deactivated", len(deactivated))
    return JSONResponse({"deactivated": deactivated, "count": len(deactivated)})


@router.post("/v1/admin/batch/close")
async def batch_close(request: Request) -> JSONResponse:
    """Anchor the pending batch now instead of waiting for size or age.

    Protected by X-Internal-Secret. Two legitimate callers: the deployment smoke
    test, which must observe a real anchor rather than wait out the batch window
    (a gate that stops measuring the anchor is a decoy), and an operator wanting
    everything anchored before a maintenance window.

    Returns 200 with anchored=false when there was nothing pending — closing an
    empty batch is not an error, and an empty tree has no root to anchor.
    """
    if not _authorized(request):
        return JSONResponse({"error": "forbidden"}, status_code=403)

    from ..batch_anchor import close_batch
    record = await asyncio.get_running_loop().run_in_executor(
        None, close_batch, "admin")
    if not record:
        return JSONResponse({"anchored": False, "reason": "no pending batch"})
    logger.info("admin/batch/close: %s anchored, %d proofs",
                record["batch_id"], record["tree_size"])
    return JSONResponse({
        "anchored": True,
        "batch_id": record["batch_id"],
        "tree_size": record["tree_size"],
        "root": record["root"],
        "timestamp_authority": record["timestamp_authority"].get("status"),
        "transparency_log": record["transparency_log"].get("status"),
    })
