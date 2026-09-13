"""Batch anchoring — one TSA request and one Rekor entry per batch, not per proof.

Before: every proof fired its own RFC 3161 request and its own Sigstore Rekor
entry. Rekor is an OpenSSF common good; writing one permanent entry per
transaction into a public log someone else pays for does not scale and is not
ours to do.

Now: chain hashes accumulate in a pending batch. The batch closes at
``BATCH_MAX_SIZE`` proofs or ``BATCH_MAX_AGE_SECONDS``, whichever comes first,
and only the Merkle root of the batch is anchored. Each proof then carries its
own inclusion proof against that root::

    chain hash --audit path--> batch root --TSA + Rekor--> anchored

The anchor artefacts (``tsr_base64``, the Rekor entry, the audit path) are
embedded in each proof rather than served from a batch endpoint: a few KB
duplicated buys a third party who needs nothing but the proof itself, and adds
no HTTP surface.

Two things this module does not get to be naive about:

  - **the pending batch lives on disk, written atomically.** Same lesson as a
    grace period anchored on the process: a restart must neither lose the batch
    nor reopen it, and a truncated state reads back as an empty one.
  - **closing is driven by a background tick, not by the next request.** A batch
    opened at 23:00 on a quiet night must not wait for morning traffic.

Between creation and closing a proof has no external anchor. That state is
``pending``, and it is reported as pending — never as tampered.
"""

import base64
import logging
import threading
from datetime import datetime, timezone
from typing import List, Optional

from .config import DATA_DIR, PROOFS_DIR
from .merkle import audit_path, leaf_hash, merkle_root
from .persistence import load_json, save_json
from .proofs import load_proof, store_proof

logger = logging.getLogger("trust_layer.batch_anchor")

BATCH_MAX_SIZE = 100
BATCH_MAX_AGE_SECONDS = 600  # 10 minutes
BATCH_TICK_SECONDS = 30

BATCHES_DIR = DATA_DIR / "batches"
PENDING_FILE = BATCHES_DIR / "pending.json"
# A batch being closed lives here until every proof is stamped. Anchoring takes
# seconds of network: a crash in that window must not evaporate the batch.
CLOSING_DIR = BATCHES_DIR / "closing"

# One process owns the pending batch; the lock keeps a request thread and the
# background tick from closing it twice.
_lock = threading.Lock()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _new_batch_id() -> str:
    return "batch_" + _now().strftime("%Y%m%d_%H%M%S_%f")[:-3]


def _load_pending() -> dict:
    state = load_json(PENDING_FILE, {})
    if not isinstance(state, dict) or "entries" not in state:
        return {}
    return state


def _save_pending(state: dict) -> None:
    save_json(PENDING_FILE, state)


def _clear_pending() -> None:
    try:
        PENDING_FILE.unlink()
    except FileNotFoundError:
        pass


def add_proof(proof_id: str, chain_hash: str, plan: str = "") -> dict:
    """Queue a proof's chain hash for the next batch anchor.

    Returns the pending descriptor written into the proof. Closes the batch
    immediately if it reaches BATCH_MAX_SIZE.

    A batch mixes plans, so its TSA routing is the most demanding one any member
    asks for: one ``platform`` proof sends the whole batch to DigiCert. Monotone
    on purpose — nobody's timestamp guarantee is downgraded by a neighbour.
    """
    with _lock:
        state = _load_pending()
        if not state:
            state = {"batch_id": _new_batch_id(), "opened_at": _now().isoformat(),
                     "plan": "", "entries": []}
        if plan == "platform":
            state["plan"] = "platform"
        if any(e["proof_id"] == proof_id for e in state["entries"]):
            _save_pending(state)
            return {"status": "pending", "batch_id": state["batch_id"]}
        state["entries"].append({"proof_id": proof_id, "chain_hash": chain_hash})
        _save_pending(state)
        full = len(state["entries"]) >= BATCH_MAX_SIZE
        descriptor = {"status": "pending", "batch_id": state["batch_id"]}
    if full:
        close_batch(reason="size")
    return descriptor


def pending_age_seconds() -> Optional[float]:
    """Age of the open batch in seconds, or None if no batch is open."""
    state = _load_pending()
    if not state or not state.get("entries"):
        return None
    try:
        opened = datetime.fromisoformat(state["opened_at"])
    except (KeyError, ValueError):
        return None
    return (_now() - opened).total_seconds()


def close_due_batch() -> Optional[dict]:
    """Close the pending batch if it is older than BATCH_MAX_AGE_SECONDS."""
    age = pending_age_seconds()
    if age is None or age < BATCH_MAX_AGE_SECONDS:
        return None
    return close_batch(reason="age")


def close_batch(reason: str = "manual") -> Optional[dict]:
    """Build the Merkle root of the pending batch, anchor it, stamp every proof.

    Returns the batch record, or None if there was nothing to anchor. Anchoring
    an empty batch is never attempted: an empty tree has no root.
    """
    with _lock:
        state = _load_pending()
        entries = state.get("entries") or []
        if not entries:
            return None
        # Move, never drop: the batch is durable from here until it is stamped.
        state["reason"] = reason
        save_json(CLOSING_DIR / f"{state['batch_id']}.json", state)
        _clear_pending()

    return _anchor_closing_batch(state)


def _anchor_closing_batch(state: dict) -> dict:
    """Anchor a batch already moved to CLOSING_DIR, then stamp its proofs.

    Idempotent: re-running it re-anchors and re-stamps, which costs one extra TSA
    request and one extra Rekor entry but never loses a proof. Only the final
    unlink of the closing file ends the batch.
    """
    reason = state.get("reason", "manual")
    entries = state["entries"]
    batch_id = state["batch_id"]
    leaves = [leaf_hash(bytes.fromhex(e["chain_hash"])) for e in entries]
    root = merkle_root(leaves).hex()
    logger.info("Closing %s (%s): %d proofs, root %s", batch_id, reason, len(entries), root[:16])

    tsa = _anchor_tsa(root, state.get("plan", ""))
    rekor = _anchor_rekor(root)

    record = {
        "batch_id": batch_id,
        "opened_at": state.get("opened_at"),
        "closed_at": _now().isoformat(),
        "reason": reason,
        "plan": state.get("plan", ""),
        "tree_size": len(entries),
        "root": f"sha256:{root}",
        "entries": [e["proof_id"] for e in entries],
        "timestamp_authority": tsa,
        "transparency_log": rekor,
    }
    save_json(BATCHES_DIR / f"{batch_id}.json", record)

    for index, entry in enumerate(entries):
        _stamp_proof(entry["proof_id"], batch_id, index, len(entries),
                     [h.hex() for h in audit_path(index, leaves)], root, tsa, rekor)
    try:
        (CLOSING_DIR / f"{batch_id}.json").unlink()
    except FileNotFoundError:
        pass
    return record


def recover_closing_batches() -> int:
    """Re-drive every batch left mid-close by a crash. Returns how many were finished.

    Called at startup. Without it a batch interrupted between "pending cleared"
    and "proofs stamped" would leave its proofs pending forever: spec 3.0 never
    sets timestamp_authority.status to "submitted", so the older TSA recovery
    never sees them.
    """
    recovered = 0
    for path in sorted(CLOSING_DIR.glob("batch_*.json")) if CLOSING_DIR.exists() else []:
        state = load_json(path, {})
        if not state.get("entries"):
            path.unlink(missing_ok=True)
            continue
        logger.warning("Recovering batch %s left mid-close (%d proofs)",
                       state.get("batch_id"), len(state["entries"]))
        try:
            _anchor_closing_batch(state)
            recovered += 1
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Batch %s recovery failed: %s", state.get("batch_id"), e)
    return recovered


def _anchor_tsa(root: str, plan: str = "") -> dict:
    """One RFC 3161 request for the whole batch."""
    from .timestamps import submit_hash
    try:
        result = submit_hash(root, plan=plan)
    except (OSError, ValueError, RuntimeError) as e:
        logger.warning("Batch TSA failed: %s", e)
        return {"status": "failed", "error": str(e)[:200]}
    if not result:
        return {"status": "failed", "error": "all TSA servers failed"}
    tsr_bytes, provider = result
    return {
        "status": "verified",
        "provider": provider,
        "tsr_base64": base64.b64encode(tsr_bytes).decode("ascii"),
    }


def _anchor_rekor(root: str) -> dict:
    """One Sigstore Rekor entry for the whole batch."""
    from .rekor import submit_to_rekor
    try:
        return submit_to_rekor(root)
    except Exception as e:  # rekor.submit_to_rekor already swallows most of it
        logger.warning("Batch Rekor failed: %s", e)
        return {"provider": "sigstore-rekor", "status": "failed",
                "error": "transparency log temporarily unavailable"}


def _stamp_proof(proof_id: str, batch_id: str, index: int, tree_size: int,
                 path: List[str], root: str, tsa: dict, rekor: dict) -> None:
    """Write the inclusion proof and the anchor artefacts into one proof."""
    proof = load_proof(proof_id)
    if not proof:
        logger.warning("Batch %s: proof %s vanished before stamping", batch_id, proof_id)
        return
    proof["batch_anchor"] = {
        "status": "anchored",
        "batch_id": batch_id,
        "leaf_index": index,
        "tree_size": tree_size,
        "audit_path": path,
        "root": f"sha256:{root}",
    }
    proof["timestamp_authority"] = dict(tsa, anchored="batch_root")
    proof["transparency_log"] = dict(rekor, anchored="batch_root")
    if tsa.get("tsr_base64"):
        try:
            (PROOFS_DIR / f"{proof_id}.tsr").write_bytes(base64.b64decode(tsa["tsr_base64"]))
        except OSError as e:
            logger.warning("Batch %s: cannot write .tsr for %s: %s", batch_id, proof_id, e)
    store_proof(proof_id, proof)
