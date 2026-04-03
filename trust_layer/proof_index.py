"""Proof index — time-range queries over proofs by buyer_fingerprint.

Provides a pluggable backend abstraction so the storage layer can evolve
(Redis → SQLite → Postgres) without touching the indexing interface.

Architecture:
- ProofIndexBackend (ABC): record() + query()
- RedisProofIndex: ZADD/ZRANGEBYSCORE on pidx:{fingerprint}
- FileProofIndex: JSONL append with threading.Lock (fallback)
- DualWriteProofIndex: writes to both (JSONL primary, Redis secondary).
  Used when Redis is available — JSONL is always written first (durable),
  Redis is written second (fast queries). If Redis fails mid-write, the JSONL
  entry is already committed. Queries prefer Redis; fall back to JSONL.
- get_proof_index(): singleton, DualWrite when Redis available, File otherwise

Resilience model
----------------
JSONL is the source of truth. Redis is derived and rebuildable at any time.

Two automatic reconciliation triggers:
1. Startup reconciliation: at DualWriteProofIndex init, a background thread
   replays the full JSONL into Redis (idempotent — ZADD on existing entries
   is a no-op). Handles the case where Redis restarted while the service was
   down and its data was lost.
2. Periodic reconciliation: a daemon thread re-replays the last
   RECONCILE_WINDOW_HOURS of JSONL every RECONCILE_INTERVAL_SEC seconds.
   Handles the case where Redis restarted *while the service was running*
   (without a service restart). Entries missed during the Redis outage window
   are re-injected automatically.

Manual reconciliation: `python3 scripts/backfill_proof_index.py`

Design mirrors redis_client.py: if Redis is unavailable, falls back silently.
"""

import json
import logging
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("trust_layer.proof_index")

from .config import PROOF_INDEX_FILE

# Periodic reconciliation window: re-replay entries newer than this threshold.
# Wide enough to cover any realistic Redis outage without scanning the full JSONL.
RECONCILE_WINDOW_HOURS = 25  # slightly more than 1 day
RECONCILE_INTERVAL_SEC = 300  # every 5 minutes


# ---------------------------------------------------------------------------
# Abstract backend
# ---------------------------------------------------------------------------

class ProofIndexBackend(ABC):
    """Abstract proof index backend.

    To add a new backend (e.g. SQLite):
    1. Subclass ProofIndexBackend
    2. Implement record() and query()
    3. Update get_proof_index() to try the new backend
    """

    @abstractmethod
    def record(self, fingerprint: str, proof_id: str, ts_unix: float) -> None:
        """Index a proof. fingerprint = sha256(api_key) from proof parties.

        Silently skips if fingerprint is empty.
        """
        ...

    @abstractmethod
    def query(self, fingerprint: str, from_unix: float, to_unix: float) -> list[str]:
        """Return proof_ids for fingerprint in [from_unix, to_unix]."""
        ...


# ---------------------------------------------------------------------------
# Redis backend
# ---------------------------------------------------------------------------

class RedisProofIndex(ProofIndexBackend):
    """Proof index backed by Redis sorted sets.

    Key schema: pidx:{fingerprint}
    Score: unix timestamp (float)
    Member: proof_id

    TTL: 90 days rolling (EXPIREAT reset on each record).
    """

    def __init__(self, redis_client) -> None:
        self._r = redis_client

    def record(self, fingerprint: str, proof_id: str, ts_unix: float) -> None:
        if not fingerprint:
            return
        key = f"pidx:{fingerprint}"
        self._r.zadd(key, {proof_id: ts_unix})
        # Rolling 90-day TTL
        expire_at = int(ts_unix) + 90 * 86400
        self._r.expireat(key, expire_at)

    def query(self, fingerprint: str, from_unix: float, to_unix: float) -> list[str]:
        if not fingerprint:
            return []
        key = f"pidx:{fingerprint}"
        results = self._r.zrangebyscore(key, from_unix, to_unix)
        return results if results else []


# ---------------------------------------------------------------------------
# File (JSONL) backend — fallback when Redis is unavailable
# ---------------------------------------------------------------------------

_FILE_LOCK = threading.Lock()


class FileProofIndex(ProofIndexBackend):
    """Proof index backed by an append-only JSONL file.

    Each line: {"fp": "<fingerprint>", "pid": "<proof_id>", "ts": <float>}

    Thread-safe via a module-level lock. Idempotent: duplicate (fp, pid) pairs
    are harmless — query deduplicates by converting results to a set.

    Adequate for <100k proofs. Beyond that, Redis or SQLite is recommended
    (see ROADMAP.md — Phase 3 storage evolution).
    """

    def __init__(self, index_file: Path) -> None:
        self._file = index_file

    def record(self, fingerprint: str, proof_id: str, ts_unix: float) -> None:
        if not fingerprint:
            return
        entry = json.dumps({"fp": fingerprint, "pid": proof_id, "ts": ts_unix})
        with _FILE_LOCK:
            with self._file.open("a", encoding="utf-8") as f:
                f.write(entry + "\n")

    def query(self, fingerprint: str, from_unix: float, to_unix: float) -> list[str]:
        if not fingerprint or not self._file.exists():
            return []
        results: set[str] = set()
        with _FILE_LOCK:
            with self._file.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if (
                            entry.get("fp") == fingerprint
                            and from_unix <= entry.get("ts", 0) <= to_unix
                        ):
                            results.add(entry["pid"])
                    except (json.JSONDecodeError, KeyError):
                        continue
        return list(results)


# ---------------------------------------------------------------------------
# DualWrite backend — JSONL primary, Redis secondary
# ---------------------------------------------------------------------------

class DualWriteProofIndex(ProofIndexBackend):
    """Dual-write proof index: JSONL (durable) + Redis (fast queries).

    Write path
    ----------
    1. JSONL is written first — always committed before Redis is touched.
    2. Redis ZADD follows — if it fails, the JSONL entry is already safe.

    Read path
    ---------
    Redis is queried first (O(log n)). If Redis raises any exception (outage,
    connection reset), the JSONL is read as fallback (O(n) scan, adequate for
    <100k proofs).

    Reconciliation
    --------------
    JSONL is the source of truth. Redis can be rebuilt from it at any time.

    Two automatic triggers (no operator action required):
    - Startup: full JSONL replay into Redis on init (background thread).
    - Periodic: re-replay of the last RECONCILE_WINDOW_HOURS every
      RECONCILE_INTERVAL_SEC seconds (covers Redis outages during runtime).

    Manual trigger: `python3 scripts/backfill_proof_index.py`
    """

    def __init__(self, redis_client, file_index: FileProofIndex) -> None:
        self._redis = RedisProofIndex(redis_client)
        self._file = file_index
        # Startup reconciliation: replay full JSONL → Redis in background.
        t = threading.Thread(
            target=self._reconcile_jsonl_to_redis,
            kwargs={"since_unix": None},
            daemon=True,
            name="proof-index-startup-reconcile",
        )
        t.start()
        # Periodic reconciliation: re-replay recent window every N seconds.
        t2 = threading.Thread(
            target=self._periodic_reconcile,
            daemon=True,
            name="proof-index-periodic-reconcile",
        )
        t2.start()

    def record(self, fingerprint: str, proof_id: str, ts_unix: float) -> None:
        # JSONL first — durable, always committed
        self._file.record(fingerprint, proof_id, ts_unix)
        # Redis second — performance, best-effort
        try:
            self._redis.record(fingerprint, proof_id, ts_unix)
        except Exception as exc:
            logger.warning(
                "ProofIndex: Redis write failed for %s (JSONL committed) — %s",
                proof_id, exc,
            )

    def query(self, fingerprint: str, from_unix: float, to_unix: float) -> list[str]:
        try:
            return self._redis.query(fingerprint, from_unix, to_unix)
        except Exception as exc:
            logger.warning(
                "ProofIndex: Redis query failed, falling back to JSONL — %s", exc
            )
            return self._file.query(fingerprint, from_unix, to_unix)

    def reconcile(self, since_unix: Optional[float] = None) -> int:
        """Replay JSONL entries into Redis. Returns number of entries replayed.

        Args:
            since_unix: if provided, only replay entries with ts >= since_unix.
                        If None, replay the full JSONL (used at startup).

        This method is idempotent: ZADD on an existing (key, member) pair
        updates the score but does not create duplicates in Redis.
        Can be called manually or by the background threads.
        """
        return self._reconcile_jsonl_to_redis(since_unix=since_unix)

    def _reconcile_jsonl_to_redis(self, since_unix: Optional[float] = None) -> int:
        """Internal: read JSONL, ZADD entries to Redis. Thread-safe."""
        if not self._file._file.exists():
            return 0
        count = 0
        label = "full" if since_unix is None else f"since={datetime.fromtimestamp(since_unix, tz=timezone.utc).isoformat()}"
        try:
            with _FILE_LOCK:
                with self._file._file.open("r", encoding="utf-8") as f:
                    lines = f.readlines()
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    fp = entry.get("fp", "")
                    pid = entry.get("pid", "")
                    ts = entry.get("ts", 0.0)
                    if not fp or not pid:
                        continue
                    if since_unix is not None and ts < since_unix:
                        continue
                    self._redis.record(fp, pid, ts)
                    count += 1
                except Exception:
                    continue
            if count:
                logger.info(
                    "ProofIndex: reconciled %d entries JSONL→Redis (%s)", count, label
                )
        except Exception as exc:
            logger.warning("ProofIndex: reconciliation failed (%s) — %s", label, exc)
        return count

    def _periodic_reconcile(self) -> None:
        """Daemon thread: re-replay recent JSONL window into Redis every N seconds."""
        while True:
            time.sleep(RECONCILE_INTERVAL_SEC)
            window_start = (
                datetime.now(timezone.utc) - timedelta(hours=RECONCILE_WINDOW_HOURS)
            ).timestamp()
            try:
                self._reconcile_jsonl_to_redis(since_unix=window_start)
            except Exception as exc:
                logger.debug("ProofIndex: periodic reconcile error — %s", exc)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_index_backend: Optional[ProofIndexBackend] = None
_index_checked = False
_INDEX_LOCK = threading.Lock()


def get_proof_index() -> ProofIndexBackend:
    """Return the active proof index backend (DualWrite when Redis available,
    File otherwise).

    Thread-safe singleton. Mirrors the pattern from redis_client.get_redis().

    When Redis is available: DualWriteProofIndex
      - Writes to JSONL (durable) + Redis (fast).
      - Reads from Redis; falls back to JSONL on error.
      - Automatically reconciles JSONL→Redis at startup and every 5 minutes.

    When Redis is unavailable: FileProofIndex
      - Writes and reads from JSONL only.
      - No data loss risk; performance degrades to O(n) scan for large indexes.
    """
    global _index_backend, _index_checked
    with _INDEX_LOCK:
        if _index_checked:
            return _index_backend  # type: ignore[return-value]
        _index_checked = True
        try:
            from .redis_client import get_redis
            r = get_redis()
            if r is not None:
                file_index = FileProofIndex(PROOF_INDEX_FILE)
                _index_backend = DualWriteProofIndex(r, file_index)
                logger.info("ProofIndex: using DualWrite backend (Redis + JSONL)")
                return _index_backend
        except Exception as e:
            logger.debug("ProofIndex: Redis unavailable (%s), using File fallback", e)
        _index_backend = FileProofIndex(PROOF_INDEX_FILE)
        logger.info("ProofIndex: using File backend (%s)", PROOF_INDEX_FILE)
        return _index_backend


def reset_proof_index() -> None:
    """Reset singleton (tests only)."""
    global _index_backend, _index_checked
    with _INDEX_LOCK:
        _index_backend = None
        _index_checked = False
