"""Proof index — time-range queries over proofs by buyer_fingerprint.

Provides a pluggable backend abstraction so the storage layer can evolve
(Redis → SQLite → Postgres) without touching the indexing interface.

Architecture:
- ProofIndexBackend (ABC): record() + query()
- RedisProofIndex: ZADD/ZRANGEBYSCORE on pidx:{fingerprint}
- FileProofIndex: JSONL append with threading.Lock (fallback)
- get_proof_index(): singleton, Redis-first, File fallback

Design mirrors redis_client.py: if Redis is unavailable, falls back silently.
"""

import json
import logging
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("trust_layer.proof_index")

from .config import PROOF_INDEX_FILE


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
# Singleton
# ---------------------------------------------------------------------------

_index_backend: Optional[ProofIndexBackend] = None
_index_checked = False
_INDEX_LOCK = threading.Lock()


def get_proof_index() -> ProofIndexBackend:
    """Return the active proof index backend (Redis-first, File fallback).

    Thread-safe singleton. Mirrors the pattern from redis_client.get_redis().
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
                _index_backend = RedisProofIndex(r)
                logger.info("ProofIndex: using Redis backend")
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
