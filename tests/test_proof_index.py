"""Tests for ProofIndexBackend implementations."""

import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from trust_layer.proof_index import (
    DualWriteProofIndex,
    FileProofIndex,
    RedisProofIndex,
    reset_proof_index,
)


@pytest.fixture
def file_index(tmp_path):
    """Fresh FileProofIndex pointing to tmp_path."""
    reset_proof_index()
    return FileProofIndex(tmp_path / "proof_index.jsonl")


@pytest.fixture
def mock_redis():
    """Mock Redis client with in-memory sorted set behaviour."""
    store: dict[str, dict[str, float]] = {}

    r = MagicMock()

    def zadd(key, mapping):
        store.setdefault(key, {}).update(mapping)

    def zrangebyscore(key, min_score, max_score):
        members = store.get(key, {})
        return [
            pid for pid, ts in members.items()
            if min_score <= ts <= max_score
        ]

    r.zadd.side_effect = zadd
    r.zrangebyscore.side_effect = zrangebyscore
    r.expireat.return_value = True
    return r


@pytest.fixture
def dual_index(tmp_path, mock_redis):
    """DualWriteProofIndex backed by mock Redis + tmp FileProofIndex.

    Background threads (startup reconcile, periodic reconcile) are started
    but harmless — the mock Redis is already populated inline per test.
    """
    reset_proof_index()
    file_idx = FileProofIndex(tmp_path / "proof_index.jsonl")
    return DualWriteProofIndex(mock_redis, file_idx)


# ---------------------------------------------------------------------------
# FileProofIndex
# ---------------------------------------------------------------------------

def test_record_and_query(file_index):
    file_index.record("fp_abc", "prf_001", 1000.0)
    file_index.record("fp_abc", "prf_002", 2000.0)
    file_index.record("fp_abc", "prf_003", 3000.0)

    result = file_index.query("fp_abc", 0.0, 9999999.0)
    assert set(result) == {"prf_001", "prf_002", "prf_003"}


def test_query_date_range(file_index):
    file_index.record("fp_abc", "prf_early", 1000.0)
    file_index.record("fp_abc", "prf_mid", 2000.0)
    file_index.record("fp_abc", "prf_late", 3000.0)

    result = file_index.query("fp_abc", 1500.0, 2500.0)
    assert result == ["prf_mid"]


def test_query_empty_range(file_index):
    file_index.record("fp_abc", "prf_001", 1000.0)
    result = file_index.query("fp_abc", 5000.0, 9000.0)
    assert result == []


def test_query_different_fingerprint(file_index):
    file_index.record("fp_alice", "prf_001", 1000.0)
    file_index.record("fp_bob", "prf_002", 1000.0)

    assert file_index.query("fp_alice", 0, 9999) == ["prf_001"]
    assert file_index.query("fp_bob", 0, 9999) == ["prf_002"]


def test_empty_fingerprint_skipped(file_index):
    file_index.record("", "prf_001", 1000.0)
    assert file_index.query("", 0, 9999) == []


def test_query_nonexistent_fingerprint(file_index):
    result = file_index.query("fp_nobody", 0.0, 9999.0)
    assert result == []


def test_query_no_index_file(tmp_path):
    idx = FileProofIndex(tmp_path / "nonexistent.jsonl")
    result = idx.query("fp_abc", 0.0, 9999.0)
    assert result == []


def test_idempotent_record(file_index):
    """Duplicate records do not duplicate query results (dedup via set)."""
    file_index.record("fp_abc", "prf_001", 1000.0)
    file_index.record("fp_abc", "prf_001", 1000.0)

    result = file_index.query("fp_abc", 0.0, 9999.0)
    assert result == ["prf_001"]


def test_concurrent_writes(file_index):
    """Concurrent records from multiple threads do not corrupt the file."""
    errors = []

    def write(i):
        try:
            file_index.record("fp_concurrent", f"prf_{i:04d}", float(i))
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=write, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Concurrent write errors: {errors}"
    results = file_index.query("fp_concurrent", 0.0, 9999.0)
    assert len(results) == 50


def test_get_proof_index_returns_backend(tmp_path, monkeypatch):
    """get_proof_index() returns a FileProofIndex when Redis is unavailable."""
    import trust_layer.proof_index as pidx_mod
    import trust_layer.config as cfg

    monkeypatch.setattr(pidx_mod, "_index_backend", None)
    monkeypatch.setattr(pidx_mod, "_index_checked", False)
    monkeypatch.setattr(pidx_mod, "PROOF_INDEX_FILE", tmp_path / "idx.jsonl")

    from trust_layer.proof_index import get_proof_index
    backend = get_proof_index()
    assert isinstance(backend, FileProofIndex)


# ---------------------------------------------------------------------------
# DualWriteProofIndex
# ---------------------------------------------------------------------------

def test_dualwrite_record_writes_both(dual_index, mock_redis):
    """record() commits to JSONL and to Redis."""
    dual_index.record("fp_test", "prf_001", 1000.0)

    # JSONL has it
    file_results = dual_index._file.query("fp_test", 0.0, 9999.0)
    assert "prf_001" in file_results

    # Redis has it
    mock_redis.zadd.assert_called()
    redis_results = dual_index._redis.query("fp_test", 0.0, 9999.0)
    assert "prf_001" in redis_results


def test_dualwrite_query_prefers_redis(dual_index, mock_redis):
    """query() returns Redis results when Redis is available."""
    dual_index.record("fp_test", "prf_001", 1000.0)

    result = dual_index.query("fp_test", 0.0, 9999.0)

    assert "prf_001" in result
    mock_redis.zrangebyscore.assert_called()


def test_dualwrite_query_falls_back_to_file_on_redis_error(dual_index, mock_redis):
    """query() falls back to JSONL when Redis raises."""
    dual_index._file.record("fp_test", "prf_file_only", 1000.0)
    mock_redis.zrangebyscore.side_effect = Exception("Redis connection reset")

    result = dual_index.query("fp_test", 0.0, 9999.0)

    assert "prf_file_only" in result


def test_dualwrite_redis_failure_on_record_still_writes_file(dual_index, mock_redis):
    """If Redis write fails, JSONL still gets the entry — no data loss."""
    mock_redis.zadd.side_effect = Exception("Redis unavailable")

    # Should not raise
    dual_index.record("fp_test", "prf_safe", 1000.0)

    # JSONL has it despite Redis failure
    file_results = dual_index._file.query("fp_test", 0.0, 9999.0)
    assert "prf_safe" in file_results


def test_dualwrite_reconcile_populates_redis(tmp_path, mock_redis):
    """reconcile() replays existing JSONL entries into Redis (idempotent)."""
    reset_proof_index()
    file_idx = FileProofIndex(tmp_path / "proof_index.jsonl")
    # Pre-populate JSONL before DualWrite is created (simulates Redis restart)
    file_idx.record("fp_test", "prf_old_001", 1000.0)
    file_idx.record("fp_test", "prf_old_002", 2000.0)

    dual = DualWriteProofIndex(mock_redis, file_idx)
    # Wait for startup reconciliation thread
    time.sleep(0.3)

    redis_results = dual._redis.query("fp_test", 0.0, 9999.0)
    assert "prf_old_001" in redis_results
    assert "prf_old_002" in redis_results


def test_dualwrite_reconcile_manual_call(tmp_path, mock_redis):
    """reconcile(since_unix=...) replays only entries in the given window."""
    reset_proof_index()
    file_idx = FileProofIndex(tmp_path / "proof_index.jsonl")
    file_idx.record("fp_test", "prf_old", 1000.0)
    file_idx.record("fp_test", "prf_new", 5000.0)

    dual = DualWriteProofIndex(mock_redis, file_idx)
    # Wait for startup reconciliation thread to finish, then reset call history
    time.sleep(0.3)
    mock_redis.zadd.reset_mock()
    mock_redis.zrangebyscore.side_effect = None  # reset side effect from mock_redis

    count = dual.reconcile(since_unix=3000.0)

    assert count == 1  # only prf_new qualifies
    # Verify Redis was called for prf_new only
    call_args = [str(c) for c in mock_redis.zadd.call_args_list]
    assert any("prf_new" in c for c in call_args)
    assert not any("prf_old" in c for c in call_args)


def test_dualwrite_reconcile_idempotent(tmp_path, mock_redis):
    """Running reconcile() twice does not corrupt the index."""
    reset_proof_index()
    file_idx = FileProofIndex(tmp_path / "proof_index.jsonl")
    file_idx.record("fp_test", "prf_001", 1000.0)

    dual = DualWriteProofIndex(mock_redis, file_idx)
    dual.reconcile()
    dual.reconcile()  # second pass — idempotent

    redis_results = dual._redis.query("fp_test", 0.0, 9999.0)
    assert redis_results.count("prf_001") == 1


def test_get_proof_index_returns_dualwrite_when_redis_available(tmp_path, monkeypatch):
    """get_proof_index() returns DualWriteProofIndex when Redis is available."""
    import trust_layer.proof_index as pidx_mod

    monkeypatch.setattr(pidx_mod, "_index_backend", None)
    monkeypatch.setattr(pidx_mod, "_index_checked", False)
    monkeypatch.setattr(pidx_mod, "PROOF_INDEX_FILE", tmp_path / "idx.jsonl")

    mock_r = MagicMock()
    mock_r.zadd.return_value = 1
    mock_r.zrangebyscore.return_value = []
    mock_r.expireat.return_value = True

    with patch("trust_layer.proof_index.FileProofIndex") as _mock_file, \
         patch("trust_layer.redis_client.get_redis", return_value=mock_r):
        _mock_file.return_value = MagicMock(spec=FileProofIndex)
        _mock_file.return_value._file = MagicMock()
        _mock_file.return_value._file.exists.return_value = False

        from trust_layer.proof_index import get_proof_index
        backend = get_proof_index()

    assert isinstance(backend, DualWriteProofIndex)
