"""Tests for ProofIndexBackend implementations."""

import threading
import time
from pathlib import Path

import pytest

from trust_layer.proof_index import FileProofIndex, reset_proof_index


@pytest.fixture
def file_index(tmp_path):
    """Fresh FileProofIndex pointing to tmp_path."""
    reset_proof_index()
    return FileProofIndex(tmp_path / "proof_index.jsonl")


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
