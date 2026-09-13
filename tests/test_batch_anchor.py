"""Batch anchoring — one TSA request and one Rekor entry per batch.

What matters here is not that a batch closes, but that the chain from an
individual proof up to the anchored root holds, that the pending batch survives
a restart, and that a proof still waiting for its batch reads as pending rather
than as tampered.
"""

import base64

import pytest

import trust_layer.batch_anchor as ba
from trust_layer.merkle import inclusion_root, leaf_hash
from trust_layer.proofs import load_proof, store_proof


@pytest.fixture
def fake_anchors(monkeypatch):
    """Capture what gets anchored without touching FreeTSA or the public Rekor log."""
    calls = {"tsa": [], "rekor": []}

    def fake_tsa(root, plan=""):
        calls["tsa"].append(root)
        return {"status": "verified", "provider": "freetsa.org",
                "tsr_base64": base64.b64encode(b"fake-tsr-" + root.encode()).decode()}

    def fake_rekor(root):
        calls["rekor"].append(root)
        return {"provider": "sigstore-rekor", "status": "included", "log_index": 42}

    monkeypatch.setattr(ba, "_anchor_tsa", fake_tsa)
    monkeypatch.setattr(ba, "_anchor_rekor", fake_rekor)
    return calls


def _store(proof_id, chain_hash):
    store_proof(proof_id, {"proof_id": proof_id, "spec_version": "3.0",
                           "hashes": {"chain": f"sha256:{chain_hash}"},
                           "batch_anchor": {"status": "pending"}})


def _queue(n, plan=""):
    ids = []
    for i in range(n):
        pid, chain = f"prf_test_{i:03d}", f"{i:064x}"
        _store(pid, chain)
        ba.add_proof(pid, chain, plan)
        ids.append((pid, chain))
    return ids


def test_one_anchor_per_batch_not_per_proof(fake_anchors):
    _queue(5)
    ba.close_batch()
    assert len(fake_anchors["tsa"]) == 1
    assert len(fake_anchors["rekor"]) == 1


def test_each_proof_carries_an_inclusion_proof_to_the_root(fake_anchors):
    ids = _queue(5)
    record = ba.close_batch()
    root = record["root"].replace("sha256:", "")
    for pid, chain in ids:
        anchor = load_proof(pid)["batch_anchor"]
        assert anchor["status"] == "anchored"
        computed, consumed = inclusion_root(
            leaf_hash(bytes.fromhex(chain)), anchor["leaf_index"], anchor["tree_size"],
            [bytes.fromhex(h) for h in anchor["audit_path"]])
        assert computed.hex() == root
        assert consumed == len(anchor["audit_path"])


def test_tsr_is_written_per_proof_so_a_third_party_needs_nothing_else(fake_anchors):
    ids = _queue(3)
    ba.close_batch()
    for pid, _ in ids:
        proof = load_proof(pid)
        assert proof["timestamp_authority"]["tsr_base64"]
        assert proof["timestamp_authority"]["anchored"] == "batch_root"
        assert (ba.PROOFS_DIR / f"{pid}.tsr").exists()


def test_batch_closes_on_size(fake_anchors, monkeypatch):
    monkeypatch.setattr(ba, "BATCH_MAX_SIZE", 4)
    _queue(4)
    assert ba._load_pending() == {}                     # closed and cleared
    assert len(fake_anchors["rekor"]) == 1
    assert load_proof("prf_test_003")["batch_anchor"]["status"] == "anchored"


def test_batch_does_not_close_before_its_age(fake_anchors):
    _queue(3)
    assert ba.close_due_batch() is None
    assert fake_anchors["rekor"] == []
    assert load_proof("prf_test_000")["batch_anchor"]["status"] == "pending"


def test_batch_closes_on_age(fake_anchors, monkeypatch):
    _queue(3)
    monkeypatch.setattr(ba, "BATCH_MAX_AGE_SECONDS", 0)
    record = ba.close_due_batch()
    assert record["reason"] == "age"
    assert record["tree_size"] == 3


def test_pending_batch_survives_a_restart(fake_anchors):
    """The batch lives on disk: a restart must neither lose it nor reopen it."""
    _queue(3)
    state = ba._load_pending()
    batch_id, opened_at = state["batch_id"], state["opened_at"]
    # simulate a restart: nothing in memory, everything re-read from disk
    _store("prf_test_003", f"{3:064x}")
    ba.add_proof("prf_test_003", f"{3:064x}")
    reloaded = ba._load_pending()
    assert reloaded["batch_id"] == batch_id
    assert reloaded["opened_at"] == opened_at
    assert len(reloaded["entries"]) == 4


def test_a_truncated_pending_state_reads_back_as_empty(fake_anchors):
    _queue(2)
    ba.PENDING_FILE.write_text('{"batch_id": "batch_x", "entr')
    assert ba._load_pending() == {}
    assert ba.close_batch() is None                      # nothing anchored from garbage


def test_an_empty_batch_is_never_anchored(fake_anchors):
    assert ba.close_batch() is None
    assert fake_anchors["tsa"] == [] and fake_anchors["rekor"] == []


def test_a_proof_is_queued_once(fake_anchors):
    _store("prf_dup", "aa" * 32)
    ba.add_proof("prf_dup", "aa" * 32)
    ba.add_proof("prf_dup", "aa" * 32)
    assert len(ba._load_pending()["entries"]) == 1


def test_a_failed_anchor_is_recorded_not_swallowed(monkeypatch):
    monkeypatch.setattr(ba, "_anchor_tsa", lambda root, plan="": {"status": "failed", "error": "all TSA servers failed"})
    monkeypatch.setattr(ba, "_anchor_rekor", lambda root: {"provider": "sigstore-rekor", "status": "failed"})
    _queue(2)
    record = ba.close_batch()
    assert record["timestamp_authority"]["status"] == "failed"
    proof = load_proof("prf_test_000")
    # The inclusion proof still holds; only the external witnesses are missing.
    assert proof["batch_anchor"]["status"] == "anchored"
    assert proof["timestamp_authority"]["status"] == "failed"


def test_one_platform_proof_routes_the_whole_batch(fake_anchors, monkeypatch):
    """Monotone: a batch is timestamped at the most demanding plan it contains."""
    seen = {}

    def record_plan(root, plan=""):
        seen["plan"] = plan
        return {"status": "verified"}

    monkeypatch.setattr(ba, "_anchor_tsa", record_plan)
    _store("prf_free", "aa" * 32)
    _store("prf_platform", "bb" * 32)
    ba.add_proof("prf_free", "aa" * 32, "free")
    ba.add_proof("prf_platform", "bb" * 32, "platform")
    ba.close_batch()
    assert seen["plan"] == "platform"
    assert load_proof("prf_free")["batch_anchor"]["status"] == "anchored"
