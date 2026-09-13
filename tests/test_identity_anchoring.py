"""Spec 3.1 — the identity triple is anchored, and a third party can open it.

Until 3.0 inclusive, ``agent_identity``, ``agent_identity_verified`` and
``did_resolution_status`` were served publicly but lived outside ``chain_data``:
outside the Merkle root, outside ``hashes.chain``, outside the Ed25519 signature,
therefore outside TSA and Rekor. The issuer could rewrite them after the fact and
every external anchor still verified. The witness for that is
``test_tampering_the_identity_triple_now_breaks_integrity``: it is the exact
falsification that used to pass.

Anchoring alone is not enough here. A commitment with a secret nonce is
non-falsifiable but unreadable: the third party recomputes the root from digests,
never from values. These three values must stay readable, so 3.1 publishes their
nonces alongside them. Hiding is deliberately given up on this triple, and only
on it.
"""

import json

import pytest

from trust_layer.commitments import verify_disclosure
from trust_layer.proofs import (
    IDENTITY_FIELDS,
    SPEC_VERSION,
    generate_proof,
    get_full_proof,
    get_public_proof,
    verify_proof_integrity,
)


def _proof(**kw):
    base = dict(
        request_data={"q": "x"},
        response_data={"r": "y"},
        payment_data={"transaction_id": "pi_secret_value"},
        timestamp="2026-09-13T10:00:00Z",
        buyer_fingerprint="f" * 64,
        seller="corpus.arkforge.tech",
        agent_identity="did:web:agent.example",
        agent_identity_verified=True,
        did_resolution_status="bound",
    )
    base.update(kw)
    return generate_proof(**base)


def test_identity_consistent_is_committed_too():
    """Same family as the triple, same defect if left out.

    ``identity_consistent`` is a judgment ON the identity, computed by the proxy and
    served publicly. Anchoring the three fields next to it and leaving it out would
    rebuild the same hole one field to the left.
    """
    proof = _proof(identity_consistent=True)
    assert "identity_consistent" in proof["commitments"]
    assert verify_proof_integrity(proof) is True
    proof["identity_consistent"] = False
    proof["_chain_data"]["identity_consistent"] = False
    assert verify_proof_integrity(proof) is False


def test_identity_consistent_opens_publicly_and_cannot_be_restated():
    proof = _proof(identity_consistent=False)
    proof["identity_consistent"] = True          # what a restating issuer would edit
    public = get_public_proof(proof)
    assert public["identity_consistent"] is False
    item = public["disclosed"]["identity_consistent"]
    assert verify_disclosure("identity_consistent", item["nonce"], item["value"],
                             public["commitments"]["identity_consistent"])


def test_a_stored_and_reloaded_proof_still_opens():
    """The nonces must survive the disk, or a third party gets 'committed but not opened'.

    Every other check here runs on the in-memory record; production serves a reloaded
    one. Writing in one shape and reading in another is the defect this repo has already
    paid for twice.
    """
    import os
    from trust_layer.config import PROOFS_DIR
    from trust_layer.proofs import load_proof, store_proof
    proof = dict(_proof(), proof_id="prf_roundtrip_anchoring")
    store_proof("prf_roundtrip_anchoring", proof)
    try:
        back = load_proof("prf_roundtrip_anchoring")
        assert verify_proof_integrity(back) is True
        public = get_public_proof(back)
        assert set(public["disclosed"]) == set(IDENTITY_FIELDS)
        for field, item in public["disclosed"].items():
            assert verify_disclosure(field, item["nonce"], item["value"],
                                     public["commitments"][field])
    finally:
        os.remove(PROOFS_DIR / "prf_roundtrip_anchoring.json")


def test_the_demo_path_produces_a_valid_3_1_proof():
    """demo.py assembles its record by hand; it must not drift from generate_proof."""
    import os
    from trust_layer.config import PROOFS_DIR
    from trust_layer.demo import build_demo_proof
    record = build_demo_proof("https://example.com/api", {"q": 1})
    try:
        assert record["spec_version"] == SPEC_VERSION
        assert verify_proof_integrity(record) is True
        assert set(get_public_proof(record)["disclosed"]) == set(IDENTITY_FIELDS)
    finally:
        os.remove(PROOFS_DIR / f"{record['proof_id']}.json")


def test_spec_version_is_3_1():
    assert SPEC_VERSION == "3.1"
    assert _proof()["spec_version"] == "3.1"


def test_the_identity_triple_is_committed():
    proof = _proof()
    assert set(IDENTITY_FIELDS) <= set(proof["commitments"])
    assert set(IDENTITY_FIELDS) <= set(proof["_chain_data"])


def test_tampering_the_identity_triple_now_breaks_integrity():
    """The exact falsification that passed under 3.0, field by field."""
    for field, forged in (
        ("agent_identity", "did:web:trust.arkforge.tech"),
        ("agent_identity_verified", True),
        ("did_resolution_status", "bound"),
    ):
        proof = _proof(agent_identity="did:web:evil.example",
                       agent_identity_verified=None,
                       did_resolution_status="unverified")
        assert verify_proof_integrity(proof) is True
        proof["parties"][field] = forged
        proof["_chain_data"][field] = forged
        assert verify_proof_integrity(proof) is False, f"{field} is still forgeable"


def test_a_third_party_opens_the_triple_from_public_data_alone():
    proof = _proof()
    public = get_public_proof(proof)
    disclosed = public["disclosed"]
    assert set(disclosed) == set(IDENTITY_FIELDS)
    for field, item in disclosed.items():
        assert verify_disclosure(field, item["nonce"], item["value"],
                                 public["commitments"][field])


def test_a_forged_public_value_fails_to_open():
    proof = _proof(agent_identity_verified=None, did_resolution_status="unverified")
    public = get_public_proof(proof)
    public["disclosed"]["agent_identity_verified"]["value"] = True
    item = public["disclosed"]["agent_identity_verified"]
    assert not verify_disclosure("agent_identity_verified", item["nonce"], item["value"],
                                 public["commitments"]["agent_identity_verified"])


def test_top_level_identity_cannot_diverge_from_the_disclosed_value():
    """The restatement attack, played at serving time.

    ``parties`` is what an issuer would edit to restate an identity: it is a plain
    stored field, covered by nothing. The flat fields of the public view must be read
    from the committed data, so that editing ``parties`` changes nothing a reader sees.
    Asserting equality on an untampered proof would pass either way and measure zero.
    """
    proof = _proof(agent_identity="did:web:agent.example",
                   agent_identity_verified=None, did_resolution_status="unverified")
    proof["parties"]["agent_identity"] = "did:web:trust.arkforge.tech"
    proof["parties"]["agent_identity_verified"] = True
    proof["parties"]["did_resolution_status"] = "bound"
    public = get_public_proof(proof)
    for field in IDENTITY_FIELDS:
        assert public[field] == public["disclosed"][field]["value"]
    assert public["agent_identity"] == "did:web:agent.example"
    assert public["agent_identity_verified"] is None


def test_publishing_identity_nonces_discloses_nothing_else():
    public = get_public_proof(_proof())
    blob = json.dumps(public)
    assert "pi_secret_value" not in blob
    assert "f" * 64 not in blob
    assert set(public["disclosed"]) == set(IDENTITY_FIELDS)


@pytest.mark.parametrize("verified,status", [
    (True, "bound"),
    (False, "unverified"),
    (None, "unverified"),
    (None, None),
])
def test_every_identity_state_round_trips(verified, status):
    """False must not normalise to None on one side and stay False on the other.

    Same family as the Redis binding bug: write in one store, read in the other.
    """
    proof = _proof(agent_identity_verified=verified, did_resolution_status=status)
    assert verify_proof_integrity(proof) is True
    public = get_public_proof(proof)
    for field in IDENTITY_FIELDS:
        item = public["disclosed"][field]
        assert verify_disclosure(field, item["nonce"], item["value"],
                                 public["commitments"][field])
    # False is normalised to None once, at the source, so both sides agree.
    assert public["agent_identity_verified"] is (True if verified else None)
    assert proof["parties"]["agent_identity_verified"] == public["agent_identity_verified"]


def test_an_agent_without_identity_still_commits_the_triple():
    """Absent identity is a committed None, never a missing commitment.

    Otherwise an issuer drops the three fields and the scorer has nothing to refuse.
    """
    proof = _proof(agent_identity=None, agent_identity_verified=None,
                   did_resolution_status=None)
    assert set(IDENTITY_FIELDS) <= set(proof["commitments"])
    assert verify_proof_integrity(proof) is True
    public = get_public_proof(proof)
    assert public["disclosed"]["agent_identity"]["value"] is None


def test_a_3_1_proof_missing_identity_commitments_is_refused():
    """A coherent 3.1 proof that simply dropped the identity commitments.

    The chain hash is recomputed over the reduced set, so the Merkle root matches and
    every generic check passes. Only the explicit 'a 3.1 proof commits the triple' rule
    catches it. Deleting the field without rebuilding the root would fail on the root
    instead, and leave that rule untested.
    """
    from trust_layer.commitments import commitments_root
    proof = _proof()
    for holder in ("commitments", "_chain_data", "_commitment_nonces"):
        for field in IDENTITY_FIELDS:
            del proof[holder][field]
    proof["hashes"]["chain"] = f"sha256:{commitments_root(proof['commitments'])}"
    assert verify_proof_integrity(proof) is False


def test_3_0_proofs_still_verify():
    """Existing anchored proofs keep verifying; only their identity is unanchored."""
    proof = _proof()
    legacy = {k: v for k, v in proof.items()
              if k not in ("_chain_data", "_commitment_nonces", "commitments", "hashes")}
    legacy_chain = {k: v for k, v in proof["_chain_data"].items()
                    if k not in IDENTITY_FIELDS}
    from trust_layer.commitments import build_commitments
    commitments, nonces, chain_hash = build_commitments(legacy_chain)
    legacy["spec_version"] = "3.0"
    legacy["commitments"] = commitments
    legacy["_commitment_nonces"] = nonces
    legacy["_chain_data"] = legacy_chain
    legacy["hashes"] = dict(proof["hashes"], chain=f"sha256:{chain_hash}")
    assert verify_proof_integrity(legacy) is True
    assert "disclosed" not in get_public_proof(legacy)


def test_owner_view_still_carries_every_nonce():
    full = get_full_proof(_proof())
    assert set(IDENTITY_FIELDS) <= set(full["commitment_nonces"])
    assert "transaction_id" in full["commitment_nonces"]
