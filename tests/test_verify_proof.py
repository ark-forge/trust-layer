"""Tests for scripts/verify_proof.py — the third-party verification path.

The point of these tests is NOT that the verifier accepts a genuine proof. It is
that it REFUSES a tampered one. A verifier that has never returned a failure is a
decoy: it measures nothing. Each witness therefore gets its own negative case.

Fixtures are real artefacts captured on 2026-09-13 (a production proof, its Sigstore
Rekor entry, the log's public key, FreeTSA's certificates), so the suite never touches
the network.
"""

import base64
import copy
import importlib.util
import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "verify_proof"
SCRIPT = Path(__file__).parent.parent / "scripts" / "verify_proof.py"

_spec = importlib.util.spec_from_file_location("verify_proof", SCRIPT)
vp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vp)


def _load(name):
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def offline_fetch(monkeypatch):
    """Serve every network read from the captured fixtures."""
    routes = {
        "/.well-known/did.json": (FIXTURES / "did.json").read_bytes(),
        "/v1/pubkey": (FIXTURES / "pubkey.json").read_bytes(),
        "/api/v1/log/publicKey": (FIXTURES / "rekor_log_pubkey.pem").read_bytes(),
        "freetsa.org/files/cacert.pem": (FIXTURES / "freetsa_cacert.pem").read_bytes(),
        "freetsa.org/files/tsa.crt": (FIXTURES / "freetsa_tsa.crt").read_bytes(),
    }
    state = {"rekor_entry": (FIXTURES / "rekor_entry.json").read_bytes()}

    def fake_fetch(url, binary=False, timeout=30):
        if "/api/v1/log/entries/" in url:
            data = state["rekor_entry"]
        else:
            for suffix, data in routes.items():
                if url.endswith(suffix):
                    break
            else:
                raise AssertionError(f"unexpected fetch: {url}")
        return data if binary else data.decode("utf-8")

    monkeypatch.setattr(vp, "fetch", fake_fetch)
    return state


def _run(proof, offline=False, disclosure=None):
    rep = vp.Report()
    chain = vp.check_chain_hash(proof, rep, disclosure)
    vp.check_ed25519(proof, chain, rep, offline)
    anchored = vp.check_batch_anchor(proof, chain, rep)
    vp.check_rfc3161(proof, anchored, rep, offline)
    vp.check_rekor(proof, anchored, rep, offline)
    return rep


def _status(rep, witness):
    return next(s for w, s, _, _ in rep.rows if w == witness)


def _detail(rep, witness):
    return next(d for w, s, d, _ in rep.rows if w == witness)


# --- the genuine proof -------------------------------------------------------

def test_genuine_proof_has_two_independent_witnesses(offline_fetch):
    rep = _run(_load("proof_rekor.json"))
    assert not rep.failed
    assert _status(rep, "RFC 3161 timestamp") == vp.OK
    assert _status(rep, "Sigstore Rekor") == vp.OK
    assert rep.independent_ok == 2


def test_redacted_preimage_is_skipped_not_faked(offline_fetch):
    """The public proof redacts two chain-hash inputs. The verifier must say so
    rather than substitute a neighbouring field and report a bogus mismatch."""
    rep = _run(_load("proof_rekor.json"))
    assert _status(rep, "chain hash") == vp.SKIP
    assert "buyer_fingerprint" in _detail(rep, "chain hash")


# --- negative: RFC 3161 ------------------------------------------------------

def test_tampered_timestamp_token_is_rejected(offline_fetch):
    proof = _load("proof_rekor.json")
    raw = bytearray(base64.b64decode(proof["timestamp_authority"]["tsr_base64"]))
    raw[len(raw) // 2] ^= 0xFF
    proof["timestamp_authority"]["tsr_base64"] = base64.b64encode(bytes(raw)).decode()
    rep = _run(proof)
    assert _status(rep, "RFC 3161 timestamp") == vp.FAIL
    assert rep.failed


def test_unknown_timestamp_issuer_is_rejected(offline_fetch):
    """No CA material is mapped for an unknown issuer, so the token cannot be
    checked — that is a failure, never a pass."""
    proof = _load("proof_rekor.json")
    proof["timestamp_authority"]["provider"] = "tsa.example.invalid"
    rep = _run(proof)
    assert _status(rep, "RFC 3161 timestamp") == vp.FAIL


def test_chain_hash_swapped_breaks_the_timestamp(offline_fetch):
    """Anchors attest a specific chain hash. Change it and both anchors must object."""
    proof = _load("proof_rekor.json")
    proof["hashes"]["chain"] = "sha256:" + "ab" * 32
    rep = _run(proof)
    assert _status(rep, "RFC 3161 timestamp") == vp.FAIL
    assert _status(rep, "Sigstore Rekor") == vp.FAIL
    assert "not this proof's chain hash" in _detail(rep, "Sigstore Rekor")


# --- negative: Ed25519 -------------------------------------------------------

def test_tampered_signature_is_rejected(offline_fetch):
    proof = _load("proof_rekor.json")
    sig = bytearray(vp._b64url_decode(proof["arkforge_signature"].replace("ed25519:", "")))
    sig[0] ^= 0xFF
    proof["arkforge_signature"] = "ed25519:" + base64.urlsafe_b64encode(bytes(sig)).decode().rstrip("=")
    rep = _run(proof)
    assert _status(rep, "Ed25519 (ArkForge)") == vp.FAIL


def test_key_not_matching_the_published_one_is_rejected(offline_fetch):
    """A proof carrying its own key must not be trusted over the published key."""
    proof = _load("proof_rekor.json")
    proof["arkforge_pubkey"] = "ed25519:" + "A" * 43
    rep = _run(proof)
    assert _status(rep, "Ed25519 (ArkForge)") == vp.FAIL
    assert "did.json" in _detail(rep, "Ed25519 (ArkForge)")


# --- negative: Rekor ---------------------------------------------------------

def test_uuid_pointing_at_an_unrelated_real_entry_is_rejected(offline_fetch):
    """The defect this whole lot exists to fix: the previous implementation was
    happy with any HTTP 200. A genuine entry for somebody else's artefact must
    still fail, because it does not cover this proof's chain hash."""
    offline_fetch["rekor_entry"] = (FIXTURES / "rekor_unrelated.json").read_bytes()
    rep = _run(_load("proof_rekor.json"))
    assert _status(rep, "Sigstore Rekor") == vp.FAIL
    assert "hashedrekord" in _detail(rep, "Sigstore Rekor")


def _mutate_entry(mutator):
    doc = _load("rekor_entry.json")
    uuid, entry = next(iter(doc.items()))
    mutator(entry)
    return json.dumps({uuid: entry}).encode()


def test_corrupted_inclusion_path_is_rejected(offline_fetch):
    def mutate(entry):
        hashes = entry["verification"]["inclusionProof"]["hashes"]
        hashes[0] = "00" * 32
    offline_fetch["rekor_entry"] = _mutate_entry(mutate)
    rep = _run(_load("proof_rekor.json"))
    assert _status(rep, "Sigstore Rekor") == vp.FAIL
    assert "inclusion proof" in _detail(rep, "Sigstore Rekor")


def test_extra_inclusion_path_node_is_rejected(offline_fetch):
    """A path longer than the tree shape requires must not be silently ignored."""
    def mutate(entry):
        entry["verification"]["inclusionProof"]["hashes"].append("11" * 32)
    offline_fetch["rekor_entry"] = _mutate_entry(mutate)
    rep = _run(_load("proof_rekor.json"))
    assert _status(rep, "Sigstore Rekor") == vp.FAIL


def test_tampered_signed_entry_timestamp_is_rejected(offline_fetch):
    def mutate(entry):
        raw = bytearray(base64.b64decode(entry["verification"]["signedEntryTimestamp"]))
        raw[-1] ^= 0xFF
        entry["verification"]["signedEntryTimestamp"] = base64.b64encode(bytes(raw)).decode()
    offline_fetch["rekor_entry"] = _mutate_entry(mutate)
    rep = _run(_load("proof_rekor.json"))
    assert _status(rep, "Sigstore Rekor") == vp.FAIL
    assert "signed entry timestamp" in _detail(rep, "Sigstore Rekor")


def test_forged_checkpoint_is_rejected(offline_fetch):
    """Recomputing a root proves nothing if the root is not the log's own.
    Replacing both the path root and the checkpoint root must still fail on the
    checkpoint signature."""
    def mutate(entry):
        ip = entry["verification"]["inclusionProof"]
        forged = base64.b64encode(bytes.fromhex("cd" * 32)).decode()
        body, sep, sig = ip["checkpoint"].partition("\n\n")
        lines = body.split("\n")
        lines[2] = forged
        ip["checkpoint"] = "\n".join(lines) + sep + sig
    offline_fetch["rekor_entry"] = _mutate_entry(mutate)
    rep = _run(_load("proof_rekor.json"))
    assert _status(rep, "Sigstore Rekor") == vp.FAIL


def test_entry_signed_by_another_key_is_rejected(offline_fetch):
    def mutate(entry):
        body = json.loads(base64.b64decode(entry["body"]))
        sig = bytearray(base64.b64decode(body["spec"]["signature"]["content"]))
        sig[-1] ^= 0xFF
        body["spec"]["signature"]["content"] = base64.b64encode(bytes(sig)).decode()
        entry["body"] = base64.b64encode(json.dumps(body).encode()).decode()
    offline_fetch["rekor_entry"] = _mutate_entry(mutate)
    rep = _run(_load("proof_rekor.json"))
    assert _status(rep, "Sigstore Rekor") == vp.FAIL


# --- chain hash: both algorithms --------------------------------------------

def _preimage_proof(spec_version):
    """A proof carrying its own preimage, both chain-hash algorithms covered."""
    from trust_layer.proofs import canonical_json, sha256_hex
    fields = {
        "request_hash": "aa" * 32,
        "response_hash": "bb" * 32,
        "transaction_id": "pi_test_123",
        "timestamp": "2026-09-13T10:00:00Z",
        "buyer_fingerprint": "fp_test",
        "seller": "seller.example",
    }
    if spec_version in vp.LEGACY_SPEC_VERSIONS:
        chain = sha256_hex("".join([fields["request_hash"], fields["response_hash"],
                                    fields["transaction_id"], fields["timestamp"],
                                    fields["buyer_fingerprint"], fields["seller"]]))
    else:
        chain = sha256_hex(canonical_json(fields))
    return {
        "proof_id": "prf_test", "spec_version": spec_version,
        "hashes": {"request": f"sha256:{fields['request_hash']}",
                   "response": f"sha256:{fields['response_hash']}",
                   "chain": f"sha256:{chain}"},
        "timestamp": fields["timestamp"],
        "parties": {"buyer_fingerprint": fields["buyer_fingerprint"], "seller": fields["seller"]},
        "certification_fee": {"transaction_id": fields["transaction_id"]},
        "timestamp_authority": {}, "transparency_log": {},
    }


@pytest.mark.parametrize("spec_version", ["2.0", "1.1", "1.2", "2.1"])
def test_chain_hash_recomputes_under_both_algorithms(spec_version):
    rep = _run(_preimage_proof(spec_version), offline=True)
    assert _status(rep, "chain hash") == vp.OK


@pytest.mark.parametrize("spec_version", ["2.0", "1.2"])
def test_chain_hash_detects_a_swapped_response(spec_version):
    proof = _preimage_proof(spec_version)
    proof["hashes"]["response"] = "sha256:" + "cc" * 32
    rep = _run(proof, offline=True)
    assert _status(rep, "chain hash") == vp.FAIL


def test_wrong_algorithm_for_the_spec_is_detected():
    """Guards the drift that made the published procedure wrong: a 1.2 proof
    recomputed with the legacy concatenation must not validate."""
    proof = _preimage_proof("1.2")
    proof["spec_version"] = "2.0"   # forces the legacy branch on a canonical-JSON proof
    rep = _run(proof, offline=True)
    assert _status(rep, "chain hash") == vp.FAIL


# --- spec 3.0: the third party runs the published procedure on the PUBLIC proof --

def _anchored_public_proof(client, monkeypatch, n_siblings=4):
    """Issue a spec 3.0 proof, close its batch, and read it back from the public endpoint.

    Nothing here is hand-built: the proof goes through generate_proof, the batch
    through batch_anchor, and it comes back through GET /v1/proof/{id} — the same
    bytes a third party gets. Only the two external anchors are faked, because
    hitting a TSA and writing into the public Rekor log is not a unit test's job.
    """
    import base64 as _b64
    import trust_layer.batch_anchor as ba
    from trust_layer.proofs import generate_proof, store_proof

    monkeypatch.setattr(ba, "_anchor_tsa",
                        lambda root, plan="": {"status": "verified", "provider": "freetsa.org"})
    monkeypatch.setattr(ba, "_anchor_rekor", lambda root: {"provider": "sigstore-rekor", "status": "included"})

    target_id, nonces, chain_data = None, None, None
    for i in range(n_siblings):
        proof = generate_proof({"target": f"https://svc{i}.example", "payload": {"k": i}},
                               {"result": "ok"},
                               {"transaction_id": f"pi_secret_{i}", "amount": 0.5, "currency": "eur"},
                               "2026-09-13T10:00:00+00:00",
                               buyer_fingerprint="fp" * 32, seller=f"svc{i}.example")
        proof_id = f"prf_20260913_10000{i}_aaaaaa"
        record = dict(proof, proof_id=proof_id,
                      timestamp_authority={"status": "pending_batch"},
                      batch_anchor={"status": "pending"})
        store_proof(proof_id, record)
        ba.add_proof(proof_id, proof["_raw_chain_hash"])
        if i == 0:
            target_id, nonces, chain_data = proof_id, proof["_commitment_nonces"], proof["_chain_data"]
    ba.close_batch()
    public = client.get(f"/v1/proof/{target_id}").json()
    return public, nonces, chain_data


def test_third_party_verifies_the_public_proof_without_any_preimage(client, monkeypatch):
    """The measurement that this lot exists for.

    Before spec 3.0 this exact path answered TAMPERED: the public proof redacts
    the preimage the chain hash was built on. It must now verify, and the
    transaction id must not appear anywhere the third party can see.
    """
    public, _, _ = _anchored_public_proof(client, monkeypatch)
    assert "pi_secret_0" not in json.dumps(public)
    assert "fp" * 32 not in json.dumps(public)

    rep = _run(public, offline=True)
    assert _status(rep, "chain hash") == vp.OK
    assert _status(rep, "batch anchor") == vp.OK
    assert not rep.failed


def test_third_party_refuses_a_tampered_commitment(client, monkeypatch):
    public, _, _ = _anchored_public_proof(client, monkeypatch)
    public["commitments"]["seller"] = "sha256:" + "00" * 32
    rep = _run(public, offline=True)
    assert _status(rep, "chain hash") == vp.FAIL


def test_third_party_refuses_a_tampered_audit_path(client, monkeypatch):
    public, _, _ = _anchored_public_proof(client, monkeypatch)
    public["batch_anchor"]["audit_path"][0] = "00" * 32
    rep = _run(public, offline=True)
    assert _status(rep, "batch anchor") == vp.FAIL


def test_third_party_refuses_a_wrong_leaf_index(client, monkeypatch):
    public, _, _ = _anchored_public_proof(client, monkeypatch)
    anchor = public["batch_anchor"]
    anchor["leaf_index"] = (anchor["leaf_index"] + 1) % anchor["tree_size"]
    rep = _run(public, offline=True)
    assert _status(rep, "batch anchor") == vp.FAIL


def test_third_party_refuses_an_out_of_range_leaf_index(client, monkeypatch):
    public, _, _ = _anchored_public_proof(client, monkeypatch)
    public["batch_anchor"]["leaf_index"] = public["batch_anchor"]["tree_size"]
    rep = _run(public, offline=True)
    assert _status(rep, "batch anchor") == vp.FAIL


def test_third_party_refuses_a_root_that_is_not_the_one_walked(client, monkeypatch):
    public, _, _ = _anchored_public_proof(client, monkeypatch)
    public["batch_anchor"]["root"] = "sha256:" + "11" * 32
    rep = _run(public, offline=True)
    assert _status(rep, "batch anchor") == vp.FAIL


def test_third_party_refuses_a_padded_audit_path(client, monkeypatch):
    """A path with a leftover sibling does not match the shape that was walked."""
    public, _, _ = _anchored_public_proof(client, monkeypatch)
    public["batch_anchor"]["audit_path"].append("22" * 32)
    rep = _run(public, offline=True)
    assert _status(rep, "batch anchor") == vp.FAIL


def test_a_proof_waiting_for_its_batch_is_pending_not_tampered(client, monkeypatch):
    """The failure mode measured on 2026-09-13: an honest proof accused of fraud."""
    import trust_layer.batch_anchor as ba
    from trust_layer.proofs import generate_proof, store_proof
    proof = generate_proof({"t": 1}, {"r": "ok"}, {"transaction_id": "pi_x"},
                           "2026-09-13T10:00:00+00:00", buyer_fingerprint="f" * 64, seller="s")
    proof_id = "prf_20260913_120000_bbbbbb"
    store_proof(proof_id, dict(proof, proof_id=proof_id, batch_anchor={"status": "pending"},
                               timestamp_authority={"status": "pending_batch"}))
    ba.add_proof(proof_id, proof["_raw_chain_hash"])

    public = client.get(f"/v1/proof/{proof_id}").json()
    rep = _run(public, offline=True)
    assert _status(rep, "chain hash") == vp.OK
    assert _status(rep, "batch anchor") == vp.SKIP
    assert _status(rep, "RFC 3161 timestamp") == vp.SKIP
    assert not rep.failed


# --- selective disclosure ----------------------------------------------------

def test_disclosed_field_is_checked_against_the_anchored_commitment(client, monkeypatch):
    public, nonces, chain_data = _anchored_public_proof(client, monkeypatch)
    disclosure = {"disclosed": {"seller": {"nonce": nonces["seller"],
                                           "value": chain_data["seller"]}}}
    rep = _run(public, offline=True, disclosure=disclosure)
    assert _status(rep, "selective disclosure") == vp.OK


def test_a_forged_disclosed_value_is_refused(client, monkeypatch):
    public, nonces, _ = _anchored_public_proof(client, monkeypatch)
    disclosure = {"disclosed": {"seller": {"nonce": nonces["seller"], "value": "evil.example"}}}
    rep = _run(public, offline=True, disclosure=disclosure)
    assert _status(rep, "selective disclosure") == vp.FAIL


def test_a_disclosure_moved_to_another_field_is_refused(client, monkeypatch):
    """Domain separation at the verifier: the field name is in the preimage."""
    public, nonces, chain_data = _anchored_public_proof(client, monkeypatch)
    disclosure = {"disclosed": {"response_hash": {"nonce": nonces["request_hash"],
                                                  "value": chain_data["request_hash"]}}}
    rep = _run(public, offline=True, disclosure=disclosure)
    assert _status(rep, "selective disclosure") == vp.FAIL


def test_a_disclosure_for_an_unknown_field_is_refused(client, monkeypatch):
    public, nonces, _ = _anchored_public_proof(client, monkeypatch)
    disclosure = {"disclosed": {"not_a_field": {"nonce": nonces["seller"], "value": "x"}}}
    rep = _run(public, offline=True, disclosure=disclosure)
    assert _status(rep, "selective disclosure") == vp.FAIL


def test_spec_3_proof_without_commitments_fails():
    rep = _run({"spec_version": "3.0", "hashes": {"chain": "sha256:" + "ab" * 32}}, offline=True)
    assert _status(rep, "chain hash") == vp.FAIL
