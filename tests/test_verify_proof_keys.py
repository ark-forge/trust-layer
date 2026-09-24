"""verify_proof.py against a key history.

Real proofs signed by key-1 (July 2026, and the PROVE IT corpus freeze of
2026-09-23) must keep verifying once key-1 is retired and key-2 signs. A key
is accepted only for proofs dated before its retirement.
"""

import importlib.util
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from trust_layer.signing import LocalSigner

FIXTURES = Path(__file__).parent / "fixtures" / "verify_proof"
SCRIPT = Path(__file__).parent.parent / "scripts" / "verify_proof.py"
_spec = importlib.util.spec_from_file_location("verify_proof_keys", SCRIPT)
vp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vp)

KEY_1 = "ed25519:ZLlGE0eN0eTNUE9vaK1tStf6AuoFUWqJBvqx7QgxfEY"
RETIRED = "2026-10-01T08:00:00Z"
NODE_2 = LocalSigner(Ed25519PrivateKey.generate(), kid="key-2")


@pytest.fixture(autouse=True)
def history(monkeypatch):
    pubkey = {
        "pubkey": NODE_2.public, "algorithm": "Ed25519", "kid": "key-2",
        "keys": [
            {"kid": "key-1", "type": "Ed25519", "public": KEY_1,
             "valid_from": "2026-02-26T00:00:00Z", "retired_at": RETIRED},
            {"kid": "key-2", "type": "Ed25519", "public": NODE_2.public,
             "valid_from": RETIRED, "retired_at": None},
        ],
    }
    did = {"verificationMethod": [
        {"id": "did:web:trust.arkforge.tech#key-2",
         "publicKeyJwk": {"x": NODE_2.public.split(":", 1)[1]}},
        {"id": "did:web:trust.arkforge.tech#key-1", "publicKeyJwk": {"x": KEY_1.split(":", 1)[1]}},
    ]}
    routes = {"/v1/pubkey": json.dumps(pubkey), "/.well-known/did.json": json.dumps(did)}

    def fake_fetch(url, binary=False, timeout=30):
        for suffix, data in routes.items():
            if url.endswith(suffix):
                return data.encode() if binary else data
        raise AssertionError(f"unexpected fetch: {url}")

    monkeypatch.setattr(vp, "fetch", fake_fetch)


def _ed25519(proof):
    rep = vp.Report()
    vp.check_ed25519(proof, proof["hashes"]["chain"].replace("sha256:", ""), rep, offline=False)
    return next((s, d) for w, s, d, _ in rep.rows if w == "Ed25519 (ArkForge)")


@pytest.mark.parametrize("name", ["proof_2026_07.json", "proof_proveit_gel.json", "proof_rekor.json"])
def test_proofs_signed_before_the_rotation_still_verify(name):
    status, detail = _ed25519(json.loads((FIXTURES / name).read_text()))
    assert status == vp.OK, detail


def _new_proof(signer, timestamp="2026-10-02T09:00:00Z", kid=None):
    chain = "d" * 64
    return {"hashes": {"chain": f"sha256:{chain}"}, "timestamp": timestamp,
            "arkforge_signature": signer.sign_chain_hash(chain),
            "arkforge_pubkey": signer.public, "arkforge_kid": kid or signer.kid}


def test_a_proof_signed_by_the_new_node_key_verifies():
    status, detail = _ed25519(_new_proof(NODE_2))
    assert status == vp.OK, detail


def test_a_retired_key_is_refused_after_its_retirement():
    rogue = json.loads((FIXTURES / "proof_2026_07.json").read_text())
    rogue["timestamp"] = "2026-10-05T00:00:00Z"
    status, detail = _ed25519(rogue)
    assert status == vp.FAIL
    assert "retired" in detail


def test_a_kid_naming_another_key_is_refused():
    impostor = LocalSigner(Ed25519PrivateKey.generate(), kid="key-2")
    status, _ = _ed25519(_new_proof(impostor))
    assert status == vp.FAIL


def test_an_unknown_kid_is_refused():
    status, _ = _ed25519(_new_proof(NODE_2, kid="key-7"))
    assert status == vp.FAIL


# --- Rekor attribution across the rotation ------------------------------------

def _rekor_submitter_pem():
    import base64
    entry = json.loads((FIXTURES / "rekor_entry.json").read_text())
    body = next(iter(entry.values()))["body"]
    spec = json.loads(base64.b64decode(body))["spec"]
    return base64.b64decode(spec["signature"]["publicKey"]["content"]).decode()


def _rekor_status(monkeypatch, pubkey):
    routes = {
        "/v1/pubkey": json.dumps(pubkey).encode(),
        "/api/v1/log/publicKey": (FIXTURES / "rekor_log_pubkey.pem").read_bytes(),
    }

    def fake_fetch(url, binary=False, timeout=30):
        if "/api/v1/log/entries/" in url:
            data = (FIXTURES / "rekor_entry.json").read_bytes()
        else:
            data = next(v for k, v in routes.items() if url.endswith(k))
        return data if binary else data.decode()

    monkeypatch.setattr(vp, "fetch", fake_fetch)
    proof = json.loads((FIXTURES / "proof_rekor.json").read_text())
    rep = vp.Report()
    chain = vp.check_chain_hash(proof, rep)
    anchored = vp.check_batch_anchor(proof, chain, rep)
    vp.check_rekor(proof, anchored, rep, offline=False)
    return next((s, d) for w, s, d, _ in rep.rows if w == "Sigstore Rekor")


def _throwaway_rekor_pem():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


NEW_REKOR_PEM = _throwaway_rekor_pem()


def test_an_entry_submitted_by_a_retired_rekor_key_is_still_attributed(monkeypatch):
    status, detail = _rekor_status(monkeypatch, {
        "rekor_pubkey": NEW_REKOR_PEM, "rekor_kid": "rekor-2",
        "rekor_keys": [
            {"kid": "rekor-1", "public_pem": _rekor_submitter_pem(), "retired_at": RETIRED},
            {"kid": "rekor-2", "public_pem": NEW_REKOR_PEM, "retired_at": None},
        ]})
    assert status == vp.OK
    assert "published key" in detail


def test_an_entry_from_an_unpublished_rekor_key_is_refused(monkeypatch):
    status, _ = _rekor_status(monkeypatch, {
        "rekor_pubkey": NEW_REKOR_PEM,
        "rekor_keys": [{"kid": "rekor-2", "public_pem": NEW_REKOR_PEM, "retired_at": None}]})
    assert status == vp.FAIL
