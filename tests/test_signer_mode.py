"""Trust Layer in signer mode (P5a): keys live in tl-signer, the API only sees a socket."""

import json
import threading
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from signer import tl_signer
from trust_layer.crypto import verify_proof_signature

DEMO = {"target": "https://api.openai.com/v1/chat/completions", "payload": {"model": "gpt-4"}}
KEY_1 = "ed25519:ZLlGE0eN0eTNUE9vaK1tStf6AuoFUWqJBvqx7QgxfEY"


@pytest.fixture
def signer_mode(tmp_path, monkeypatch):
    import trust_layer.config as cfg
    from trust_layer.signing import SocketSigner

    sock = tmp_path / "sign.sock"
    server = tl_signer.build_server(tmp_path / "state", sock, "key-9", "rekor-9",
                                    "did:web:test.arkforge.fr")
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01},
                     daemon=True).start()
    node = SocketSigner(sock)
    registry = tmp_path / "published_keys.json"
    registry.write_text(json.dumps({"keys": [
        {"kid": "key-1", "type": "Ed25519", "public": KEY_1, "node": "vps1",
         "valid_from": "2026-02-26", "retired_at": "2026-10-01"},
        {"kid": "key-9", "type": "Ed25519", "public": node.public, "node": "test",
         "valid_from": "2026-10-01", "retired_at": None},
    ]}))
    monkeypatch.setattr(cfg, "PUBLISHED_KEYS_FILE", registry)
    monkeypatch.setattr(cfg, "SIGNING_KEY_PATH", tmp_path / "must-not-exist.pem")
    monkeypatch.setattr(cfg, "REKOR_EC_KEY_PATH", tmp_path / "must-not-exist-rekor.pem")
    monkeypatch.setattr(cfg, "_SIGNING_KEY", None)
    monkeypatch.setattr(cfg, "_SIGNER", node)
    yield node, tmp_path
    server.shutdown()
    server.server_close()


@pytest.fixture
def client():
    from trust_layer.app import app
    return TestClient(app)


def _demo_proof(client):
    with patch("trust_layer.app._post_proof_background", new=AsyncMock()), \
         patch("trust_layer.app._track_task"):
        r = client.post("/v1/demo", json=DEMO)
    assert r.status_code == 200
    proof = client.get(f"/v1/proof/{r.json()['proof_id']}").json()
    return r.json(), proof


def test_a_proof_is_signed_by_the_node_key_and_names_it(signer_mode, client):
    demo, proof = _demo_proof(client)
    published = client.get("/v1/pubkey").json()
    assert demo["kid"] == "key-9"
    assert published["kid"] == "key-9"
    chain = proof["hashes"]["chain"].replace("sha256:", "")
    assert verify_proof_signature(published["pubkey"], chain, demo["signature"])


def test_pubkey_and_did_document_publish_the_whole_history(signer_mode, client):
    published = client.get("/v1/pubkey").json()
    assert [k["kid"] for k in published["keys"]] == ["key-1", "key-9"]
    assert published["rekor_kid"] == "rekor-9"
    did = client.get("/.well-known/did.json").json()
    ids = [m["id"].rsplit("#", 1)[1] for m in did["verificationMethod"]]
    assert ids[0] == "key-9" and "key-1" in ids
    assert [a.rsplit("#", 1)[1] for a in did["assertionMethod"]] == ["key-9"]


def test_signer_mode_never_creates_a_private_key_file(signer_mode, client):
    _, tmp = signer_mode
    _demo_proof(client)
    client.get("/v1/pubkey")
    from trust_layer.rekor import _build_entry
    entry = _build_entry("c" * 64)
    assert entry["spec"]["signature"]["content"]
    assert not list(tmp.glob("must-not-exist*"))


def test_a_node_key_missing_from_the_registry_refuses_to_start(signer_mode, tmp_path):
    from trust_layer.signing import SignerError, check_registered
    node, _ = signer_mode
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"keys": [{"kid": "key-9", "public": KEY_1}]}))
    with pytest.raises(SignerError):
        check_registered(node, other)


def test_an_absent_socket_refuses_to_start(tmp_path):
    from trust_layer.signing import SignerError, SocketSigner
    with pytest.raises(SignerError):
        SocketSigner(tmp_path / "nowhere.sock")
