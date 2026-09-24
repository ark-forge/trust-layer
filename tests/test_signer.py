"""tl-signer socket protocol (P5a): the only seam the Trust Layer has to its keys."""

import json
import socket
import threading

import pytest

from signer import tl_signer
from trust_layer.crypto import verify_proof_signature

CHAIN = "a" * 64


@pytest.fixture
def signer(tmp_path):
    sock = tmp_path / "sign.sock"
    server = tl_signer.build_server(
        state_dir=tmp_path / "state", sock_path=sock,
        kid="key-9", rekor_kid="rekor-9", did="did:web:test.arkforge.fr",
    )
    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    t.start()
    yield sock, tmp_path / "state"
    server.shutdown()
    server.server_close()


def call(sock, request):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(str(sock))
        s.sendall((json.dumps(request) + "\n").encode())
        return json.loads(s.makefile().readline())


def test_signs_a_chain_hash_with_the_key_it_publishes(signer):
    sock, _ = signer
    keys = call(sock, {"op": "pubkeys"})
    signed = call(sock, {"op": "sign_chain_hash", "chain_hash": CHAIN})
    assert signed["kid"] == "key-9"
    assert verify_proof_signature(keys["ed25519"]["public"], CHAIN, signed["signature"])


@pytest.mark.parametrize("request_", [
    {"op": "sign_chain_hash", "chain_hash": "A" * 64},
    {"op": "sign_chain_hash", "chain_hash": "a" * 63},
    {"op": "sign_chain_hash", "chain_hash": "a" * 64 + "\n"},
    {"op": "sign_chain_hash", "chain_hash": 42},
    {"op": "sign_reputation", "payload": "anything:else"},
    {"op": "export_key"},
    {"op": "sign", "data": "raw bytes please"},
])
def test_refuses_anything_outside_the_closed_operations(signer, request_):
    sock, _ = signer
    assert "error" in call(sock, request_)


def test_refuses_an_oversized_request(signer):
    sock, _ = signer
    resp = call(sock, {"op": "sign_chain_hash", "chain_hash": CHAIN, "pad": "x" * 20000})
    assert "error" in resp


def test_no_response_ever_carries_private_material(signer):
    sock, _ = signer
    for req in ({"op": "pubkeys"}, {"op": "sign_chain_hash", "chain_hash": CHAIN}):
        assert "PRIVATE" not in json.dumps(call(sock, req))


def test_keys_are_born_once_and_kept_private(signer, tmp_path):
    sock, state = signer
    first = call(sock, {"op": "pubkeys"})
    assert oct(state.stat().st_mode & 0o777) == "0o700"
    for f in state.iterdir():
        assert oct(f.stat().st_mode & 0o777) == "0o600"
    again = tl_signer.Signer(state, "key-9", "rekor-9", "did:web:test.arkforge.fr")
    assert again.ed_public == first["ed25519"]["public"]
    assert again.rekor_public_pem == first["rekor"]["public_pem"]


def test_signs_the_reputation_statement_format(signer):
    sock, _ = signer
    statement = "sha256:" + "b" * 64 + ":87:2026-09-24T10:00:00.123456+00:00"
    keys = call(sock, {"op": "pubkeys"})
    signed = call(sock, {"op": "sign_reputation", "payload": statement})
    assert verify_proof_signature(keys["ed25519"]["public"], statement, signed["signature"])


def test_builds_the_jws_itself_with_its_own_kid(signer):
    from trust_layer.crypto import verify_jws, _b64url_decode
    sock, _ = signer
    keys = call(sock, {"op": "pubkeys"})
    signed = call(sock, {"op": "sign_jws", "payload": {"certified": True}})
    header = json.loads(_b64url_decode(signed["jws"].split(".")[0]))
    assert header == {"alg": "EdDSA", "kid": "did:web:test.arkforge.fr#key-9"}
    pub = keys["ed25519"]["public"].split(":", 1)[1]
    assert verify_jws(pub, signed["jws"]) == {"certified": True}


def test_refuses_a_jws_header_or_an_oversized_payload(signer):
    sock, _ = signer
    assert "error" in call(sock, {"op": "sign_jws", "payload": "h.p"})
    assert "error" in call(sock, {"op": "sign_jws", "payload": {"x": "y" * 9000}})


def test_signs_a_rekor_artifact_with_the_published_rekor_key(signer):
    import base64
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    sock, _ = signer
    keys = call(sock, {"op": "pubkeys"})
    signed = call(sock, {"op": "sign_rekor", "chain_hash": CHAIN})
    assert signed["kid"] == "rekor-9"
    pub = serialization.load_pem_public_key(keys["rekor"]["public_pem"].encode())
    pub.verify(base64.b64decode(signed["signature"]), CHAIN.encode(), ec.ECDSA(hashes.SHA256()))
    assert "error" in call(sock, {"op": "sign_rekor", "chain_hash": "zz"})
