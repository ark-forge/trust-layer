"""Trust Layer in signer mode: keys live in tl-signer, the API only sees a socket."""

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
    yield node, tmp_path, server
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
    _, tmp, _ = signer_mode
    _demo_proof(client)
    client.get("/v1/pubkey")
    from trust_layer.rekor import _build_entry
    entry = _build_entry("c" * 64)
    assert entry["spec"]["signature"]["content"]
    assert not list(tmp.glob("must-not-exist*"))


def test_a_node_key_missing_from_the_registry_refuses_to_start(signer_mode, tmp_path):
    from trust_layer.signing import SignerError, check_registered
    node, _, _ = signer_mode
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"keys": [{"kid": "key-9", "public": KEY_1}]}))
    with pytest.raises(SignerError):
        check_registered(node, other)


def test_an_absent_socket_refuses_to_start(tmp_path):
    from trust_layer.signing import SignerError, SocketSigner
    with pytest.raises(SignerError):
        SocketSigner(tmp_path / "nowhere.sock")


def test_health_shows_which_key_signs_on_this_node(signer_mode, client):
    signing = client.get("/v1/health").json()["signing"]
    assert signing == {"mode": "signer", "kid": "key-9", "self_test": "ok"}


def test_health_in_legacy_mode_names_key_1(client):
    signing = client.get("/v1/health").json()["signing"]
    assert signing["mode"] == "legacy" and signing["kid"] == "key-1"


# --- a paid request never loses its money to an unavailable signer ---------------

def _paid_key():
    from trust_layer.config import PRO_OVERAGE_PRICE, PROOF_PRICE
    from trust_layer.credits import add_credits
    from trust_layer.keys import create_api_key, update_overage_settings
    key = create_api_key("cus_sig", "ref_sig", "sig@test.com", test_mode=False, plan="pro")
    update_overage_settings(key, enabled=True, cap_eur=10.0, overage_rate=PRO_OVERAGE_PRICE)
    add_credits(key, round(PROOF_PRICE * 5, 2), "pi_sig_test")
    return key


async def _proxy(key, on_upstream=None):
    from unittest.mock import MagicMock, patch as upatch
    from trust_layer.proxy import execute_proxy
    resp = MagicMock(status_code=200, headers={"Date": "Mon, 02 Mar 2026 13:00:00 GMT"})
    resp.json.return_value = {"result": "ok"}

    async def upstream(*a, **k):
        if on_upstream:
            on_upstream()
        return resp
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.get.side_effect = upstream
    with upatch("trust_layer.proxy.check_rate_limit", return_value=(True, 0, True, "")), \
         upatch("trust_layer.proxy.httpx.AsyncClient", return_value=client), \
         upatch("trust_layer.proxy.add_proof_to_batch"), \
         upatch("trust_layer.proxy.send_proof_email"):
        return await execute_proxy(target="https://httpbin.org/get", method="GET", payload={},
                                   amount=0.0, currency="eur", api_key=key)


def _stop(server):
    server.shutdown()
    server.server_close()


@pytest.mark.asyncio
async def test_signer_down_before_the_charge_costs_nothing(signer_mode):
    from trust_layer.credits import get_balance
    from trust_layer.proxy import ProxyError
    key = _paid_key()
    before = get_balance(key)
    _stop(signer_mode[2])
    with pytest.raises(ProxyError) as e:
        await _proxy(key)
    assert e.value.status == 503 and e.value.code == "signing_unavailable"
    assert get_balance(key) == pytest.approx(before)


@pytest.mark.asyncio
async def test_signer_lost_after_the_charge_refunds_it(signer_mode):
    from trust_layer.credits import get_balance
    from trust_layer.proxy import ProxyError
    key = _paid_key()
    before = get_balance(key)
    with pytest.raises(ProxyError) as e:
        await _proxy(key, on_upstream=lambda: _stop(signer_mode[2]))
    assert e.value.status == 503 and e.value.code == "signing_unavailable"
    assert get_balance(key) == pytest.approx(before)
