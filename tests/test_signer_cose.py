"""sign_cose: COSE_Sign1 over a chain hash, built by tl-signer (design: docs/design/TLCOSE-S.md)."""

import ast
import base64
import hashlib
import json
import os
import threading
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from signer import tl_signer
from trust_layer import signing
from trust_layer.crypto import verify_proof_signature

CHAIN = "a" * 64
DID = "did:web:test.arkforge.fr"
KID = "key-9"
CONTENT_TYPE = "application/vnd.arkforge.chain-hash"
# Fixed test key (RFC 8032 style seed 00..1f); Ed25519 is deterministic.
FIXED_SEED = bytes(range(32))
# Computed once with an assembler independent of both encoders, then frozen.
FROZEN_COSE = bytes.fromhex(
    "d28458b1a401320378236170706c69636174696f6e2f766e642e61726b666f7267652e636861696e2d6861"
    "736804581e6469643a7765623a746573742e61726b666f7267652e6672236b65792d390fa2017818646964"
    "3a7765623a746573742e61726b666f7267652e66720278477368613235363a616161616161616161616161"
    "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161"
    "616161616161616161a05820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aa584098b7c346c23328d428b4de56c1b0c5333538ca6e7d9370fa19ebdab6950555173b7db1f07908f590"
    "10ef4c583afcb3cec5fc22f587d769f92cfc9f6133ee7d01"
)


# ---- independent minimal CBOR decoder (definite lengths only) -------------------------

class Tagged:
    def __init__(self, tag, value):
        self.tag, self.value = tag, value


def cbor_decode(data: bytes):
    value, pos = _item(data, 0)
    assert pos == len(data), "trailing bytes after the CBOR item"
    return value


def _item(d, i):
    major, info = d[i] >> 5, d[i] & 0x1F
    i += 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        n = 1 << (info - 24)
        arg = int.from_bytes(d[i:i + n], "big")
        i += n
    else:
        raise AssertionError("indefinite or reserved length")
    if major == 0:
        return arg, i
    if major == 1:
        return -1 - arg, i
    if major in (2, 3):
        raw = d[i:i + arg]
        assert len(raw) == arg
        return (raw if major == 2 else raw.decode("utf-8")), i + arg
    if major == 4:
        out = []
        for _ in range(arg):
            v, i = _item(d, i)
            out.append(v)
        return out, i
    if major == 5:
        out = {}
        for _ in range(arg):
            k, i = _item(d, i)
            v, i = _item(d, i)
            out[k] = v
        return out, i
    if major == 6:
        v, i = _item(d, i)
        return Tagged(arg, v), i
    raise AssertionError("unsupported major type")


# ---- fixtures -------------------------------------------------------------------------

def _write_key(state_dir: Path, seed: bytes):
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = Ed25519PrivateKey.from_private_bytes(seed)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    fd = os.open(state_dir / "ed25519.pem", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return key


@pytest.fixture
def served(tmp_path):
    """(signer, private key): a Signer on the fixed test key, called in-process.

    The wire path (socket) has its own test below; the sandbox of a dev run may forbid
    creating Unix sockets, so everything else goes through Signer.handle.
    """
    key = _write_key(tmp_path / "state", FIXED_SEED)
    signer = tl_signer.Signer(tmp_path / "state", KID, "rekor-9", DID)
    return signer, key


def call(signer, request):
    """What _Handler does around Signer.handle: JSON round trip, ValueError -> error."""
    try:
        resp = signer.handle(json.loads(json.dumps(request)))
    except ValueError as e:
        resp = {"error": str(e)}
    return json.loads(json.dumps(resp))


class InProcessSocketSigner(signing.SocketSigner):
    """The real client logic (_signed, kid check, decoding), wire replaced by handle()."""

    def __init__(self, signer):
        self._signer = signer
        super().__init__("/nonexistent")

    def _call(self, request):
        resp = call(self._signer, request)
        if "error" in resp:
            raise signing.SignerError(resp["error"])
        return resp


def cose_bytes(signer, chain=CHAIN, **extra):
    resp = call(signer, {"op": "sign_cose", "chain_hash": chain, **extra})
    return base64.urlsafe_b64decode(resp["cose"] + "=" * (-len(resp["cose"]) % 4))


def parse(cose: bytes):
    tagged = cbor_decode(cose)
    protected_bytes, unprotected, payload, signature = tagged.value
    return tagged, protected_bytes, unprotected, payload, signature


def sig_structure(protected_bytes: bytes, payload: bytes) -> bytes:
    """RFC 9052 s4.4, assembled by hand: ["Signature1", protected, h'', payload]."""
    def bstr(x):
        return (bytes([0x58, len(x)]) if len(x) >= 24 else bytes([0x40 | len(x)])) + x
    return b"\x84\x6aSignature1" + bstr(protected_bytes) + b"\x40" + bstr(payload)


# ---- 1. structure ---------------------------------------------------------------------

def test_cose_output_parses_as_tag_18_with_four_elements(served):
    signer, _ = served
    resp = call(signer, {"op": "sign_cose", "chain_hash": CHAIN})
    assert resp["kid"] == KID
    assert "=" not in resp["cose"]
    tagged, protected_bytes, unprotected, payload, signature = parse(cose_bytes(signer))
    assert tagged.tag == 18
    assert len(tagged.value) == 4
    assert isinstance(protected_bytes, bytes)
    assert unprotected == {}
    assert payload == bytes.fromhex(CHAIN)
    assert len(signature) == 64


# ---- 2. signature ---------------------------------------------------------------------

def test_cose_signature_verifies_with_the_published_public_key(served):
    signer, _ = served
    public = call(signer, {"op": "pubkeys"})["ed25519"]["public"]
    raw = base64.urlsafe_b64decode(public.split(":", 1)[1] + "=")
    _, protected_bytes, _, payload, signature = parse(cose_bytes(signer))
    Ed25519PublicKey.from_public_bytes(raw).verify(signature, sig_structure(protected_bytes, payload))
    with pytest.raises(InvalidSignature):
        Ed25519PublicKey.from_public_bytes(raw).verify(
            signature, sig_structure(protected_bytes, bytes(32)))


# ---- 3. protected header --------------------------------------------------------------

def test_protected_header_carries_alg_kid_content_type_and_cwt_claims(served):
    signer, _ = served
    _, protected_bytes, _, _, _ = parse(cose_bytes(signer))
    header = cbor_decode(protected_bytes)
    assert list(header) == [1, 3, 4, 15]  # deterministic key order
    assert header[1] == -19
    assert header[3] == CONTENT_TYPE
    assert header[4] == f"{DID}#{KID}".encode()
    assert header[15] == {1: DID, 2: "sha256:" + CHAIN}


# ---- 4. validation --------------------------------------------------------------------

@pytest.mark.parametrize("chain", ["a" * 63, "a" * 65, "A" * 64, "g" * 64, "a" * 64 + "\n", 42, None])
def test_refuses_a_malformed_chain_hash_and_signs_nothing(served, chain):
    signer, _ = served
    calls = []

    class Spy:
        def sign(self, data):
            calls.append(data)
            return bytes(64)

    signer._ed = Spy()
    resp = call(signer, {"op": "sign_cose", "chain_hash": chain})
    assert "error" in resp and "cose" not in resp
    assert calls == []


def test_refuses_a_missing_chain_hash_and_signs_nothing(served):
    signer, _ = served
    calls = []

    class Spy:
        def sign(self, data):
            calls.append(data)
            return bytes(64)

    signer._ed = Spy()
    resp = call(signer, {"op": "sign_cose"})
    assert "error" in resp and "cose" not in resp
    assert calls == []


def test_accepts_a_well_formed_chain_hash_and_ignores_unknown_fields(served):
    signer, _ = served
    plain = cose_bytes(signer)
    assert cose_bytes(signer, whatever="x", extra=[1, 2]) == plain


# ---- 6. frozen vector -----------------------------------------------------------------

def test_fixed_key_and_input_give_the_frozen_cose_bytes(served):
    signer, _ = served
    assert cose_bytes(signer) == FROZEN_COSE


# ---- 7. both encoders agree -----------------------------------------------------------

def test_local_socket_and_signer_outputs_are_byte_identical(served):
    signer, key = served
    from_signer = cose_bytes(signer)
    local = signing.LocalSigner(key, kid=KID, did=DID)
    remote = InProcessSocketSigner(signer)
    assert local.sign_cose(CHAIN) == from_signer
    assert remote.sign_cose(CHAIN) == from_signer
    assert isinstance(local.sign_cose(CHAIN), bytes)


def test_local_signer_refuses_a_malformed_chain_hash_and_signs_nothing(served):
    _, key = served
    calls = []

    class Spy:
        def sign(self, data):
            calls.append(data)
            return bytes(64)

    local = signing.LocalSigner(key, kid=KID, did=DID)
    local._ed = Spy()
    for bad in ("A" * 64, "a" * 63, "a" * 64 + "\n", 42):
        with pytest.raises(ValueError):
            local.sign_cose(bad)
    assert calls == []


def test_the_two_cbor_encoders_agree_on_every_supported_type():
    value = {"b": [1, -1, 23, 24, 255, 256, 65535, 65536, 2**32, 2**64 - 1, -(2**63)],
             1: b"\x00" * 30, 15: {"x": "é" * 30}, -3: tl_signer._Tag(18, [b"", ""])}
    mirrored = {"b": value["b"], 1: value[1], 15: value[15], -3: signing._Tag(18, [b"", ""])}
    assert tl_signer._cbor(value) == signing._cbor(mirrored)


# ---- 8. caller cannot steer the message ----------------------------------------------

def test_request_fields_protected_payload_kid_alg_aad_are_ignored(served):
    signer, _ = served
    steered = cose_bytes(signer, protected="a0", payload="00" * 32, kid="evil", alg=-8, aad="ff")
    assert steered == cose_bytes(signer) == FROZEN_COSE


# ---- 9. non-confusion (invariant I2) --------------------------------------------------

def test_cose_and_chain_hash_signatures_do_not_verify_across_messages(served):
    signer, _ = served
    public = call(signer, {"op": "pubkeys"})["ed25519"]["public"]
    _, protected_bytes, _, payload, signature = parse(cose_bytes(signer))
    structure = sig_structure(protected_bytes, payload)
    assert structure[0] == 0x84
    # COSE signature over the hex chain hash: no.
    cose_sig = "ed25519:" + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    assert not verify_proof_signature(public, CHAIN, cose_sig)
    # sign_chain_hash signature over the Sig_structure: no.
    plain = call(signer, {"op": "sign_chain_hash", "chain_hash": CHAIN})["signature"]
    raw = base64.urlsafe_b64decode(public.split(":", 1)[1] + "=")
    plain_raw = base64.urlsafe_b64decode(plain.split(":", 1)[1] + "==")
    with pytest.raises(InvalidSignature):
        Ed25519PublicKey.from_public_bytes(raw).verify(plain_raw, structure)


def test_header_states_invariant_i2():
    doc = tl_signer.__doc__
    assert "I2" in doc and "0x84" in doc


# ---- 10. encoder is closed ------------------------------------------------------------

@pytest.mark.parametrize("encode", [lambda v: tl_signer._cbor(v), lambda v: signing._cbor(v)])
@pytest.mark.parametrize("value", [1.5, None, True, False, {1, 2}, bytearray(b"x"), object(),
                                   2**64, -(2**64) - 1, {"a": 1.5}, [None], {1.5: 1}])
def test_cbor_encoder_raises_on_any_type_outside_its_list(encode, value):
    with pytest.raises(TypeError):
        encode(value)


def test_cbor_encoder_matches_rfc_8949_appendix_a_examples():
    for enc in (tl_signer._cbor, signing._cbor):
        assert enc(0) == b"\x00"
        assert enc(24) == b"\x18\x18"
        assert enc(1000) == b"\x19\x03\xe8"
        assert enc(1000000) == b"\x1a\x00\x0f\x42\x40"
        assert enc(-1) == b"\x20"
        assert enc(-1000) == b"\x39\x03\xe7"
        assert enc(b"\x01\x02\x03\x04") == b"\x44\x01\x02\x03\x04"
        assert enc("IETF") == b"\x64IETF"
        assert enc([1, [2, 3]]) == b"\x82\x01\x82\x02\x03"
        assert enc({}) == b"\xa0"
        assert enc({"b": 1, "a": 2}) == b"\xa2\x61a\x02\x61b\x01"
        assert enc({10: 1, 1: 2}) == b"\xa2\x01\x02\x0a\x01"


# ---- 11. existing operations untouched -----------------------------------------------

# sha256 of ast.dump() of each existing branch of Signer.handle at 4c2e05b.
EXISTING_BRANCHES = {
    "pubkeys": "e71a5a2d25408ae7ceaf9ab281b248cfa71b49f480577c56602b9c1b3d0c9e3e",
    "sign_chain_hash": "28b2af59a5919a78fd6edb17e3afc3559311008a8fdc067ac10407577801e1db",
    "sign_reputation": "0e46e6cf9bb4a20bd451af5d979d08141f837d293617257703b84b0d6c5f94af",
    "sign_jws": "703315fe662ec6c99689e0bc420fe32eab75f24d0484f21c27c47d056dcd9da2",
    "sign_rekor": "fcd81532dbc0b11984a9aeac502f46d9598c57dd47af0d20a2d7d0e1b78bffd2",
}


def test_existing_operation_branches_are_unchanged():
    tree = ast.parse(Path(tl_signer.__file__).read_text())
    handle = next(n for c in tree.body if isinstance(c, ast.ClassDef) and c.name == "Signer"
                  for n in c.body if isinstance(n, ast.FunctionDef) and n.name == "handle")
    found = {}
    for node in handle.body:
        if isinstance(node, ast.If) and isinstance(node.test, ast.Compare):
            found[node.test.comparators[0].value] = hashlib.sha256(
                ast.dump(node).encode()).hexdigest()
    assert {op: found.get(op) for op in EXISTING_BRANCHES} == EXISTING_BRANCHES


def test_cose_over_the_real_unix_socket_matches_the_frozen_bytes(tmp_path):
    key = _write_key(tmp_path / "state", FIXED_SEED)
    assert key
    try:
        server = tl_signer.build_server(state_dir=tmp_path / "state", sock_path=tmp_path / "s.sock",
                                        kid=KID, rekor_kid="rekor-9", did=DID)
    except PermissionError:
        pytest.skip("sandbox forbids creating Unix sockets")
    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    t.start()
    try:
        assert signing.SocketSigner(tmp_path / "s.sock").sign_cose(CHAIN) == FROZEN_COSE
    finally:
        server.shutdown()
        server.server_close()
