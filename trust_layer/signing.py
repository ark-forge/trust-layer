"""Signing seam: the in-process legacy key, or the tl-signer socket.

Callers never touch a private key. They ask `config.get_signer()` for a signer and
use its closed operations, the same ones tl-signer serves (signer/tl_signer.py):
chain hash, reputation statement, JWS built by the signer, Rekor artifact.

Legacy mode (default until the switch): the Ed25519 key is the .pem next to the
package, kid `key-1`; the Rekor key is `rekor-1`. Signer mode (TL_SIGNER_SOCKET set):
no key file is read or created, the public keys come from the socket at startup.
"""

import base64
import json
import socket
from pathlib import Path

from .crypto import get_public_key_b64url, sign_jws, sign_proof, verify_proof_signature

LEGACY_KID = "key-1"
LEGACY_REKOR_KID = "rekor-1"
GATEWAY_DID = "did:web:trust.arkforge.tech"
SOCKET_TIMEOUT = 5.0
# sha256("tl-signer self-test"): signed at startup, verified with the published key.
SELF_TEST_HASH = "0c81932a6a92f6612e9b61f221c1af652d972f23736b6b5f8f63b233ed710234"


class SignerError(RuntimeError):
    """The signer is unreachable, refused the request, or is not published."""


class LocalSigner:
    """Legacy: the private keys live in this process (.pem files)."""

    def __init__(self, ed_key, kid: str = LEGACY_KID, rekor_kid: str = LEGACY_REKOR_KID,
                 did: str = GATEWAY_DID):
        self._ed = ed_key
        self.kid, self.rekor_kid, self.did = kid, rekor_kid, did
        self.public = get_public_key_b64url(ed_key)

    @property
    def rekor_public_pem(self) -> str:
        from cryptography.hazmat.primitives import serialization
        from .rekor import _get_or_create_rekor_ec_key
        return _get_or_create_rekor_ec_key().public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def ping(self) -> None:
        """In-process key: always reachable."""

    def sign_chain_hash(self, chain_hash: str) -> str:
        return sign_proof(self._ed, chain_hash)

    def sign_reputation(self, statement: str) -> str:
        return sign_proof(self._ed, statement)

    def sign_jws(self, payload: dict) -> str:
        return sign_jws(self._ed, {"alg": "EdDSA", "kid": f"{self.did}#{self.kid}"}, payload)

    def sign_rekor(self, chain_hash: str) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from .rekor import _get_or_create_rekor_ec_key
        der = _get_or_create_rekor_ec_key().sign(chain_hash.encode("utf-8"),
                                                 ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(der).decode("ascii")


class SocketSigner:
    """Signer mode: every signature is a request to tl-signer. Fails fast at startup."""

    def __init__(self, sock_path):
        self.sock_path = Path(sock_path)
        keys = self._call({"op": "pubkeys"})
        self.kid = keys["ed25519"]["kid"]
        self.public = keys["ed25519"]["public"]
        self.rekor_kid = keys["rekor"]["kid"]
        self.rekor_public_pem = keys["rekor"]["public_pem"]
        self.did = keys["did"]
        # Proves at startup that this node signs with the key it will publish (the
        # standby canary of the deploy reads it in /v1/health).
        if not verify_proof_signature(self.public, SELF_TEST_HASH, self.sign_chain_hash(SELF_TEST_HASH)):
            raise SignerError("tl-signer signature does not verify with its own public key")

    def _call(self, request: dict) -> dict:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(SOCKET_TIMEOUT)
                s.connect(str(self.sock_path))
                s.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode())
                line = s.makefile("rb").readline()
        except OSError as e:
            raise SignerError(f"tl-signer unreachable at {self.sock_path}: {e}") from e
        try:
            resp = json.loads(line)
        except ValueError as e:
            raise SignerError("tl-signer sent no valid answer") from e
        if "error" in resp:
            raise SignerError(f"tl-signer refused {request.get('op')}: {resp['error']}")
        return resp

    def _signed(self, request: dict, field: str = "signature") -> str:
        resp = self._call(request)
        if resp.get("kid") not in (self.kid, self.rekor_kid):
            # The signer restarted with another key: this process publishes a stale one.
            raise SignerError("tl-signer key changed since startup, restart the Trust Layer")
        return resp[field]

    def ping(self) -> None:
        """Raise SignerError unless tl-signer answers with the key this process publishes."""
        if self._call({"op": "pubkeys"})["ed25519"]["kid"] != self.kid:
            raise SignerError("tl-signer key changed since startup, restart the Trust Layer")

    def sign_chain_hash(self, chain_hash: str) -> str:
        return self._signed({"op": "sign_chain_hash", "chain_hash": chain_hash})

    def sign_reputation(self, statement: str) -> str:
        return self._signed({"op": "sign_reputation", "payload": statement})

    def sign_jws(self, payload: dict) -> str:
        return self._signed({"op": "sign_jws", "payload": payload}, field="jws")

    def sign_rekor(self, chain_hash: str) -> str:
        return self._signed({"op": "sign_rekor", "chain_hash": chain_hash})


def signing_status(signer) -> dict:
    """What /v1/health says about signing on this node."""
    if signer is None:
        return {"mode": "none", "kid": None, "self_test": "failed"}
    if isinstance(signer, SocketSigner):
        return {"mode": "signer", "kid": signer.kid, "self_test": "ok"}  # checked at startup
    ok = verify_proof_signature(signer.public, SELF_TEST_HASH, signer.sign_chain_hash(SELF_TEST_HASH))
    return {"mode": "legacy", "kid": signer.kid, "self_test": "ok" if ok else "failed"}


def load_registry(path) -> list:
    """Published key history (trust_layer/published_keys.json), oldest first."""
    return json.loads(Path(path).read_text())["keys"]


def key_history(signer, registry_path) -> tuple[list, list]:
    """(Ed25519 keys, Rekor keys) to publish: the registry, plus the node keys if absent.

    Absent only in legacy mode or tests (signer mode refuses to start without them).
    """
    path = Path(registry_path)
    data = json.loads(path.read_text()) if path.exists() else {}
    ed = list(data.get("keys", []))
    rekor = list(data.get("rekor_keys", []))
    if signer.public not in [k.get("public") for k in ed]:
        ed.append({"kid": signer.kid, "type": "Ed25519", "public": signer.public,
                   "node": None, "valid_from": None, "retired_at": None})
    pem = signer.rekor_public_pem
    if pem and pem not in [k.get("public_pem") for k in rekor]:
        rekor.append({"kid": signer.rekor_kid, "type": "ECDSA-P256-SHA256", "public_pem": pem,
                      "node": None, "valid_from": None, "retired_at": None})
    return ed, rekor


def check_registered(signer, registry_path) -> None:
    """Signer mode refuses to start with a key nobody can find in the history."""
    for entry in load_registry(registry_path):
        if entry.get("kid") == signer.kid:
            if entry.get("public") != signer.public:
                raise SignerError(f"{signer.kid} in the registry is not the key tl-signer holds")
            if entry.get("retired_at"):
                raise SignerError(f"{signer.kid} is retired in the registry")
            return
    raise SignerError(f"{signer.kid} is not in the published key registry")
