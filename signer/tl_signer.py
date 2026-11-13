"""tl-signer: holds the Trust Layer private keys and signs through a Unix socket.

Runs as its own user, with no network, from a root-owned file (arkforge-infra, role
tl_signer). The Trust Layer reaches it through /run/tl-signer/sign.sock; whoever can
open the socket can sign, nobody can read a key. Keys are born here on first start,
one per node, and never leave the state directory: a lost key is replaced by a new
one, published next to the old ones (proof-spec, key history).

Protocol: one JSON object per line in, one JSON object per line out. Closed set of
operations, each with a bounded, validated input. No operation returns private key
material.

Invariant I2 (message partition): every operation signs messages whose first byte
differs from all the others among the Ed25519 operations. Chain hash starts with [0-9a-f]
(the Rekor input is signed by another key, ECDSA), reputation
with 's', JWS with 'e' ('eyJ'), COSE Sig_structure with 0x84 (CBOR array of 4). A new
operation must keep this partition, so a signature made for one operation can never be
replayed as another's. Headers, payload and aad of sign_cose are never taken from the
request, and its encoding is deterministic (header keys sorted 1, 3, 4, 15). sign_cose
has the same power as sign_chain_hash for whoever opens the socket, with stronger
semantics (iss = gateway DID): acceptable only while the gateway alone opens it.

Depends on the standard library and `cryptography` only (python3-cryptography from
the distribution), so the host does not need a venv.
"""

import base64
import json
import logging
import os
import re
import socket
import socketserver
import sys
import threading
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MAX_REQUEST = 16 * 1024
MAX_JWS_PAYLOAD = 8 * 1024
CHAIN_HASH = re.compile(r"[0-9a-f]{64}")
COSE_ALG_ED25519 = -19  # fully-specified Ed25519 (RFC 9864 as recalled, not verified offline)
COSE_CONTENT_TYPE = "application/vnd.arkforge.chain-hash"
# reputation.py signs "{agent_id}:{score}:{computed_at}".
REPUTATION = re.compile(
    r"sha256:[0-9a-f]{64}:\d{1,3}:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(\+00:00|Z)"
)

log = logging.getLogger("tl-signer")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class _Tag:
    """A CBOR tag (major type 6) around one value."""

    def __init__(self, number: int, value):
        self.number, self.value = number, value


def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    raise TypeError("CBOR length or integer out of range")


def _cbor(value) -> bytes:
    """Deterministic CBOR (RFC 8949 s4.2.1): shortest heads, map keys sorted by encoding.

    Supports int (not bool), bytes, str, list/tuple, dict and _Tag only; anything else
    raises TypeError. Duplicated in trust_layer/signing.py (this file imports nothing
    from the Trust Layer); tests assert both give the same bytes.
    """
    if isinstance(value, bool):
        raise TypeError("bool is not supported")
    if isinstance(value, int):
        return _cbor_head(0, value) if value >= 0 else _cbor_head(1, -1 - value)
    if isinstance(value, bytes):
        return _cbor_head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _cbor_head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _cbor_head(4, len(value)) + b"".join(_cbor(v) for v in value)
    if isinstance(value, dict):
        pairs = sorted((_cbor(k), _cbor(v)) for k, v in value.items())
        return _cbor_head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
    if isinstance(value, _Tag):
        return _cbor_head(6, value.number) + _cbor(value.value)
    raise TypeError(f"unsupported CBOR type: {type(value).__name__}")


def _load_or_create(path: Path, generate):
    """Load a PKCS8 key, or create it once. The file never leaves this process."""
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    log.info("generated %s", path.name)
    return key


class Signer:
    def __init__(self, state_dir: Path, kid: str, rekor_kid: str, did: str):
        state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.kid, self.rekor_kid, self.did = kid, rekor_kid, did
        self._ed = _load_or_create(state_dir / "ed25519.pem", Ed25519PrivateKey.generate)
        self._rekor = _load_or_create(
            state_dir / "rekor.pem", lambda: ec.generate_private_key(ec.SECP256R1())
        )
        self._lock = threading.Lock()
        self.counts = {}
        raw = self._ed.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.ed_public = f"ed25519:{_b64url(raw)}"
        self.rekor_public_pem = self._rekor.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")

    def _ed_sign(self, message: str) -> str:
        return f"ed25519:{_b64url(self._ed.sign(message.encode('utf-8')))}"

    def handle(self, req: dict) -> dict:
        op = req.get("op")
        if op == "pubkeys":
            return {
                "ed25519": {"kid": self.kid, "public": self.ed_public},
                "rekor": {"kid": self.rekor_kid, "public_pem": self.rekor_public_pem},
                "did": self.did,
            }
        if op == "sign_chain_hash":
            chain_hash = req.get("chain_hash")
            if not isinstance(chain_hash, str) or not CHAIN_HASH.fullmatch(chain_hash):
                raise ValueError("chain_hash must be 64 lowercase hex characters")
            return {"kid": self.kid, "signature": self._ed_sign(chain_hash)}
        if op == "sign_reputation":
            payload = req.get("payload")
            if not isinstance(payload, str) or not REPUTATION.fullmatch(payload):
                raise ValueError("payload is not a reputation statement")
            return {"kid": self.kid, "signature": self._ed_sign(payload)}
        if op == "sign_jws":
            # The header is ours, never the caller's.
            payload = req.get("payload")
            if not isinstance(payload, dict):
                raise ValueError("payload must be a JSON object")
            p = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if len(p) > MAX_JWS_PAYLOAD:
                raise ValueError("payload too large")
            h = json.dumps({"alg": "EdDSA", "kid": f"{self.did}#{self.kid}"},
                           separators=(",", ":")).encode("utf-8")
            signing_input = f"{_b64url(h)}.{_b64url(p)}"
            sig = self._ed.sign(signing_input.encode("ascii"))
            return {"kid": self.kid, "jws": f"{signing_input}.{_b64url(sig)}"}
        if op == "sign_rekor":
            # hashedrekord artifact = the chain hash itself (rekor.py).
            chain_hash = req.get("chain_hash")
            if not isinstance(chain_hash, str) or not CHAIN_HASH.fullmatch(chain_hash):
                raise ValueError("chain_hash must be 64 lowercase hex characters")
            der = self._rekor.sign(chain_hash.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
            return {"kid": self.rekor_kid, "signature": base64.b64encode(der).decode("ascii")}
        if op == "sign_cose":
            # COSE_Sign1 (RFC 9052) over the chain hash; header and payload are ours.
            chain_hash = req.get("chain_hash")
            if not isinstance(chain_hash, str) or not CHAIN_HASH.fullmatch(chain_hash):
                raise ValueError("chain_hash must be 64 lowercase hex characters")
            return {"kid": self.kid, "cose": _b64url(self._cose_sign1(chain_hash))}
        raise ValueError("unknown operation")

    def _cose_sign1(self, chain_hash: str) -> bytes:
        protected = _cbor({
            1: COSE_ALG_ED25519,
            3: COSE_CONTENT_TYPE,
            4: f"{self.did}#{self.kid}".encode("utf-8"),
            15: {1: self.did, 2: f"sha256:{chain_hash}"},  # CWT claims iss, sub (RFC 9597)
        })
        payload = bytes.fromhex(chain_hash)
        # Sig_structure, RFC 9052 s4.4.
        signature = self._ed.sign(_cbor(["Signature1", protected, b"", payload]))
        return _cbor(_Tag(18, [protected, {}, payload, signature]))

    def count(self, op: str) -> int:
        with self._lock:
            self.counts[op] = self.counts.get(op, 0) + 1
            return self.counts[op]


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline(MAX_REQUEST + 1)
        signer: Signer = self.server.signer
        try:
            if len(line) > MAX_REQUEST or not line.endswith(b"\n"):
                raise ValueError("request too long or not terminated")
            req = json.loads(line)
            if not isinstance(req, dict):
                raise ValueError("request must be a JSON object")
            resp = signer.handle(req)
            n = signer.count(req["op"])
            log.info("op=%s n=%d peer_uid=%s", req["op"], n, _peer_uid(self.request))
        except (ValueError, json.JSONDecodeError) as e:
            resp = {"error": str(e)}
            log.warning("refused: %s peer_uid=%s", e, _peer_uid(self.request))
        self.wfile.write((json.dumps(resp, separators=(",", ":")) + "\n").encode())


def _peer_uid(sock) -> str:
    try:
        creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        return str(int.from_bytes(creds[4:8], sys.byteorder))
    except OSError:
        return "?"


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def build_server(state_dir: Path, sock_path: Path, kid: str, rekor_kid: str, did: str,
                 listen_fd: int | None = None) -> _Server:
    """Server on sock_path, or on an inherited socket (systemd socket activation)."""
    if listen_fd is None:
        server = _Server(str(sock_path), _Handler)
    else:
        server = _Server(str(sock_path), _Handler, bind_and_activate=False)
        server.socket = socket.socket(fileno=listen_fd)
    server.signer = Signer(Path(state_dir), kid, rekor_kid, did)
    return server


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    env = os.environ
    listen_fd = 3 if env.get("LISTEN_FDS") == "1" and env.get("LISTEN_PID") == str(os.getpid()) else None
    server = build_server(
        state_dir=Path(env["STATE_DIRECTORY"]),
        sock_path=Path(env.get("TL_SIGNER_SOCKET", "/run/tl-signer/sign.sock")),
        kid=env["TL_SIGNER_KID"],
        rekor_kid=env["TL_SIGNER_REKOR_KID"],
        did=env["TL_SIGNER_DID"],
        listen_fd=listen_fd,
    )
    log.info("serving kid=%s rekor_kid=%s public=%s", server.signer.kid,
             server.signer.rekor_kid, server.signer.ed_public)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
