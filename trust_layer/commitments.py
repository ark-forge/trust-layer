"""Per-field commitments — spec 3.0 chain hash, with selective disclosure.

Spec 1.2/2.1 hashed the chain over the field values themselves. The public proof
redacts ``parties`` and ``certification_fee``, so a third party could never
recompute that hash: the published verification procedure either skipped the
check or, worse, reported TAMPERED against an honest issuer.

Spec 3.0 closes that hole without publishing anything new. Each chain field gets
its own commitment::

    commitment = sha256(field_name || 0x00 || nonce || canonical_json(value))

and ``hashes.chain`` *becomes* the Merkle root of those commitments. The public
proof carries the commitments, never the nonces, so:

  - a third party recomputes the anchored chain hash from public data alone;
  - ``transaction_id`` and ``buyer_fingerprint`` stay hidden;
  - the owner discloses any single field out of band by handing over
    ``(field, nonce, value)``, which the verifier checks against the published
    commitment — without learning the other fields.

Three details are load-bearing:

  - **field name in the preimage**: without domain separation, a commitment over
    an equal value moves between slots during a partial disclosure.
  - **one fresh 32-byte nonce per field AND per proof**: per-field protects
    low-entropy values (an amount, a seller) once a neighbouring field is
    disclosed; per-proof stops equal commitments from linking two proofs.
  - **canonical_json of the value**, never ``str()``: ``100`` and ``"100"`` must
    not collide.
"""

import hashlib
import hmac
import secrets
from typing import Dict, Optional, Tuple

from .proofs import canonical_json

SPEC_VERSION_COMMITMENTS = "3.0"

NONCE_BYTES = 32

# Field order is the sorted key order, which a third party reconstructs from the
# published commitments alone. No separate ordering to publish or to trust.


def commit(field: str, nonce: bytes, value) -> bytes:
    """Commitment to one field: sha256(field || 0x00 || nonce || canonical_json(value))."""
    if len(nonce) != NONCE_BYTES:
        raise ValueError(f"commit: nonce must be {NONCE_BYTES} bytes, got {len(nonce)}")
    preimage = field.encode("utf-8") + b"\x00" + nonce + canonical_json(value).encode("utf-8")
    return hashlib.sha256(preimage).digest()


def commitments_root(commitments: Dict[str, str]) -> str:
    """Merkle root (hex) over the commitments, leaves ordered by field name.

    ``commitments`` maps field -> hex digest (with or without the ``sha256:``
    prefix). This is the spec 3.0 chain hash.
    """
    from .merkle import leaf_hash, merkle_root

    if not commitments:
        raise ValueError("commitments_root: no commitments to hash")
    leaves = [
        leaf_hash(bytes.fromhex(commitments[field].replace("sha256:", "")))
        for field in sorted(commitments)
    ]
    return merkle_root(leaves).hex()


def build_commitments(chain_data: dict) -> Tuple[Dict[str, str], Dict[str, str], str]:
    """Commit to every chain field. Returns (commitments, nonces, chain_hash).

    ``commitments`` and ``nonces`` are hex-keyed by field name; nonces are
    secret and must never reach a public response.
    """
    commitments: Dict[str, str] = {}
    nonces: Dict[str, str] = {}
    for field, value in chain_data.items():
        nonce = secrets.token_bytes(NONCE_BYTES)
        nonces[field] = nonce.hex()
        commitments[field] = f"sha256:{commit(field, nonce, value).hex()}"
    return commitments, nonces, commitments_root(commitments)


def verify_disclosure(field: str, nonce_hex: str, value, commitment: str) -> bool:
    """Check a disclosed (field, nonce, value) triplet against its commitment."""
    try:
        nonce = bytes.fromhex(nonce_hex)
        expected = bytes.fromhex((commitment or "").replace("sha256:", ""))
    except ValueError:
        return False
    if len(nonce) != NONCE_BYTES or len(expected) != 32:
        return False
    return hmac.compare_digest(commit(field, nonce, value), expected)


def disclosure_bundle(nonces: Dict[str, str], chain_data: dict,
                      fields: Optional[list] = None) -> dict:
    """Build the out-of-band disclosure the owner hands to a third party.

    ``{"proof_id": ..., "disclosed": {field: {"nonce": hex, "value": ...}}}``.
    ``fields=None`` discloses everything the owner holds.
    """
    selected = sorted(nonces) if fields is None else [f for f in fields if f in nonces]
    return {
        "disclosed": {
            field: {"nonce": nonces[field], "value": chain_data.get(field)}
            for field in selected
        }
    }
