"""Proof generation, storage, and verification — SHA-256 chain."""

import json
import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import PROOFS_DIR
from .persistence import save_json, load_json

SPEC_VERSION = "3.1"          # 3.0 + the identity triple committed and publicly opened
SPEC_VERSION_COMMITMENTS = "3.0"  # per-field commitments, chain hash = their Merkle root
SPEC_VERSION_VALUES = "1.2"   # canonical_json over the values themselves (pre-3.0)
SPEC_VERSION_RECEIPT = "2.1"  # same, with receipt evidence

# Legacy spec versions that used concatenation — still verified for backward compat
_LEGACY_SPEC_VERSIONS = {"1.0", "1.1", "2.0", None}
# Spec versions whose chain hash is the Merkle root of per-field commitments.
_COMMITMENT_SPEC_VERSIONS = {"3.0", "3.1"}

# Spec 3.1: the identity triple joins the chain fields, so the anchors cover it.
# Up to 3.0 it was served publicly but committed nowhere, which left the issuer
# free to rewrite it after anchoring with every external witness still verifying.
IDENTITY_FIELDS = ("agent_identity", "agent_identity_verified", "did_resolution_status")
_IDENTITY_SPEC_VERSIONS = {"3.1"}

# These three are the only fields whose nonce is published. A commitment hides its
# value; these values must stay readable by a third party, so 3.1 trades hiding for
# openability on this triple and on nothing else.
_PUBLIC_NONCE_FIELDS = IDENTITY_FIELDS


def normalize_identity_verified(value) -> Optional[bool]:
    """``True`` or ``None`` — never ``False``.

    Called once, at the source, so ``parties`` and ``chain_data`` cannot disagree.
    A ``False`` stored on one side and a ``None`` on the other would make every
    unverified proof fail its own integrity check.
    """
    return True if value else None


def canonical_json(data: dict) -> str:
    """Deterministic JSON: sorted keys, no spaces."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(data: str) -> str:
    """SHA-256 hex digest of a string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def generate_proof_id() -> str:
    """Generate proof ID: prf_YYYYMMDD_HHMMSS_<6hex>."""
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%d_%H%M%S")
    rand = secrets.token_hex(3)
    return f"prf_{ts}_{rand}"


def generate_proof(
    request_data: dict,
    response_data: dict,
    payment_data: dict,
    timestamp: str,
    buyer_fingerprint: str = "",
    seller: str = "",
    agent_identity: Optional[str] = None,
    agent_version: Optional[str] = None,
    agent_identity_verified: Optional[bool] = None,
    did_resolution_status: Optional[str] = None,
    upstream_timestamp: Optional[str] = None,
    receipt_content_hash: Optional[str] = None,
    provider_payment: Optional[dict] = None,
) -> dict:
    """Generate a proof with request/response/chain hashes + party identities."""
    request_hash = sha256_hex(canonical_json(request_data))
    response_hash = sha256_hex(canonical_json(response_data))

    # Chain hash — canonical JSON eliminates preimage ambiguity from variable-length concat.
    # spec_version 1.2+ uses this method. Legacy 1.0/1.1/2.0 used raw string concatenation.
    payment_intent_id = payment_data.get("transaction_id", "")
    chain_data: dict = {
        "request_hash": request_hash,
        "response_hash": response_hash,
        "transaction_id": payment_intent_id,
        "timestamp": timestamp,
        "buyer_fingerprint": buyer_fingerprint,
        "seller": seller,
    }
    if upstream_timestamp:
        chain_data["upstream_timestamp"] = upstream_timestamp
    if receipt_content_hash:
        chain_data["receipt_content_hash"] = receipt_content_hash
    # Spec 3.1: the identity triple is always committed, including when it is absent.
    # Committing it only when present would let an issuer simply omit the fields and
    # leave the scorer with no commitment to refuse.
    identity_verified = normalize_identity_verified(agent_identity_verified)
    chain_data["agent_identity"] = agent_identity
    chain_data["agent_identity_verified"] = identity_verified
    chain_data["did_resolution_status"] = did_resolution_status
    # Spec 3.0: hashes.chain BECOMES the Merkle root of the per-field commitments.
    # Nothing that was public stops being public; what is public becomes sufficient.
    from .commitments import build_commitments
    commitments, commitment_nonces, chain_hash = build_commitments(chain_data)
    spec_version = SPEC_VERSION

    result = {
        "spec_version": spec_version,
        "commitments": commitments,
        "_commitment_nonces": commitment_nonces,
        "_chain_data": chain_data,
        "hashes": {
            "request": f"sha256:{request_hash}",
            "response": f"sha256:{response_hash}",
            "chain": f"sha256:{chain_hash}",
        },
        "parties": {
            "buyer_fingerprint": buyer_fingerprint,
            "seller": seller,
            "agent_identity": agent_identity,
            "agent_identity_verified": identity_verified,
            "did_resolution_status": did_resolution_status,
            "agent_version": agent_version,
        },
        "certification_fee": payment_data,
        "timestamp": timestamp,
        "_raw_request_hash": request_hash,
        "_raw_response_hash": response_hash,
        "_raw_chain_hash": chain_hash,
    }
    if upstream_timestamp:
        result["upstream_timestamp"] = upstream_timestamp
    if provider_payment:
        result["provider_payment"] = provider_payment
    return result


def store_proof(proof_id: str, proof_data: dict) -> Path:
    """Atomic write proof to proofs/<proof_id>.json. Returns path."""
    path = PROOFS_DIR / f"{proof_id}.json"
    save_json(path, proof_data)
    # Index for time-range queries (compliance reports). Never blocks proof writing.
    try:
        from .proof_index import get_proof_index
        fp = proof_data.get("parties", {}).get("buyer_fingerprint", "")
        ts_str = proof_data.get("timestamp", "")
        if fp and ts_str:
            from datetime import datetime, timezone
            ts_unix = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
            get_proof_index().record(fp, proof_id, ts_unix)
    except Exception:
        pass
    return path


def load_proof(proof_id: str) -> Optional[dict]:
    """Load a proof by ID. Returns None if not found."""
    path = PROOFS_DIR / f"{proof_id}.json"
    if not path.exists():
        return None
    return load_json(path)


def verify_proof_integrity(proof: dict) -> bool:
    """Recalculate chain hash and compare — public verification.

    Backward compatible: if upstream_timestamp is present and non-null,
    include it in the chain hash. Otherwise use the original formula.
    """
    hashes = proof.get("hashes", {})
    payment = proof.get("certification_fee", {})
    parties = proof.get("parties", {})
    timestamp = proof.get("timestamp", "")

    request_hash = hashes.get("request", "").replace("sha256:", "")
    response_hash = hashes.get("response", "").replace("sha256:", "")
    expected_chain = hashes.get("chain", "").replace("sha256:", "")

    payment_intent_id = payment.get("transaction_id", "")
    buyer_fingerprint = parties.get("buyer_fingerprint", "")
    seller = parties.get("seller", "")

    spec_version = proof.get("spec_version")
    upstream_timestamp = proof.get("upstream_timestamp")

    if spec_version in _COMMITMENT_SPEC_VERSIONS:
        from .commitments import commitments_root, verify_disclosure
        commitments = proof.get("commitments") or {}
        if not commitments:
            return False
        # A 3.1 proof that drops an identity commitment is not a 3.1 proof.
        if spec_version in _IDENTITY_SPEC_VERSIONS:
            if not set(IDENTITY_FIELDS) <= set(commitments):
                return False
        try:
            if commitments_root(commitments) != expected_chain:
                return False
        except ValueError:
            return False
        # Internally we hold the nonces and the values, so check every commitment too.
        # A third party holds neither and stops at the root, which is the point.
        nonces = proof.get("_commitment_nonces") or {}
        chain_data = proof.get("_chain_data")
        if nonces and chain_data is not None:
            if set(nonces) != set(commitments) or set(chain_data) != set(commitments):
                return False
            for field, commitment in commitments.items():
                if not verify_disclosure(field, nonces[field], chain_data[field], commitment):
                    return False
        return True

    # Receipt content hash (spec v2.0+)
    pe = proof.get("provider_payment") or {}
    receipt_content_hash = pe.get("receipt_content_hash", "")
    if receipt_content_hash:
        receipt_content_hash = receipt_content_hash.replace("sha256:", "")

    if spec_version in _LEGACY_SPEC_VERSIONS:
        # Legacy: raw string concatenation (spec 1.0, 1.1, 2.0 and unversioned proofs)
        chain_input = request_hash + response_hash + payment_intent_id + timestamp + buyer_fingerprint + seller
        if upstream_timestamp:
            chain_input += upstream_timestamp
        if receipt_content_hash:
            chain_input += receipt_content_hash
        computed_chain = sha256_hex(chain_input)
    else:
        # Current: canonical JSON (spec 1.2+) — eliminates preimage ambiguity
        chain_data: dict = {
            "request_hash": request_hash,
            "response_hash": response_hash,
            "transaction_id": payment_intent_id,
            "timestamp": timestamp,
            "buyer_fingerprint": buyer_fingerprint,
            "seller": seller,
        }
        if upstream_timestamp:
            chain_data["upstream_timestamp"] = upstream_timestamp
        if receipt_content_hash:
            chain_data["receipt_content_hash"] = receipt_content_hash
        computed_chain = sha256_hex(canonical_json(chain_data))

    return computed_chain == expected_chain


def strip_private(proof_record: dict) -> dict:
    """Drop the underscore-prefixed working fields before a record leaves the process.

    The owner already holds their proof, so this is not a disclosure boundary — but
    the commitment nonces are what keep every undisclosed field hidden, and they
    have exactly one deliberate way out: GET /v1/proof/{id}/full. Shipping them in
    every proxy response would scatter them through client logs instead.
    """
    return {k: v for k, v in proof_record.items() if not k.startswith("_")}


def get_public_proof(proof: dict) -> dict:
    """Return proof data safe for public access.

    Sensitive fields (parties, certification_fee, full provider_payment,
    buyer_reputation_score, buyer_profile_url) are redacted or removed.
    Use get_full_proof() for authenticated owner access.
    """
    is_demo = proof.get("is_demo", False)
    result = {
        "proof_id": proof.get("proof_id"),
        "is_demo": is_demo,
        "spec_version": proof.get("spec_version"),
        "hashes": proof.get("hashes"),
        "commitments": proof.get("commitments"),
        "batch_anchor": proof.get("batch_anchor"),
        "timestamp_authority": proof.get("timestamp_authority"),
        "timestamp": proof.get("timestamp"),
        "upstream_timestamp": proof.get("upstream_timestamp"),
        "verification_algorithm": proof.get("verification_algorithm"),
        "arkforge_signature": proof.get("arkforge_signature"),
        "arkforge_pubkey": proof.get("arkforge_pubkey"),
        "identity_consistent": proof.get("identity_consistent"),
        "views_count": proof.get("views_count", 0),
        "transaction_success": proof.get("transaction_success"),
        "upstream_status_code": proof.get("upstream_status_code"),
        "disputed": proof.get("disputed"),
        "dispute_id": proof.get("dispute_id"),
        "transparency_log": proof.get("transparency_log"),
        "agent_identity": proof.get("parties", {}).get("agent_identity"),
        "agent_identity_verified": proof.get("parties", {}).get("agent_identity_verified"),
        "did_resolution_status": proof.get("parties", {}).get("did_resolution_status"),
        "seller": proof.get("parties", {}).get("seller"),
    }
    # Spec 3.1: open the identity triple to everyone. The third party checks each
    # (field, nonce, value) against the commitment the anchors cover, instead of
    # taking the issuer's word for the flat fields above — which is exactly what
    # the DID binding existed to remove.
    if proof.get("spec_version") in _IDENTITY_SPEC_VERSIONS:
        nonces = proof.get("_commitment_nonces") or {}
        chain_data = proof.get("_chain_data") or {}
        disclosed = {}
        for field in _PUBLIC_NONCE_FIELDS:
            if field in nonces and field in chain_data:
                disclosed[field] = {"nonce": nonces[field], "value": chain_data[field]}
        if disclosed:
            result["disclosed"] = disclosed
            # Single source: a flat field can never show something other than the
            # value that actually opens the anchored commitment.
            for field, item in disclosed.items():
                result[field] = item["value"]
    if is_demo:
        result["demo_notice"] = (
            "This is a demo proof generated without a real upstream call. "
            "Sign your production AI calls — free up to 500/month: "
            "https://arkforge.tech/en/signup.html"
        )
    # Redact provider_payment: keep only type, hash, verification_status
    pp = proof.get("provider_payment")
    if pp:
        result["provider_payment"] = {
            "type": pp.get("type"),
            "receipt_content_hash": pp.get("receipt_content_hash"),
            "verification_status": pp.get("verification_status"),
        }
    else:
        result["provider_payment"] = None
    return result


def get_full_proof(proof: dict) -> dict:
    """Return complete proof including sensitive fields — owner-only access.

    Builds on get_public_proof() and restores: parties, certification_fee,
    full provider_payment, buyer_reputation_score, buyer_profile_url.
    """
    result = get_public_proof(proof)
    result["parties"] = proof.get("parties")
    result["certification_fee"] = {
        k: v for k, v in proof.get("certification_fee", {}).items()
        if k in ("transaction_id", "amount", "currency", "status", "method")
    }
    result["provider_payment"] = proof.get("provider_payment")
    result["buyer_reputation_score"] = proof.get("buyer_reputation_score")
    result["buyer_profile_url"] = proof.get("buyer_profile_url")
    # Selective disclosure material: the owner hands (field, nonce, value) triplets
    # out of band to whoever they choose. No dedicated endpoint, no signed bundle.
    if proof.get("_commitment_nonces"):
        result["commitment_nonces"] = proof.get("_commitment_nonces")
        result["chain_data"] = proof.get("_chain_data")
    return result
