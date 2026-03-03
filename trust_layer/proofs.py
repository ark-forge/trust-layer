"""Proof generation, storage, and verification — SHA-256 chain."""

import json
import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import PROOFS_DIR
from .persistence import save_json, load_json

SPEC_VERSION = "1.1"
SPEC_VERSION_RECEIPT = "2.0"


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
    upstream_timestamp: Optional[str] = None,
    receipt_content_hash: Optional[str] = None,
    provider_payment: Optional[dict] = None,
) -> dict:
    """Generate a proof with request/response/chain hashes + party identities."""
    request_hash = sha256_hex(canonical_json(request_data))
    response_hash = sha256_hex(canonical_json(response_data))

    # Chain hash does NOT include identity — identity is metadata, not integrity
    payment_intent_id = payment_data.get("transaction_id", "")
    chain_input = request_hash + response_hash + payment_intent_id + timestamp + buyer_fingerprint + seller
    if upstream_timestamp:
        chain_input += upstream_timestamp
    if receipt_content_hash:
        chain_input += receipt_content_hash
    chain_hash = sha256_hex(chain_input)

    # Spec version: 2.0 if receipt evidence is included, 1.1 otherwise
    spec_version = SPEC_VERSION_RECEIPT if receipt_content_hash else SPEC_VERSION

    result = {
        "spec_version": spec_version,
        "hashes": {
            "request": f"sha256:{request_hash}",
            "response": f"sha256:{response_hash}",
            "chain": f"sha256:{chain_hash}",
        },
        "parties": {
            "buyer_fingerprint": buyer_fingerprint,
            "seller": seller,
            "agent_identity": agent_identity,
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
    chain_input = request_hash + response_hash + payment_intent_id + timestamp + buyer_fingerprint + seller

    upstream_timestamp = proof.get("upstream_timestamp")
    if upstream_timestamp:
        chain_input += upstream_timestamp

    # Receipt content hash (spec v2.0+)
    pe = proof.get("provider_payment") or {}
    receipt_content_hash = pe.get("receipt_content_hash", "")
    if receipt_content_hash:
        # Strip "sha256:" prefix if present
        receipt_content_hash = receipt_content_hash.replace("sha256:", "")
        chain_input += receipt_content_hash

    computed_chain = sha256_hex(chain_input)

    return computed_chain == expected_chain


def get_public_proof(proof: dict) -> dict:
    """Return proof data safe for public access (no raw request/response content)."""
    result = {
        "proof_id": proof.get("proof_id"),
        "spec_version": proof.get("spec_version"),
        "hashes": proof.get("hashes"),
        "parties": proof.get("parties"),
        "certification_fee": {
            k: v for k, v in proof.get("certification_fee", {}).items()
            if k in ("transaction_id", "amount", "currency", "status", "method")
        },
        "timestamp_authority": proof.get("timestamp_authority"),
        "timestamp": proof.get("timestamp"),
        "upstream_timestamp": proof.get("upstream_timestamp"),
        "verification_algorithm": proof.get("verification_algorithm"),
        "arkforge_signature": proof.get("arkforge_signature"),
        "arkforge_pubkey": proof.get("arkforge_pubkey"),
        "identity_consistent": proof.get("identity_consistent"),
        "provider_payment": proof.get("provider_payment"),
        "views_count": proof.get("views_count", 0),
        "transaction_success": proof.get("transaction_success"),
        "upstream_status_code": proof.get("upstream_status_code"),
        "disputed": proof.get("disputed"),
        "dispute_id": proof.get("dispute_id"),
        "buyer_reputation_score": proof.get("buyer_reputation_score"),
        "buyer_profile_url": proof.get("buyer_profile_url"),
    }
    return result
