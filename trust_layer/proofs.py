"""Proof generation, storage, and verification — SHA-256 chain."""

import json
import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import PROOFS_DIR
from .persistence import save_json, load_json


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
) -> dict:
    """Generate a proof with request/response/chain hashes + party identities."""
    request_hash = sha256_hex(canonical_json(request_data))
    response_hash = sha256_hex(canonical_json(response_data))

    # Chain hash does NOT include identity — identity is metadata, not integrity
    payment_intent_id = payment_data.get("transaction_id", "")
    chain_input = request_hash + response_hash + payment_intent_id + timestamp + buyer_fingerprint + seller
    chain_hash = sha256_hex(chain_input)

    return {
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
        "payment": payment_data,
        "timestamp": timestamp,
        "_raw_request_hash": request_hash,
        "_raw_response_hash": response_hash,
        "_raw_chain_hash": chain_hash,
    }


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
    """Recalculate chain hash and compare — public verification."""
    hashes = proof.get("hashes", {})
    payment = proof.get("payment", {})
    parties = proof.get("parties", {})
    timestamp = proof.get("timestamp", "")

    request_hash = hashes.get("request", "").replace("sha256:", "")
    response_hash = hashes.get("response", "").replace("sha256:", "")
    expected_chain = hashes.get("chain", "").replace("sha256:", "")

    payment_intent_id = payment.get("transaction_id", "")
    buyer_fingerprint = parties.get("buyer_fingerprint", "")
    seller = parties.get("seller", "")
    chain_input = request_hash + response_hash + payment_intent_id + timestamp + buyer_fingerprint + seller
    computed_chain = sha256_hex(chain_input)

    return computed_chain == expected_chain


def get_public_proof(proof: dict) -> dict:
    """Return proof data safe for public access (no raw request/response content)."""
    return {
        "proof_id": proof.get("proof_id"),
        "hashes": proof.get("hashes"),
        "parties": proof.get("parties"),
        "payment": {
            k: v for k, v in proof.get("payment", {}).items()
            if k in ("transaction_id", "amount", "currency", "status", "receipt_url", "provider")
        },
        "timestamp_authority": proof.get("timestamp_authority"),
        "archive_org": proof.get("archive_org"),
        "timestamp": proof.get("timestamp"),
        "verification_algorithm": proof.get("verification_algorithm"),
        "identity_consistent": proof.get("identity_consistent"),
        "views_count": proof.get("views_count", 0),
    }
