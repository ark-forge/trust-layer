"""Attestation — POST /attest + GET /receipt/{attestationId}.

Provider-agnostic execution attestation compatible with Encina HttpAttestationProvider.
Artifact type: attestation/1.0 (sibling to proof, stored separately in data/attestations/).

Chain hash formula:
    SHA256(canonical_json({
        content_hash, record_id, record_type,
        occurred_at_utc, attested_at_utc, attester_fingerprint
    }))
"""

import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .config import ATTESTATIONS_DIR
from .crypto import sign_proof
from .persistence import save_json, load_json
from .proofs import canonical_json, sha256_hex

ATTESTATION_SPEC_VERSION = "attestation/1.0"


def generate_attestation_id() -> str:
    """Generate attestation ID: att_YYYYMMDD_HHMMSS_<6hex>."""
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y%m%d_%H%M%S")
    rand = secrets.token_hex(3)
    return f"att_{ts}_{rand}"


def build_attestation(
    record_id: str,
    record_type: str,
    occurred_at_utc: str,
    content_hash: str,
    attester_fingerprint: str,
    signing_key: Ed25519PrivateKey,
) -> dict:
    """Build and sign an attestation record.

    Returns the full attestation dict ready for storage.
    Raises ValueError on invalid inputs.
    """
    if not record_id:
        raise ValueError("recordId is required")
    if not record_type:
        raise ValueError("recordType is required")
    if not occurred_at_utc:
        raise ValueError("occurredAtUtc is required")
    if not content_hash:
        raise ValueError("contentHash is required")

    # Validate occurredAtUtc is parseable ISO 8601
    try:
        datetime.fromisoformat(occurred_at_utc.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"occurredAtUtc is not valid ISO 8601: {occurred_at_utc!r}")

    attested_at_utc = datetime.now(timezone.utc).isoformat()
    attestation_id = generate_attestation_id()

    # Canonical chain hash
    chain_data = {
        "attested_at_utc": attested_at_utc,
        "attester_fingerprint": attester_fingerprint,
        "content_hash": content_hash,
        "occurred_at_utc": occurred_at_utc,
        "record_id": record_id,
        "record_type": record_type,
    }
    chain_hash = sha256_hex(canonical_json(chain_data))
    signature = sign_proof(signing_key, chain_hash)

    return {
        "attestation_id": attestation_id,
        "spec_version": ATTESTATION_SPEC_VERSION,
        "record_id": record_id,
        "record_type": record_type,
        "occurred_at_utc": occurred_at_utc,
        "content_hash": content_hash,
        "attested_at_utc": attested_at_utc,
        "attester_fingerprint": attester_fingerprint,
        "hashes": {
            "chain": f"sha256:{chain_hash}",
        },
        "signature": signature,
    }


def store_attestation(attestation: dict) -> None:
    """Atomic write to ATTESTATIONS_DIR/{attestation_id}.json."""
    att_id = attestation["attestation_id"]
    path = ATTESTATIONS_DIR / f"{att_id}.json"
    save_json(path, attestation)


def load_attestation(attestation_id: str) -> Optional[dict]:
    """Load attestation by ID. Returns None if not found."""
    path = ATTESTATIONS_DIR / f"{attestation_id}.json"
    if not path.exists():
        return None
    return load_json(path)


def find_by_record_id(record_id: str, attester_fingerprint: str) -> Optional[dict]:
    """Idempotency: return existing attestation for (record_id, attester_fingerprint).

    Scans ATTESTATIONS_DIR — acceptable at current volume.
    Returns None if no match found.
    """
    if not ATTESTATIONS_DIR.exists():
        return None
    for path in ATTESTATIONS_DIR.glob("att_*.json"):
        data = load_json(path)
        if (
            data.get("record_id") == record_id
            and data.get("attester_fingerprint") == attester_fingerprint
        ):
            return data
    return None


def attestation_to_encina_response(attestation: dict) -> dict:
    """Format attestation as Encina HttpAttestationProvider receipt."""
    chain_hash = attestation.get("hashes", {}).get("chain", "")
    return {
        "attestationId": attestation["attestation_id"],
        "auditRecordId": attestation["record_id"],
        "signature": attestation["signature"],
        "attestedAtUtc": attestation["attested_at_utc"],
        "proofMetadata": {
            "specVersion": attestation["spec_version"],
            "chainHash": chain_hash,
            "attesterFingerprint": attestation["attester_fingerprint"],
        },
    }
