"""Sigstore Rekor transparency log — submit proof chain hash for public auditability.

Uses ECDSA P-256 + SHA-256 (hashedrekord v0.0.1), the format natively supported
by Rekor without Sigstore/Fulcio certificates. A dedicated EC key is generated
once and stored at REKOR_EC_KEY_PATH; it is separate from the Ed25519 signing key
used for arkforge_signature.
"""

import base64
import hashlib
import logging
import threading
import time
from pathlib import Path
from typing import Optional

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .config import REKOR_EC_KEY_PATH, REKOR_URL, REKOR_ENABLED

logger = logging.getLogger("trust_layer.rekor")

_MAX_RETRIES = 2
_BACKOFF_SECONDS = [2.0, 4.0]

# Thread-safe EC key cache
_ec_key_lock = threading.Lock()
_ec_key_cache = None


def _get_or_create_rekor_ec_key():
    """Load or generate the ECDSA P-256 key used for Rekor submissions.

    The key is generated once at first call and cached in-process.
    It is stored at REKOR_EC_KEY_PATH (PKCS8 PEM, mode 0o600).
    """
    global _ec_key_cache
    with _ec_key_lock:
        if _ec_key_cache is not None:
            return _ec_key_cache

        key_path = Path(REKOR_EC_KEY_PATH)
        if not key_path.exists():
            key = ec.generate_private_key(ec.SECP256R1())
            pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_bytes(pem)
            key_path.chmod(0o600)
            logger.info("Generated ECDSA P-256 key for Rekor at %s", key_path)
        else:
            pem = key_path.read_bytes()
            key = serialization.load_pem_private_key(pem, password=None)

        _ec_key_cache = key
        return key


def _build_entry(chain_hash_hex: str, ec_key=None) -> dict:
    """Build a hashedrekord v0.0.1 entry for Rekor using ECDSA P-256 + SHA-256.

    The chain_hash_hex (UTF-8) is treated as the artifact:
      1. SHA-256 of the artifact bytes → data.hash.value
      2. ECDSA-P256-SHA256 signature over the artifact bytes → signature.content
      3. ECDSA public key PEM SPKI → publicKey.content (base64-encoded)

    Args:
        chain_hash_hex: SHA-256 chain hash as hex string (our proof integrity anchor).
        ec_key: ECDSA P-256 private key (optional — uses managed key if None).
    """
    if ec_key is None:
        ec_key = _get_or_create_rekor_ec_key()

    artifact_bytes = chain_hash_hex.encode("utf-8")
    sha256_hex = hashlib.sha256(artifact_bytes).hexdigest()

    # ECDSA signature over the artifact (SHA-256 hashing done internally by ECDSA)
    sig_der = ec_key.sign(artifact_bytes, ec.ECDSA(hashes.SHA256()))
    sig_b64 = base64.b64encode(sig_der).decode("ascii")

    # Public key as base64-encoded PEM SPKI
    pub_pem = ec_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_b64 = base64.b64encode(pub_pem).decode("ascii")

    return {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": sha256_hex,
                }
            },
            "signature": {
                "content": sig_b64,
                "publicKey": {
                    "content": pub_b64,
                },
            },
        },
    }


def _submit_once(chain_hash_hex: str, ec_key=None) -> Optional[dict]:
    """Single attempt to submit an entry to Rekor. Returns parsed entry dict or None."""
    try:
        entry = _build_entry(chain_hash_hex, ec_key)
        resp = httpx.post(
            f"{REKOR_URL}/api/v1/log/entries",
            json=entry,
            headers={"Content-Type": "application/json"},
            timeout=10.0,
        )

        # 409 Conflict = entry already exists (same data submitted twice) → treat as success
        if resp.status_code == 409:
            logger.info("Rekor entry already exists for hash %s...", chain_hash_hex[:16])
            try:
                body = resp.json()
                if isinstance(body, dict):
                    for uuid, data in body.items():
                        return {uuid: data}
            except Exception:
                pass
            return None

        if resp.status_code not in (200, 201):
            logger.warning("Rekor returned HTTP %d for hash %s...", resp.status_code, chain_hash_hex[:16])
            return None

        data = resp.json()
        if not isinstance(data, dict):
            logger.warning("Rekor unexpected response type: %s", type(data))
            return None

        logger.info("Rekor entry submitted for hash %s...", chain_hash_hex[:16])
        return data

    except httpx.TimeoutException:
        logger.warning("Rekor request timed out for hash %s...", chain_hash_hex[:16])
        return None
    except httpx.HTTPError as e:
        logger.warning("Rekor HTTP error: %s", e)
        return None
    except Exception as e:
        logger.warning("Rekor submit failed: %s", e)
        return None


def submit_to_rekor(chain_hash_hex: str) -> dict:
    """Submit a proof chain hash to Sigstore Rekor with retry + exponential backoff.

    Uses the internal ECDSA P-256 key (auto-generated on first call).
    Returns a dict with Rekor metadata on success, or {provider, status:'failed', error} on failure.
    The proof remains valid even if Rekor is unavailable.
    """
    if not REKOR_ENABLED:
        logger.info("Rekor disabled (REKOR_ENABLED=false), skipping %s...", chain_hash_hex[:16])
        return {"provider": "sigstore-rekor", "status": "disabled", "reason": "non-production environment"}
    last_error = "unknown"
    for attempt in range(_MAX_RETRIES):
        result = _submit_once(chain_hash_hex)
        if result is not None:
            # Parse response: {uuid: {logIndex, integratedTime, body, ...}}
            try:
                uuid = next(iter(result))
                entry_data = result[uuid]
                log_index = entry_data.get("logIndex")
                integrated_time = entry_data.get("integratedTime")
                return {
                    "provider": "sigstore-rekor",
                    "status": "verified",
                    "uuid": uuid,
                    "log_index": log_index,
                    "integrated_time": integrated_time,
                    "log_url": f"{REKOR_URL}/api/v1/log/entries/{uuid}",
                    "verify_url": f"https://search.sigstore.dev/?logIndex={log_index}",
                }
            except (StopIteration, KeyError, TypeError) as e:
                last_error = f"parse_error: {e}"

        if attempt < _MAX_RETRIES - 1:
            delay = _BACKOFF_SECONDS[attempt]
            logger.info(
                "Rekor attempt %d/%d failed, retrying in %.0fs...",
                attempt + 1, _MAX_RETRIES, delay,
            )
            time.sleep(delay)
        else:
            last_error = last_error or "submit returned None"

    logger.warning("Rekor submit failed after %d attempts for hash %s...", _MAX_RETRIES, chain_hash_hex[:16])
    return {
        "provider": "sigstore-rekor",
        "status": "failed",
        "error": last_error,
    }


def verify_rekor_entry(uuid: str) -> dict:
    """Fetch and return a Rekor log entry by UUID for external verification."""
    try:
        resp = httpx.get(
            f"{REKOR_URL}/api/v1/log/entries/{uuid}",
            timeout=10.0,
        )
        if resp.status_code != 200:
            return {"verified": False, "error": f"HTTP {resp.status_code}"}
        data = resp.json()
        return {"verified": True, "entry": data}
    except httpx.HTTPError as e:
        return {"verified": False, "error": str(e)}
    except Exception as e:
        return {"verified": False, "error": str(e)}
