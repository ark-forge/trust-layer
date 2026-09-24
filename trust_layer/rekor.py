"""Sigstore Rekor transparency log — submit proof chain hash for public auditability.

Uses ECDSA P-256 + SHA-256 (hashedrekord v0.0.1), the format natively supported
by Rekor without Sigstore/Fulcio certificates. The EC key is separate from the
Ed25519 signing key used for arkforge_signature. It lives in tl-signer in signer
mode; in legacy mode it is generated once and stored at REKOR_EC_KEY_PATH.
"""

import base64
import hashlib
import json
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


def get_rekor_public_key_pem() -> Optional[str]:
    """PEM of the ECDSA P-256 key used to submit entries to Rekor.

    Published so a third party can attribute a log entry to ArkForge. Without it the
    log proves that *some* key attested a hash at time T, never that ArkForge did —
    which is precisely the witness the anchoring is supposed to provide.
    """
    from .config import get_signer
    try:
        return get_signer().rekor_public_pem
    except Exception as e:
        logger.warning("Rekor public key unavailable: %s", e)
        return None


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
    artifact_bytes = chain_hash_hex.encode("utf-8")
    sha256_hex = hashlib.sha256(artifact_bytes).hexdigest()

    # ECDSA signature over the artifact (SHA-256 hashing done internally by ECDSA)
    if ec_key is None:
        from .config import get_signer
        signer = get_signer()
        sig_b64 = signer.sign_rekor(chain_hash_hex)
        pub_pem = signer.rekor_public_pem.encode("ascii")
    else:
        sig_der = ec_key.sign(artifact_bytes, ec.ECDSA(hashes.SHA256()))
        sig_b64 = base64.b64encode(sig_der).decode("ascii")
        pub_pem = ec_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    # Public key as base64-encoded PEM SPKI
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
            # Parsing failed but entry exists — return a sentinel so caller knows it's anchored
            return {"_already_exists": {"status": "conflict_entry_exists", "hash": chain_hash_hex}}

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


def _rfc6962_root(leaf: bytes, index: int, size: int, path: list) -> tuple:
    """RFC 6962 inclusion-proof walk. Returns (root, siblings_consumed).

    A right-edge node is promoted without consuming a sibling, so the walk ends on
    tree size rather than on path exhaustion. The caller checks that every sibling was
    used: a leftover one means the proof does not match the shape that was walked.
    """
    h = leaf
    idx, sz, i = index, size, 0
    while sz > 1:
        if idx % 2 == 1:
            h = hashlib.sha256(b"\x01" + bytes.fromhex(path[i]) + h).digest()
            i += 1
        elif idx + 1 < sz:
            h = hashlib.sha256(b"\x01" + h + bytes.fromhex(path[i])).digest()
            i += 1
        idx //= 2
        sz = (sz + 1) // 2
    return h, i


def _ecdsa_verify(pubkey_pem: bytes, signature: bytes, message: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    try:
        key = load_pem_public_key(pubkey_pem)
        key.verify(signature, message, _ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def verify_rekor_entry(uuid: str, chain_hash_hex: Optional[str] = None) -> dict:
    """Verify a Rekor log entry, optionally binding it to a specific chain hash.

    Fetching an entry and seeing HTTP 200 proves only that *an* entry exists. It says
    nothing about whose artefact it covers, and nothing about whether the log really
    contains it — which is the whole point of anchoring. This performs the checks a
    third party would:

      1. the entry is a hashedrekord (the only kind Trust Layer writes);
      2. its logged artefact hash equals sha256(chain_hash_hex), the convention used
         on submission — without this the entry could be anybody's;
      3. the entry's own ECDSA signature over the chain hash verifies;
      4. the signed entry timestamp verifies against the log's public key;
      5. the inclusion proof recomputes the checkpoint root, and the checkpoint is
         signed by the log key it names.

    Pass chain_hash_hex to get checks 2 and 3; without it they are reported as skipped
    and `verified` stays False, because an unbound entry proves nothing about a proof.

    Returns {verified, checks, entry, error}.
    """
    checks: dict = {}
    try:
        resp = httpx.get(f"{REKOR_URL}/api/v1/log/entries/{uuid}", timeout=10.0)
        if resp.status_code != 200:
            return {"verified": False, "checks": checks, "error": f"HTTP {resp.status_code}"}
        data = resp.json()
        entry = next(iter(data.values()))

        key_resp = httpx.get(f"{REKOR_URL}/api/v1/log/publicKey", timeout=10.0)
        if key_resp.status_code != 200:
            return {"verified": False, "checks": checks,
                    "error": f"cannot fetch log public key: HTTP {key_resp.status_code}"}
        log_pubkey = key_resp.content

        body_bytes = base64.b64decode(entry["body"])
        parsed = json.loads(body_bytes)

        checks["kind"] = parsed.get("kind") == "hashedrekord"
        if not checks["kind"]:
            return {"verified": False, "checks": checks,
                    "error": f"entry kind is '{parsed.get('kind')}', not hashedrekord"}

        spec = parsed["spec"]

        if chain_hash_hex:
            expected = hashlib.sha256(chain_hash_hex.encode("utf-8")).hexdigest()
            checks["artifact_matches_chain_hash"] = spec["data"]["hash"]["value"] == expected
            submitter_pem = base64.b64decode(spec["signature"]["publicKey"]["content"])
            checks["entry_signature"] = _ecdsa_verify(
                submitter_pem,
                base64.b64decode(spec["signature"]["content"]),
                chain_hash_hex.encode("utf-8"),
            )
        else:
            checks["artifact_matches_chain_hash"] = None
            checks["entry_signature"] = None

        set_payload = json.dumps(
            {"body": entry["body"], "integratedTime": entry["integratedTime"],
             "logID": entry["logID"], "logIndex": entry["logIndex"]},
            sort_keys=True, separators=(",", ":"),
        ).encode()
        checks["signed_entry_timestamp"] = _ecdsa_verify(
            log_pubkey, base64.b64decode(entry["verification"]["signedEntryTimestamp"]),
            set_payload,
        )

        ip = entry["verification"]["inclusionProof"]
        leaf = hashlib.sha256(b"\x00" + body_bytes).digest()
        try:
            root, consumed = _rfc6962_root(leaf, ip["logIndex"], ip["treeSize"], ip["hashes"])
            checks["inclusion_proof"] = (
                root.hex() == ip["rootHash"] and consumed == len(ip["hashes"])
            )
        except (IndexError, ValueError):
            checks["inclusion_proof"] = False

        cp_body, _, cp_sigblock = ip["checkpoint"].partition("\n\n")
        cp_body += "\n"
        cp_lines = cp_body.strip().split("\n")
        cp_root_ok = base64.b64decode(cp_lines[2]).hex() == ip["rootHash"]
        cp_sig_line = next(line for line in cp_sigblock.split("\n") if line.strip())
        cp_raw = base64.b64decode(cp_sig_line.split()[-1])
        checks["checkpoint"] = cp_root_ok and _ecdsa_verify(log_pubkey, cp_raw[4:], cp_body.encode())

        verified = all(v for v in checks.values() if v is not None)
        if chain_hash_hex is None:
            # An entry not bound to a chain hash is not evidence about a proof.
            verified = False
        return {"verified": verified, "checks": checks, "entry": data}

    except httpx.HTTPError as e:
        return {"verified": False, "checks": checks, "error": str(e)}
    except Exception as e:
        return {"verified": False, "checks": checks, "error": str(e)}
