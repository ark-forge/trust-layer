"""RFC 3161 Timestamp Authority — pool failover (FreeTSA → DigiCert → Sectigo).

Custom TSA (including eIDAS-qualified QTSP) is supported via env vars:
  TSA_PRIMARY_URL      — TSA endpoint URL
  TSA_PRIMARY_PROVIDER — human-readable provider name recorded in proofs
  TSA_CA_FILE          — CA cert bundle for TSR verification (PEM)
  TSA_CERT_FILE        — TSA signing cert for TSR verification (PEM)
Defaults to bundled FreeTSA certs when not set.
"""

import logging
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional, Tuple

import httpx

logger = logging.getLogger("trust_layer.timestamps")


def _submit_hash_once(hash_hex: str, tsa_url: str) -> Optional[bytes]:
    """Single attempt to submit a hash to the given TSA URL. Returns .tsr bytes or None."""
    data_path = None
    try:
        hash_bytes = bytes.fromhex(hash_hex)

        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as f:
            f.write(hash_bytes)
            data_path = f.name

        tsq_path = data_path + ".tsq"
        subprocess.run(
            ["openssl", "ts", "-query", "-data", data_path, "-no_nonce",
             "-sha256", "-out", tsq_path],
            check=True, capture_output=True, timeout=10,
        )
        tsq_bytes = Path(tsq_path).read_bytes()

        resp = httpx.post(
            tsa_url,
            content=tsq_bytes,
            headers={"Content-Type": "application/timestamp-query"},
            timeout=15.0,
        )
        if resp.status_code != 200:
            logger.warning("TSA %s returned HTTP %d", tsa_url, resp.status_code)
            return None

        return resp.content

    except FileNotFoundError:
        logger.warning("openssl not found, skipping TSA submit")
        raise  # non-retryable — propagates to submit_hash to abort immediately
    except subprocess.CalledProcessError as e:
        logger.warning("openssl ts -query failed: %s", e.stderr[:200] if e.stderr else e)
        return None
    except httpx.HTTPError as e:
        logger.warning("TSA %s request failed: %s", tsa_url, e)
        return None
    except Exception as e:
        logger.warning("TSA %s submit error: %s", tsa_url, e)
        return None
    finally:
        if data_path:
            for suffix in ("", ".tsq"):
                try:
                    p = Path(data_path + suffix) if suffix else Path(data_path)
                    p.unlink(missing_ok=True)
                except Exception:
                    pass


def submit_hash(hash_hex: str, plan: str = "") -> Optional[Tuple[bytes, str]]:
    """Try each TSA server in order. Returns (tsr_bytes, provider) on first success, None if all fail.

    Pool order: FreeTSA → DigiCert → Sectigo (all free, WebTrust-certified for DigiCert/Sectigo).
    Platform plan skips FreeTSA and starts at DigiCert for higher reliability.
    Each server is tried once — no per-server retry. Fast failover.
    """
    from .config import TSA_SERVERS

    servers = TSA_SERVERS[1:] if plan == "platform" else TSA_SERVERS
    for server in servers:
        try:
            tsr_bytes = _submit_hash_once(hash_hex, server["url"])
            if tsr_bytes is not None:
                logger.info(
                    "TSA timestamp obtained from %s for hash %s... (%d bytes)",
                    server["provider"], hash_hex[:16], len(tsr_bytes),
                )
                return (tsr_bytes, server["provider"])
        except FileNotFoundError:
            return None  # openssl missing — no point trying other servers
        logger.info("TSA %s failed, trying next server...", server["provider"])

    logger.warning("All TSA servers failed for hash %s...", hash_hex[:16])
    return None


def verify_tsr(tsr_bytes: bytes, hash_hex: str, provider: str = "") -> dict:
    """Verify a .tsr file against the original hash. Returns {verified, details}.

    `provider` is the issuer recorded in the proof (timestamp_authority.provider).
    It matters: submit_hash fails over across FreeTSA, DigiCert and Sectigo, and each
    needs different CA material. FreeTSA is self-signed and ships bundled; the two
    WebTrust CAs are in the system trust store and their tokens carry their own chain.
    Verifying a DigiCert token against FreeTSA's root fails — so an unrecognised
    provider is refused rather than checked against the wrong root.

    Passing no provider keeps the historical behaviour (the configured/bundled certs),
    which is what TSA_CA_FILE/TSA_CERT_FILE overrides exist for (QTSP endpoints).
    """
    from .config import (TSA_CA_FILE, TSA_CERT_FILE, TSA_SYSTEM_CA_FILE,
                         TSA_BUNDLED_PROVIDERS, TSA_SYSTEM_CA_PROVIDERS)

    use_system_ca = False
    if provider:
        if provider in TSA_BUNDLED_PROVIDERS:
            use_system_ca = False
        elif provider in TSA_SYSTEM_CA_PROVIDERS:
            if TSA_SYSTEM_CA_FILE is None:
                return {"verified": False,
                        "details": f"no system CA bundle available to verify a {provider} token"}
            use_system_ca = True
        else:
            return {"verified": False,
                    "details": f"unknown timestamp issuer '{provider}' — no CA material mapped"}

    result = {"verified": False, "details": None}
    data_path = None
    try:
        hash_bytes = bytes.fromhex(hash_hex)

        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as f:
            f.write(hash_bytes)
            data_path = f.name

        tsq_path = data_path + ".tsq"
        tsr_path = data_path + ".tsr"

        # Recreate the TSQ
        subprocess.run(
            ["openssl", "ts", "-query", "-data", data_path, "-no_nonce",
             "-sha256", "-out", tsq_path],
            check=True, capture_output=True, timeout=10,
        )

        # Write TSR
        Path(tsr_path).write_bytes(tsr_bytes)

        # Verify against configured CA (FreeTSA by default, QTSP cert if configured)
        if use_system_ca:
            verify_args = ["openssl", "ts", "-verify", "-data", data_path,
                           "-in", tsr_path, "-CAfile", str(TSA_SYSTEM_CA_FILE)]
        else:
            verify_args = ["openssl", "ts", "-verify", "-data", data_path,
                           "-in", tsr_path, "-CAfile", str(TSA_CA_FILE),
                           "-untrusted", str(TSA_CERT_FILE)]
        proc = subprocess.run(verify_args, capture_output=True, text=True, timeout=10)
        if proc.returncode == 0 and "Verification: OK" in proc.stdout:
            result["verified"] = True
            result["details"] = proc.stdout.strip()
        else:
            result["details"] = (proc.stdout + proc.stderr).strip()

    except (OSError, subprocess.SubprocessError, ValueError) as e:
        result["details"] = str(e)
    finally:
        if data_path:
            for suffix in ("", ".tsq", ".tsr"):
                try:
                    p = Path(data_path + suffix if suffix else data_path)
                    p.unlink(missing_ok=True)
                except OSError:
                    pass

    return result
