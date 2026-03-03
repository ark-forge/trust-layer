"""RFC 3161 Timestamp Authority — submit and verify via FreeTSA.org."""

import logging
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger("trust_layer.timestamps")

_CERTS_DIR = Path(__file__).parent / "certs"
_TSA_URL = "https://freetsa.org/tsr"
_TSA_CERT = _CERTS_DIR / "tsa.crt"
_CA_CERT = _CERTS_DIR / "cacert.pem"

_MAX_RETRIES = 3
_BACKOFF_BASE = 1.0  # seconds: 1s, 2s, 4s


def _submit_hash_once(hash_hex: str) -> Optional[bytes]:
    """Single attempt to submit a hash to FreeTSA. Returns .tsr bytes or None."""
    data_path = None
    try:
        hash_bytes = bytes.fromhex(hash_hex)

        # Create timestamp query (TSQ) via openssl
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

        # Submit TSQ to FreeTSA
        resp = httpx.post(
            _TSA_URL,
            content=tsq_bytes,
            headers={"Content-Type": "application/timestamp-query"},
            timeout=15.0,
        )
        if resp.status_code != 200:
            logger.warning("FreeTSA returned HTTP %d", resp.status_code)
            return None

        tsr_bytes = resp.content
        logger.info("TSA timestamp obtained for hash %s... (%d bytes)", hash_hex[:16], len(tsr_bytes))
        return tsr_bytes

    except FileNotFoundError:
        logger.warning("openssl not found, skipping TSA submit")
        raise  # non-retryable
    except subprocess.CalledProcessError as e:
        logger.warning("openssl ts -query failed: %s", e.stderr[:200] if e.stderr else e)
        return None
    except httpx.HTTPError as e:
        logger.warning("FreeTSA request failed: %s", e)
        return None
    except Exception as e:
        logger.warning("TSA submit failed: %s", e)
        return None
    finally:
        if data_path:
            for suffix in ("", ".tsq"):
                try:
                    p = Path(data_path + suffix) if suffix else Path(data_path)
                    p.unlink(missing_ok=True)
                except Exception:
                    pass


def submit_hash(hash_hex: str) -> Optional[bytes]:
    """Submit a hash to FreeTSA via RFC 3161 with retry + exponential backoff.

    Retries up to 3 times (1s, 2s, 4s delays) on transient failures.
    Returns .tsr bytes or None.
    """
    for attempt in range(_MAX_RETRIES):
        try:
            result = _submit_hash_once(hash_hex)
            if result is not None:
                return result
        except FileNotFoundError:
            return None  # openssl missing — no point retrying

        if attempt < _MAX_RETRIES - 1:
            delay = _BACKOFF_BASE * (2 ** attempt)
            logger.info("TSA attempt %d/%d failed, retrying in %.0fs...", attempt + 1, _MAX_RETRIES, delay)
            time.sleep(delay)

    logger.warning("TSA submit failed after %d attempts for hash %s...", _MAX_RETRIES, hash_hex[:16])
    return None


def verify_tsr(tsr_bytes: bytes, hash_hex: str) -> dict:
    """Verify a .tsr file against the original hash. Returns {verified, details}."""
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

        # Verify
        proc = subprocess.run(
            ["openssl", "ts", "-verify", "-data", data_path,
             "-in", tsr_path, "-CAfile", str(_CA_CERT),
             "-untrusted", str(_TSA_CERT)],
            capture_output=True, text=True, timeout=10,
        )
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
