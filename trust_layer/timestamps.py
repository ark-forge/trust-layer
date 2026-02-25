"""OpenTimestamps — submit, upgrade, verify."""

import logging
from typing import Optional

logger = logging.getLogger("trust_layer.timestamps")


def submit_hash(hash_hex: str) -> Optional[bytes]:
    """Submit a hash to OpenTimestamps. Returns .ots bytes (pending) or None on failure."""
    try:
        import opentimestamps.core.timestamp
        import opentimestamps.core.op
        import opentimestamps.core.notary
        from opentimestamps.core.timestamp import Timestamp, DetachedTimestampFile
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.timestamp import stamp_command

        file_hash = bytes.fromhex(hash_hex)
        detached = DetachedTimestampFile(OpSHA256(), Timestamp(file_hash))
        stamp_command(detached)
        import io
        ctx = io.BytesIO()
        detached.serialize(ctx)
        ots_bytes = ctx.getvalue()
        logger.info("OTS submitted for hash %s... (%d bytes)", hash_hex[:16], len(ots_bytes))
        return ots_bytes
    except ImportError:
        logger.warning("opentimestamps not installed, skipping OTS submit")
        return None
    except Exception as e:
        logger.warning("OTS submit failed: %s", e)
        return None


def upgrade_pending(ots_bytes: bytes) -> Optional[bytes]:
    """Try to upgrade a pending .ots to a confirmed Bitcoin attestation. Returns upgraded bytes or None."""
    try:
        import io
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.timestamp import upgrade_command

        ctx = io.BytesIO(ots_bytes)
        detached = DetachedTimestampFile.deserialize(ctx)
        changed = upgrade_command(detached)
        if changed:
            out = io.BytesIO()
            detached.serialize(out)
            return out.getvalue()
        return None
    except ImportError:
        return None
    except Exception as e:
        logger.warning("OTS upgrade failed: %s", e)
        return None


def verify_ots(ots_bytes: bytes, hash_hex: str) -> dict:
    """Verify an .ots file. Returns {verified, bitcoin_block, timestamp}."""
    result = {"verified": False, "bitcoin_block": None, "timestamp": None}
    try:
        import io
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.timestamp import verify_command

        ctx = io.BytesIO(ots_bytes)
        detached = DetachedTimestampFile.deserialize(ctx)
        verification = verify_command(detached)
        if verification:
            result["verified"] = True
            # verification is a dict of {attestation: timestamp}
            for attestation, ts in verification.items():
                result["bitcoin_block"] = getattr(attestation, "height", None)
                result["timestamp"] = str(ts) if ts else None
                break
    except ImportError:
        pass
    except Exception as e:
        logger.warning("OTS verify failed: %s", e)
    return result
