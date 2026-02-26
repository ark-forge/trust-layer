"""OpenTimestamps — submit, upgrade, verify using otsclient primitives."""

import io
import os
import logging
import argparse
from typing import Optional

logger = logging.getLogger("trust_layer.timestamps")

# Default OTS calendar servers
_CALENDAR_URLS = [
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
]


def _make_args(**overrides) -> argparse.Namespace:
    """Build a minimal args namespace for otsclient functions."""
    defaults = dict(
        use_btc_wallet=False,
        setup_bitcoin=False,
        calendar_urls=list(_CALENDAR_URLS),
        m=2,
        timeout=10,
        wait=False,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def submit_hash(hash_hex: str) -> Optional[bytes]:
    """Submit a hash to OpenTimestamps calendars. Returns .ots bytes (pending) or None."""
    try:
        from opentimestamps.core.timestamp import Timestamp, DetachedTimestampFile
        from opentimestamps.core.op import OpSHA256, OpAppend
        from opentimestamps.core.serialize import StreamSerializationContext
        from otsclient.cmds import create_timestamp, make_merkle_tree

        file_hash = bytes.fromhex(hash_hex)
        file_timestamp = DetachedTimestampFile(OpSHA256(), Timestamp(file_hash))
        nonce_appended = file_timestamp.timestamp.ops.add(OpAppend(os.urandom(16)))
        merkle_root = nonce_appended.ops.add(OpSHA256())
        merkle_tip = make_merkle_tree([merkle_root])

        args = _make_args()
        create_timestamp(merkle_tip, args.calendar_urls, args)

        ctx = io.BytesIO()
        file_timestamp.serialize(StreamSerializationContext(ctx))
        ots_bytes = ctx.getvalue()
        logger.info("OTS submitted for hash %s... (%d bytes)", hash_hex[:16], len(ots_bytes))
        return ots_bytes
    except ImportError:
        logger.warning("opentimestamps/otsclient not installed, skipping OTS submit")
        return None
    except Exception as e:
        logger.warning("OTS submit failed: %s", e)
        return None


def upgrade_pending(ots_bytes: bytes) -> Optional[bytes]:
    """Try to upgrade a pending .ots to a Bitcoin-confirmed attestation. Returns upgraded bytes or None."""
    try:
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.core.serialize import StreamDeserializationContext, StreamSerializationContext
        from otsclient.cmds import upgrade_timestamp

        ctx = io.BytesIO(ots_bytes)
        detached = DetachedTimestampFile.deserialize(StreamDeserializationContext(ctx))

        args = _make_args(cache={})
        changed = upgrade_timestamp(detached.timestamp, args)
        if changed:
            out = io.BytesIO()
            detached.serialize(StreamSerializationContext(out))
            logger.info("OTS upgraded to Bitcoin-confirmed")
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
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.core.serialize import StreamDeserializationContext
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation

        ctx = io.BytesIO(ots_bytes)
        detached = DetachedTimestampFile.deserialize(StreamDeserializationContext(ctx))

        # Walk attestations to find Bitcoin confirmation
        for msg, attestation in detached.timestamp.all_attestations():
            if isinstance(attestation, BitcoinBlockHeaderAttestation):
                result["verified"] = True
                result["bitcoin_block"] = attestation.height
                break
    except ImportError:
        pass
    except Exception as e:
        logger.warning("OTS verify failed: %s", e)
    return result
