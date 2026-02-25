"""Tests for OpenTimestamps module (mocked — no network)."""

from unittest.mock import patch, MagicMock

from trust_layer.timestamps import submit_hash, upgrade_pending, verify_ots


def test_submit_hash_without_lib():
    """Without opentimestamps installed, should return None gracefully."""
    with patch.dict("sys.modules", {"opentimestamps": None, "opentimestamps.core": None,
                                     "opentimestamps.core.timestamp": None, "opentimestamps.core.op": None,
                                     "opentimestamps.core.notary": None, "opentimestamps.timestamp": None}):
        result = submit_hash("a" * 64)
        # Should not raise, returns None when lib missing
        assert result is None


def test_upgrade_pending_without_lib():
    result = upgrade_pending(b"\x00" * 10)
    assert result is None


def test_verify_ots_without_lib():
    result = verify_ots(b"\x00" * 10, "a" * 64)
    assert result["verified"] is False
    assert result["bitcoin_block"] is None


def test_submit_hash_import_error():
    """ImportError should be caught gracefully."""
    with patch("builtins.__import__", side_effect=ImportError("no module")):
        result = submit_hash("b" * 64)
        assert result is None
