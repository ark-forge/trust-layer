"""Tests for rate limiting."""

from unittest.mock import patch
from trust_layer.rate_limit import check_rate_limit, get_usage


def test_rate_limit_allows_within_limit():
    allowed, remaining, is_overage, reason = check_rate_limit("mcp_test_ratelimit", limit=5)
    assert allowed is True
    assert remaining >= 0
    assert is_overage is False
    assert reason == ""


def test_rate_limit_decrements():
    for i in range(3):
        check_rate_limit("mcp_test_decrement", limit=5)
    usage = get_usage("mcp_test_decrement", limit=5)
    assert usage["daily"]["used"] == 3
    assert usage["daily"]["remaining"] == 2


def test_rate_limit_blocks_at_limit():
    key = "mcp_test_blocked_"
    for i in range(5):
        allowed, _, _, _ = check_rate_limit(key, limit=5)
        assert allowed is True

    allowed, remaining, is_overage, reason = check_rate_limit(key, limit=5)
    assert allowed is False
    assert remaining == 0
    assert reason == "daily_cap"


def test_get_usage_fresh_key():
    usage = get_usage("mcp_test_fresh_key", limit=100)
    assert usage["daily"]["used"] == 0
    assert usage["daily"]["remaining"] == 100
    assert usage["daily"]["limit"] == 100


def test_free_key_has_monthly_limit():
    """Free tier keys have a monthly limit in addition to daily."""
    usage = get_usage("mcp_free_test_monthly", limit=100)
    assert usage["plan"] == "free"
    assert "monthly" in usage
    assert usage["monthly"]["limit"] == 100
    assert usage["monthly"]["used"] == 0


def test_pro_key_has_monthly_limit():
    """Pro keys now have a monthly limit (5000/month)."""
    usage = get_usage("mcp_pro_test_nolimit", limit=100)
    assert usage["plan"] == "pro"
    assert "monthly" in usage
    assert usage["monthly"]["limit"] == 5000


def test_free_key_monthly_blocks():
    """Free tier key blocked when monthly limit reached."""
    key = "mcp_free_blocked_m"
    with patch("trust_layer.rate_limit._MONTHLY_LIMITS", {"free": 3, "pro": 5000, "enterprise": 50000, "test": None}):
        for i in range(3):
            allowed, _, _, _ = check_rate_limit(key, limit=100)
            assert allowed is True
        allowed, remaining, is_overage, reason = check_rate_limit(key, limit=100)
        assert allowed is False
        assert remaining == 0
        assert reason == "monthly_quota"
