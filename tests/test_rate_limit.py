"""Tests for rate limiting."""

from unittest.mock import patch
from trust_layer.rate_limit import check_rate_limit, get_usage
from trust_layer.config import FREE_TIER_MONTHLY_LIMIT, PRO_MONTHLY_LIMIT, ENTERPRISE_MONTHLY_LIMIT


def test_rate_limit_allows_within_limit():
    allowed, remaining = check_rate_limit("mcp_test_ratelimit", limit=5)
    assert allowed is True
    assert remaining == 4


def test_rate_limit_decrements():
    for i in range(3):
        check_rate_limit("mcp_test_decrement", limit=5)
    usage = get_usage("mcp_test_decrement", limit=5)
    assert usage["daily"]["used"] == 3
    assert usage["daily"]["remaining"] == 2


def test_rate_limit_blocks_at_limit():
    key = "mcp_test_blocked_"
    for i in range(5):
        allowed, _ = check_rate_limit(key, limit=5)
        assert allowed is True

    allowed, remaining = check_rate_limit(key, limit=5)
    assert allowed is False
    assert remaining == 0


def test_get_usage_fresh_key():
    usage = get_usage("mcp_test_fresh_key", limit=100)
    assert usage["daily"]["used"] == 0
    assert usage["daily"]["remaining"] == 100
    assert usage["daily"]["limit"] == 100


def test_free_key_has_monthly_limit():
    """Free tier keys have a monthly quota of FREE_TIER_MONTHLY_LIMIT."""
    usage = get_usage("mcp_free_test_monthly", limit=100)
    assert usage["plan"] == "free"
    assert "monthly" in usage
    assert usage["monthly"]["limit"] == FREE_TIER_MONTHLY_LIMIT  # 500
    assert usage["monthly"]["used"] == 0


def test_pro_key_has_monthly_limit():
    """Pro keys now have a monthly quota (PRO_MONTHLY_LIMIT)."""
    usage = get_usage("mcp_pro_test_monthly", limit=100)
    assert usage["plan"] == "pro"
    assert "monthly" in usage
    assert usage["monthly"]["limit"] == PRO_MONTHLY_LIMIT  # 5 000
    assert usage["monthly"]["remaining"] == PRO_MONTHLY_LIMIT


def test_enterprise_key_has_monthly_limit():
    """Enterprise keys have a monthly quota (ENTERPRISE_MONTHLY_LIMIT)."""
    usage = get_usage("mcp_ent_test_monthly", limit=100)
    assert usage["plan"] == "enterprise"
    assert "monthly" in usage
    assert usage["monthly"]["limit"] == ENTERPRISE_MONTHLY_LIMIT  # 50 000
    assert usage["monthly"]["remaining"] == ENTERPRISE_MONTHLY_LIMIT


def test_test_key_no_monthly_limit():
    """Test keys have no monthly limit."""
    usage = get_usage("mcp_test_nolimit", limit=100)
    assert usage["plan"] == "test"
    assert "monthly" not in usage


def test_free_key_monthly_blocks():
    """Free tier key blocked when monthly limit reached."""
    key = "mcp_free_blocked_monthly2"
    # Patch the _MONTHLY_LIMITS dict so the check reads the patched value at call time
    with patch("trust_layer.rate_limit._MONTHLY_LIMITS", {"free": 3, "pro": 5000, "enterprise": 50000, "test": None}):
        for i in range(3):
            allowed, _ = check_rate_limit(key, limit=100)
            assert allowed is True
        allowed, remaining = check_rate_limit(key, limit=100)
        assert allowed is False
        assert remaining == 0


def test_pro_key_monthly_blocks():
    """Pro key blocked when monthly quota reached."""
    key = "mcp_pro_blocked_monthly"
    with patch("trust_layer.rate_limit._MONTHLY_LIMITS", {"free": 500, "pro": 3, "enterprise": 50000, "test": None}):
        for i in range(3):
            allowed, _ = check_rate_limit(key, limit=100)
            assert allowed is True
        allowed, remaining = check_rate_limit(key, limit=100)
        assert allowed is False
        assert remaining == 0
