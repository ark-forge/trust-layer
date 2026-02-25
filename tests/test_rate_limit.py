"""Tests for rate limiting."""

from trust_layer.rate_limit import check_rate_limit, get_usage


def test_rate_limit_allows_within_limit():
    allowed, remaining = check_rate_limit("mcp_test_ratelimit", limit=5)
    assert allowed is True
    assert remaining == 4


def test_rate_limit_decrements():
    for i in range(3):
        check_rate_limit("mcp_test_decrement", limit=5)
    usage = get_usage("mcp_test_decrement", limit=5)
    assert usage["used"] == 3
    assert usage["remaining"] == 2


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
    assert usage["used"] == 0
    assert usage["remaining"] == 100
    assert usage["limit"] == 100
