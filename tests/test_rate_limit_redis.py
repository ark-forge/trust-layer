"""Tests du hot path Redis pour le rate limiting."""

from unittest.mock import patch

import pytest

from trust_layer.rate_limit import check_rate_limit, get_usage


class _FakePipeline:
    """Pipeline Redis minimal pour les tests."""

    def __init__(self, store):
        self._store = store
        self._cmds = []

    def get(self, key):
        self._cmds.append(("get", key))
        return self

    def incr(self, key):
        self._cmds.append(("incr", key))
        return self

    def decr(self, key):
        self._cmds.append(("decr", key))
        return self

    def expire(self, key, ttl):
        self._cmds.append(("expire", key, ttl))
        return self

    def execute(self):
        results = []
        for cmd in self._cmds:
            if cmd[0] == "get":
                results.append(self._store.get(cmd[1]))
            elif cmd[0] == "incr":
                val = int(self._store.get(cmd[1]) or 0) + 1
                self._store[cmd[1]] = str(val)
                results.append(val)
            elif cmd[0] == "decr":
                val = max(0, int(self._store.get(cmd[1]) or 0) - 1)
                self._store[cmd[1]] = str(val)
                results.append(val)
            elif cmd[0] == "expire":
                results.append(True)
        return results


class FakeRedis:
    """Redis in-memory minimal pour les tests."""

    def __init__(self):
        self._store = {}

    def get(self, key):
        return self._store.get(key)

    def incr(self, key):
        val = int(self._store.get(key) or 0) + 1
        self._store[key] = str(val)
        return val

    def decr(self, key):
        val = max(0, int(self._store.get(key) or 0) - 1)
        self._store[key] = str(val)
        return val

    def expire(self, key, ttl):
        return True

    def ping(self):
        return True

    def pipeline(self, transaction=False):
        return _FakePipeline(self._store)


def test_redis_hot_path_increments_and_returns_remaining():
    """Le hot path Redis incrémente le compteur et retourne remaining correct."""
    fake_r = FakeRedis()
    with patch("trust_layer.rate_limit.get_redis", return_value=fake_r):
        allowed, remaining, is_overage, reason = check_rate_limit("mcp_test_redis_incr", limit=10)

    assert allowed is True
    assert remaining == 9
    assert is_overage is False
    assert reason == ""


def test_redis_hot_path_blocks_at_daily_cap():
    """Le hot path Redis bloque quand daily cap atteint."""
    fake_r = FakeRedis()
    with patch("trust_layer.rate_limit.get_redis", return_value=fake_r):
        for _ in range(3):
            check_rate_limit("mcp_test_redis_block", limit=3)
        allowed, remaining, is_overage, reason = check_rate_limit("mcp_test_redis_block", limit=3)

    assert allowed is False
    assert remaining == 0
    assert reason == "daily_cap"


def test_redis_hot_path_blocks_at_monthly_quota():
    """Le hot path Redis bascule sur JSON quand quota mensuel épuisé (pas d'overage → blocked)."""
    fake_r = FakeRedis()
    with patch("trust_layer.rate_limit._MONTHLY_LIMITS", {"free": 2, "pro": 5000, "enterprise": 50000, "test": None}), \
         patch("trust_layer.rate_limit.get_redis", return_value=fake_r):
        check_rate_limit("mcp_free_redis_monthly", limit=100)
        check_rate_limit("mcp_free_redis_monthly", limit=100)
        allowed, remaining, is_overage, reason = check_rate_limit("mcp_free_redis_monthly", limit=100)

    assert allowed is False
    assert remaining == 0
    assert reason == "monthly_quota"


def test_redis_get_usage_reads_from_redis():
    """get_usage retourne les compteurs Redis quand Redis est actif."""
    fake_r = FakeRedis()
    with patch("trust_layer.rate_limit.get_redis", return_value=fake_r):
        check_rate_limit("mcp_test_redis_usage", limit=50)
        check_rate_limit("mcp_test_redis_usage", limit=50)
        usage = get_usage("mcp_test_redis_usage", limit=50)

    assert usage["daily"]["used"] == 2
    assert usage["daily"]["remaining"] == 48


def test_redis_fallback_json_when_unavailable():
    """Quand Redis est None, le fallback JSON fonctionne normalement."""
    with patch("trust_layer.rate_limit.get_redis", return_value=None):
        allowed, remaining, is_overage, reason = check_rate_limit("mcp_test_redis_fallback", limit=10)

    assert allowed is True
    assert reason == ""
