"""Redis singleton — retourne None si Redis est indisponible (fallback JSON automatique)."""

import logging

logger = logging.getLogger("trust_layer.redis_client")

_redis_client = None
_redis_checked = False


def get_redis():
    """Return a connected Redis client, or None if Redis is unavailable."""
    global _redis_client, _redis_checked
    if _redis_checked:
        return _redis_client
    _redis_checked = True
    try:
        import redis
        from .config import REDIS_URL
        r = redis.Redis.from_url(
            REDIS_URL,
            socket_connect_timeout=1,
            socket_timeout=1,
            decode_responses=True,
        )
        r.ping()
        _redis_client = r
        logger.info("Redis connected: %s", REDIS_URL)
    except Exception as e:
        logger.info("Redis unavailable — fallback to JSON: %s", e)
        _redis_client = None
    return _redis_client


def reset_redis():
    """Reset singleton (tests only)."""
    global _redis_client, _redis_checked
    _redis_client = None
    _redis_checked = False
