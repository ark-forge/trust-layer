"""Le client Redis ne journalise jamais le mot de passe de l'URL de connexion."""

import logging
from unittest.mock import patch

import pytest

from trust_layer import redis_client


@pytest.fixture(autouse=True)
def _reset():
    redis_client.reset_redis()
    yield
    redis_client.reset_redis()


def test_connexion_journalisee_sans_mot_de_passe(caplog):
    url = "redis://:motdepasse-de-test-42@127.0.0.1:6379/0"
    with patch("trust_layer.config.REDIS_URL", url), patch("redis.Redis.ping", return_value=True):
        with caplog.at_level(logging.INFO, logger="trust_layer.redis_client"):
            assert redis_client.get_redis() is not None

    journal = caplog.text
    assert "Redis connected" in journal
    assert "127.0.0.1:6379/0" in journal
    assert "motdepasse-de-test-42" not in journal
