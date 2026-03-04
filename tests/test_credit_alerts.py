"""Tests for credit alert emails — low balance and exhausted."""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

from trust_layer.keys import create_api_key, load_api_keys, save_api_keys
from trust_layer.credits import add_credits, debit_credits
from trust_layer.config import PROOF_PRICE
from trust_layer.proxy import _notify_credits_exhausted, _notify_low_credits_if_needed


# --- Fixtures ---

@pytest.fixture
def pro_key():
    return create_api_key("cus_alert_test", "ref_alert_test", "alert@test.com", test_mode=True)


@pytest.fixture
def key_info(pro_key):
    return load_api_keys()[pro_key]


@pytest.fixture
def real_pro_key():
    """Real Pro key (mcp_pro_* prefix) — required for overage billing tests."""
    return create_api_key("cus_overage_test", "ref_overage_test", "overage@test.com",
                          test_mode=False, plan="pro")


# --- _notify_credits_exhausted ---

def test_exhausted_sends_email(pro_key, key_info):
    """Should send exhausted email when credits are zero."""
    with patch("trust_layer.proxy.send_credits_exhausted_email") as mock_send:
        _notify_credits_exhausted(pro_key, key_info)
        mock_send.assert_called_once_with("alert@test.com", pro_key)


def test_exhausted_respects_24h_cooldown(pro_key, key_info):
    """Should NOT send exhausted email if already sent within 24h."""
    keys = load_api_keys()
    keys[pro_key]["credits_exhausted_alert_sent_at"] = datetime.now(timezone.utc).isoformat()
    save_api_keys(keys)

    with patch("trust_layer.proxy.send_credits_exhausted_email") as mock_send:
        _notify_credits_exhausted(pro_key, key_info)
        mock_send.assert_not_called()


def test_exhausted_sends_again_after_24h(pro_key, key_info):
    """Should send exhausted email again if last alert was > 24h ago."""
    old_time = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
    keys = load_api_keys()
    keys[pro_key]["credits_exhausted_alert_sent_at"] = old_time
    save_api_keys(keys)

    with patch("trust_layer.proxy.send_credits_exhausted_email") as mock_send:
        _notify_credits_exhausted(pro_key, key_info)
        mock_send.assert_called_once()


def test_exhausted_no_email_if_no_address(pro_key):
    """Should not crash or send if key has no email."""
    key_info_no_email = {"plan": "pro", "active": True}
    with patch("trust_layer.proxy.send_credits_exhausted_email") as mock_send:
        _notify_credits_exhausted(pro_key, key_info_no_email)
        mock_send.assert_not_called()


def test_exhausted_stores_timestamp(pro_key, key_info):
    """Should store credits_exhausted_alert_sent_at after sending."""
    with patch("trust_layer.proxy.send_credits_exhausted_email"):
        _notify_credits_exhausted(pro_key, key_info)

    keys = load_api_keys()
    assert "credits_exhausted_alert_sent_at" in keys[pro_key]


# --- _notify_low_credits_if_needed ---

def test_low_credits_sends_when_below_threshold(pro_key, key_info):
    """Should send low credits email when balance < 10 proofs."""
    low_balance = round(PROOF_PRICE * 5, 2)  # 5 proofs = 0.50 EUR
    with patch("trust_layer.proxy.send_low_credits_email") as mock_send:
        _notify_low_credits_if_needed(pro_key, key_info, low_balance)
        mock_send.assert_called_once_with("alert@test.com", pro_key, low_balance, 5)


def test_low_credits_no_email_above_threshold(pro_key, key_info):
    """Should NOT send email when balance is above threshold."""
    high_balance = round(PROOF_PRICE * 20, 2)  # 20 proofs = 2.00 EUR
    with patch("trust_layer.proxy.send_low_credits_email") as mock_send:
        _notify_low_credits_if_needed(pro_key, key_info, high_balance)
        mock_send.assert_not_called()


def test_low_credits_respects_24h_cooldown(pro_key, key_info):
    """Should NOT send low credits email if already sent within 24h."""
    keys = load_api_keys()
    keys[pro_key]["low_credits_alert_sent_at"] = datetime.now(timezone.utc).isoformat()
    save_api_keys(keys)

    low_balance = round(PROOF_PRICE * 3, 2)
    with patch("trust_layer.proxy.send_low_credits_email") as mock_send:
        _notify_low_credits_if_needed(pro_key, key_info, low_balance)
        mock_send.assert_not_called()


def test_low_credits_sends_again_after_24h(pro_key, key_info):
    """Should send low credits email again if last alert was > 24h ago."""
    old_time = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
    keys = load_api_keys()
    keys[pro_key]["low_credits_alert_sent_at"] = old_time
    save_api_keys(keys)

    low_balance = round(PROOF_PRICE * 3, 2)
    with patch("trust_layer.proxy.send_low_credits_email") as mock_send:
        _notify_low_credits_if_needed(pro_key, key_info, low_balance)
        mock_send.assert_called_once()


def test_low_credits_stores_timestamp(pro_key, key_info):
    """Should store low_credits_alert_sent_at after sending."""
    low_balance = round(PROOF_PRICE * 3, 2)
    with patch("trust_layer.proxy.send_low_credits_email"):
        _notify_low_credits_if_needed(pro_key, key_info, low_balance)

    keys = load_api_keys()
    assert "low_credits_alert_sent_at" in keys[pro_key]


def test_low_credits_zero_balance(pro_key, key_info):
    """Balance = 0 is below threshold — should trigger low credits alert."""
    with patch("trust_layer.proxy.send_low_credits_email") as mock_send:
        _notify_low_credits_if_needed(pro_key, key_info, 0.0)
        mock_send.assert_called_once_with("alert@test.com", pro_key, 0.0, 0)


# --- Integration: proxy rejects on overage with 0 credits ---

@pytest.mark.asyncio
async def test_proxy_triggers_exhausted_email_on_402(real_pro_key):
    """Overage proof with 0 credits → 402 insufficient_overage_credits + rollback.

    In the subscription model, Pro keys within quota use no credits.
    Credits are only debited for overage proofs — insufficient balance raises 402.
    """
    from trust_layer.proxy import execute_proxy, ProxyError
    from trust_layer.keys import update_overage_settings
    from trust_layer.config import PRO_OVERAGE_PRICE

    pro_key = real_pro_key
    # Enable overage (0 credits — no add_credits)
    update_overage_settings(pro_key, enabled=True, cap_eur=10.0,
                            overage_rate=PRO_OVERAGE_PRICE)

    # Simulate quota exhausted → overage path
    with patch("trust_layer.proxy.check_rate_limit",
               return_value=(True, 0, True, "")), \
         patch("trust_layer.proxy.rollback_overage") as mock_rollback, \
         pytest.raises(ProxyError) as exc_info:
        await execute_proxy(
            target="https://httpbin.org/get",
            method="GET",
            payload={},
            amount=0.0,
            currency="eur",
            api_key=pro_key,
        )

    assert exc_info.value.status == 402
    assert exc_info.value.code == "insufficient_overage_credits"
    mock_rollback.assert_called_once()


@pytest.mark.asyncio
async def test_proxy_triggers_low_credits_after_debit(real_pro_key):
    """After an overage debit that drops balance below threshold, low-credits email fires."""
    from trust_layer.proxy import execute_proxy
    from trust_layer.keys import update_overage_settings
    from trust_layer.config import PRO_OVERAGE_PRICE
    from unittest.mock import AsyncMock, MagicMock, patch as upatch

    pro_key = real_pro_key
    # Enable overage and fund below the 1.00 EUR threshold (0.20 EUR)
    update_overage_settings(pro_key, enabled=True, cap_eur=10.0,
                            overage_rate=PRO_OVERAGE_PRICE)
    add_credits(pro_key, round(PROOF_PRICE * 2, 2), "pi_low_test")  # 0.20 EUR

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Date": "Mon, 02 Mar 2026 13:00:00 GMT"}
    mock_resp.json.return_value = {"result": "ok"}

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    mock_client.get.return_value = mock_resp
    mock_client.post.return_value = mock_resp

    # Simulate quota exhausted → overage path
    with upatch("trust_layer.proxy.check_rate_limit",
                return_value=(True, 0, True, "")), \
         upatch("trust_layer.proxy._notify_low_credits_if_needed") as mock_notify, \
         upatch("trust_layer.proxy.httpx.AsyncClient", return_value=mock_client), \
         upatch("trust_layer.proxy.submit_hash"), \
         upatch("trust_layer.proxy.send_proof_email"), \
         upatch("trust_layer.proxy._update_agent_profile"), \
         upatch("trust_layer.proxy._update_service_profile"), \
         upatch("trust_layer.proxy.sign_proof", return_value="ed25519:testsig"):
        await execute_proxy(
            target="https://httpbin.org/get",
            method="GET",
            payload={},
            amount=0.0,
            currency="eur",
            api_key=pro_key,
        )

    mock_notify.assert_called_once()
