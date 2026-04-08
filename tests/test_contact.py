"""Tests for POST /v1/contact — enterprise demo request endpoint."""

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from trust_layer.app import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_contact_rate():
    """Clear the in-memory rate limit dict before each test to prevent cross-test pollution."""
    from trust_layer.app import _CONTACT_RATE
    _CONTACT_RATE.clear()
    yield
    _CONTACT_RATE.clear()


VALID_PAYLOAD = {
    "first_name": "Alex",
    "last_name": "Chen",
    "email": "alex@acme-corp.com",
    "company": "Acme Corp",
    "use_case": "eu_ai_act",
    "message": "We need EU AI Act compliance for our multi-model pipeline.",
}


def test_contact_success():
    """Valid request returns 200 and suppresses email errors gracefully."""
    with patch("trust_layer.app.send_demo_request_email") as mock_send:
        resp = client.post("/v1/contact", json=VALID_PAYLOAD)
    assert resp.status_code == 200
    assert resp.json() == {"status": "received"}
    mock_send.assert_called_once_with(
        first_name="Alex",
        last_name="Chen",
        email="alex@acme-corp.com",
        company="Acme Corp",
        use_case="eu_ai_act",
        message="We need EU AI Act compliance for our multi-model pipeline.",
    )


def test_contact_email_failure_is_graceful():
    """Email failure does NOT cause a 500 — best-effort delivery."""
    with patch("trust_layer.app.send_demo_request_email", side_effect=RuntimeError("SMTP down")):
        resp = client.post("/v1/contact", json=VALID_PAYLOAD)
    assert resp.status_code == 200
    assert resp.json()["status"] == "received"


def test_contact_missing_first_name():
    payload = {**VALID_PAYLOAD, "first_name": ""}
    resp = client.post("/v1/contact", json=payload)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "invalid_request"


def test_contact_missing_last_name():
    payload = {**VALID_PAYLOAD, "last_name": ""}
    resp = client.post("/v1/contact", json=payload)
    assert resp.status_code == 400


def test_contact_invalid_email():
    payload = {**VALID_PAYLOAD, "email": "not-an-email"}
    resp = client.post("/v1/contact", json=payload)
    assert resp.status_code == 400


def test_contact_missing_company():
    payload = {**VALID_PAYLOAD, "company": ""}
    resp = client.post("/v1/contact", json=payload)
    assert resp.status_code == 400


def test_contact_unknown_use_case_is_coerced():
    """Unknown use_case values are silently coerced to 'other'."""
    payload = {**VALID_PAYLOAD, "use_case": "totally_unknown_value"}
    with patch("trust_layer.app.send_demo_request_email") as mock_send:
        resp = client.post("/v1/contact", json=payload)
    assert resp.status_code == 200
    mock_send.assert_called_once()
    _, kwargs = mock_send.call_args
    assert kwargs.get("use_case") == "other"


def test_contact_optional_fields_absent():
    """use_case and message are optional — request succeeds without them."""
    payload = {
        "first_name": "Sam",
        "last_name": "Lee",
        "email": "sam@bigcorp.io",
        "company": "BigCorp",
    }
    with patch("trust_layer.app.send_demo_request_email"):
        resp = client.post("/v1/contact", json=payload)
    assert resp.status_code == 200


def test_contact_message_too_long():
    payload = {**VALID_PAYLOAD, "message": "x" * 2001}
    resp = client.post("/v1/contact", json=payload)
    assert resp.status_code == 400


def test_contact_invalid_json():
    resp = client.post("/v1/contact", content=b"not json", headers={"Content-Type": "application/json"})
    assert resp.status_code == 400


def test_contact_rate_limit():
    """IP should be blocked after 3 requests in 1 hour."""
    from trust_layer.app import _CONTACT_RATE

    # Clear rate state for our test IP
    _CONTACT_RATE.pop("testclient", None)

    with patch("trust_layer.app.send_demo_request_email"):
        for _ in range(3):
            resp = client.post("/v1/contact", json=VALID_PAYLOAD)
            assert resp.status_code == 200

        # 4th request should be rate-limited
        resp = client.post("/v1/contact", json=VALID_PAYLOAD)
    assert resp.status_code == 429
    assert resp.json()["error"]["code"] == "rate_limited"
