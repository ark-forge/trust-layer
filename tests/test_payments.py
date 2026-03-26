"""Tests for payment providers."""

import pytest
from unittest.mock import MagicMock, patch

from trust_layer.payments.base import ChargeResult, PaymentProvider
from trust_layer.payments.stripe_provider import StripeProvider


def test_charge_result_dataclass():
    r = ChargeResult(
        provider="stripe",
        transaction_id="pi_123",
        amount=1.00,
        currency="eur",
        status="succeeded",
        receipt_url="https://stripe.com/r/123",
    )
    assert r.provider == "stripe"
    assert r.amount == 1.00
    assert r.status == "succeeded"


def test_stripe_provider_is_payment_provider():
    assert isinstance(StripeProvider("sk_test_123"), PaymentProvider)


@pytest.mark.asyncio
async def test_stripe_charge_success():
    provider = StripeProvider("sk_test_fake")

    mock_pm_list = MagicMock()
    mock_pm_list.data = [MagicMock(id="pm_test_card")]

    mock_customer = MagicMock()
    mock_customer.invoice_settings = None  # stripe 15: dot notation, no .get()

    mock_intent = MagicMock()
    mock_intent.id = "pi_test_success"
    mock_intent.status = "succeeded"
    mock_intent.latest_charge = "ch_test_123"

    mock_charge = MagicMock()
    mock_charge.receipt_url = "https://pay.stripe.com/receipts/test"

    with patch("stripe.Customer.retrieve", return_value=mock_customer), \
         patch("stripe.PaymentMethod.list", return_value=mock_pm_list), \
         patch("stripe.PaymentIntent.create", return_value=mock_intent), \
         patch("stripe.Charge.retrieve", return_value=mock_charge):

        result = await provider.charge(
            amount=0.50,
            currency="eur",
            customer_id="cus_test",
            description="test charge",
            metadata={},
        )

    assert result.status == "succeeded"
    assert result.transaction_id == "pi_test_success"
    assert result.receipt_url == "https://pay.stripe.com/receipts/test"
    assert result.provider == "stripe"


@pytest.mark.asyncio
async def test_stripe_charge_failed():
    provider = StripeProvider("sk_test_fake")

    mock_pm_list = MagicMock()
    mock_pm_list.data = [MagicMock(id="pm_test_card")]
    mock_customer = MagicMock()
    mock_customer.invoice_settings = None  # stripe 15: dot notation, no .get()

    mock_intent = MagicMock()
    mock_intent.id = "pi_test_failed"
    mock_intent.status = "requires_action"
    mock_intent.latest_charge = None

    with patch("stripe.Customer.retrieve", return_value=mock_customer), \
         patch("stripe.PaymentMethod.list", return_value=mock_pm_list), \
         patch("stripe.PaymentIntent.create", return_value=mock_intent):

        result = await provider.charge(
            amount=0.50,
            currency="eur",
            customer_id="cus_test",
            description="test charge",
            metadata={},
        )

    assert result.status == "failed"


@pytest.mark.asyncio
async def test_stripe_no_payment_method():
    provider = StripeProvider("sk_test_fake")

    mock_pm_empty = MagicMock()
    mock_pm_empty.data = []
    mock_customer = MagicMock()
    mock_customer.invoice_settings = None  # stripe 15: dot notation, no .get()

    with patch("stripe.Customer.retrieve", return_value=mock_customer), \
         patch("stripe.PaymentMethod.list", return_value=mock_pm_empty):

        with pytest.raises(ValueError, match="No payment method found"):
            await provider.charge(
                amount=0.50, currency="eur", customer_id="cus_test",
                description="test", metadata={},
            )


def test_stripe_no_key():
    provider = StripeProvider("")
    # find_payment_method should fail with empty key
    import asyncio
    with pytest.raises(ValueError, match="Stripe key not configured"):
        asyncio.get_event_loop().run_until_complete(
            provider.find_payment_method("cus_123")
        )
