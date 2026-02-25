"""Stripe payment provider — off-session charges."""

import logging
from typing import Optional

import stripe

from .base import ChargeResult

logger = logging.getLogger("trust_layer.stripe")


class StripeProvider:
    def __init__(self, secret_key: str):
        self.sk = secret_key

    async def find_payment_method(self, customer_id: str) -> str:
        """Find the customer's saved payment method."""
        if not self.sk:
            raise ValueError("Stripe key not configured")

        customer = stripe.Customer.retrieve(customer_id, api_key=self.sk)
        pm_id = None

        # Check invoice_settings default
        invoice_settings = customer.get("invoice_settings") or {}
        if invoice_settings.get("default_payment_method"):
            pm_id = invoice_settings["default_payment_method"]

        # Fallback: list card payment methods
        if not pm_id:
            pms = stripe.PaymentMethod.list(
                customer=customer_id, type="card", limit=1, api_key=self.sk
            )
            if pms.data:
                pm_id = pms.data[0].id

        # Fallback: try link type
        if not pm_id:
            pms = stripe.PaymentMethod.list(
                customer=customer_id, type="link", limit=1, api_key=self.sk
            )
            if pms.data:
                pm_id = pms.data[0].id

        if not pm_id:
            raise ValueError("No payment method found. Use setup_card first.")

        return pm_id

    async def charge(
        self,
        amount: float,
        currency: str,
        customer_id: str,
        description: str,
        metadata: dict,
    ) -> ChargeResult:
        """Create a PaymentIntent off-session and confirm immediately."""
        if not self.sk:
            raise ValueError("Stripe key not configured")

        pm_id = await self.find_payment_method(customer_id)
        amount_cents = int(round(amount * 100))

        intent = stripe.PaymentIntent.create(
            amount=amount_cents,
            currency=currency,
            customer=customer_id,
            payment_method=pm_id,
            off_session=True,
            confirm=True,
            description=description,
            metadata=metadata,
            api_key=self.sk,
        )

        if intent.status != "succeeded":
            return ChargeResult(
                provider="stripe",
                transaction_id=intent.id,
                amount=amount,
                currency=currency,
                status="failed",
                raw={"stripe_status": intent.status},
            )

        receipt_url = None
        if intent.latest_charge:
            try:
                charge = stripe.Charge.retrieve(intent.latest_charge, api_key=self.sk)
                receipt_url = charge.receipt_url
            except Exception:
                pass

        return ChargeResult(
            provider="stripe",
            transaction_id=intent.id,
            amount=amount,
            currency=currency,
            status="succeeded",
            receipt_url=receipt_url,
            raw={"payment_method": pm_id},
        )
