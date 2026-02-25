"""Payment providers — abstraction over Stripe and future providers."""

from .base import PaymentProvider, ChargeResult
from .stripe_provider import StripeProvider

__all__ = ["PaymentProvider", "ChargeResult", "StripeProvider", "get_provider"]


def get_provider(api_key: str = "") -> PaymentProvider:
    """Return the payment provider based on API key prefix."""
    from ..config import STRIPE_TEST_KEY, STRIPE_LIVE_KEY
    from ..keys import is_test_key

    if is_test_key(api_key):
        return StripeProvider(STRIPE_TEST_KEY)
    return StripeProvider(STRIPE_LIVE_KEY)
