"""Payment provider protocol and result dataclass."""

from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable


@dataclass
class ChargeResult:
    provider: str  # "stripe", "crypto", etc.
    transaction_id: str  # pi_... for Stripe
    amount: float
    currency: str
    status: str  # "succeeded", "failed"
    receipt_url: Optional[str] = None
    raw: dict = field(default_factory=dict)


@runtime_checkable
class PaymentProvider(Protocol):
    async def charge(
        self,
        amount: float,
        currency: str,
        customer_id: str,
        description: str,
        metadata: dict,
    ) -> ChargeResult: ...

    async def find_payment_method(self, customer_id: str) -> str: ...
