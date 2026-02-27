"""Prepaid credit management — balance, debit, purchase, transaction log."""

import json
import logging
import secrets
from datetime import datetime, timezone

from .config import API_KEYS_FILE, CREDIT_TRANSACTIONS_LOG, PROOF_PRICE
from .keys import load_api_keys, save_api_keys

logger = logging.getLogger("trust_layer.credits")


class InsufficientCredits(Exception):
    """Raised when credit balance is too low for the requested operation."""
    def __init__(self, balance: float, required: float):
        self.balance = balance
        self.required = required
        super().__init__(f"Insufficient credits: {balance:.2f} EUR available, {required:.2f} EUR required")


def _generate_credit_id() -> str:
    """Generate a unique credit transaction ID."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    rand = secrets.token_hex(3)
    return f"crd_{ts}_{rand}"


def get_balance(api_key: str) -> float:
    """Return the credit balance for an API key."""
    keys = load_api_keys()
    info = keys.get(api_key, {})
    return float(info.get("credit_balance", 0.0))


def debit_credits(api_key: str, amount: float, proof_id: str) -> str:
    """Debit credits from an API key. Returns transaction ID.

    Raises InsufficientCredits if balance < amount.
    """
    keys = load_api_keys()
    info = keys.get(api_key)
    if not info:
        raise ValueError(f"API key not found")

    balance = float(info.get("credit_balance", 0.0))
    if balance < amount:
        raise InsufficientCredits(balance, amount)

    new_balance = round(balance - amount, 2)
    info["credit_balance"] = new_balance
    save_api_keys(keys)

    txn_id = _generate_credit_id()
    log_transaction({
        "id": txn_id,
        "type": "debit",
        "api_key_prefix": api_key[:16],
        "amount": amount,
        "proof_id": proof_id,
        "balance_after": new_balance,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    logger.info("Credit debit %.2f EUR for %s (proof=%s, balance=%.2f)",
                amount, api_key[:16], proof_id, new_balance)
    return txn_id


def add_credits(api_key: str, amount: float, stripe_pi: str) -> float:
    """Add credits to an API key after a Stripe purchase. Returns new balance."""
    keys = load_api_keys()
    info = keys.get(api_key)
    if not info:
        raise ValueError(f"API key not found")

    balance = float(info.get("credit_balance", 0.0))
    new_balance = round(balance + amount, 2)
    info["credit_balance"] = new_balance
    info["total_credits_purchased"] = round(
        float(info.get("total_credits_purchased", 0.0)) + amount, 2
    )
    save_api_keys(keys)

    txn_id = _generate_credit_id()
    log_transaction({
        "id": txn_id,
        "type": "purchase",
        "api_key_prefix": api_key[:16],
        "amount": amount,
        "stripe_pi": stripe_pi,
        "balance_after": new_balance,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    logger.info("Credit purchase %.2f EUR for %s (pi=%s, balance=%.2f)",
                amount, api_key[:16], stripe_pi, new_balance)
    return new_balance


def log_transaction(entry: dict):
    """Append a credit transaction to the JSONL log."""
    try:
        with open(CREDIT_TRANSACTIONS_LOG, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as e:
        logger.warning("Failed to log credit transaction: %s", e)
