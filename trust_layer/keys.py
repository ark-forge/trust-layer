"""API key lifecycle — generate, validate, deactivate."""

import secrets
import logging
from datetime import datetime, timezone
from typing import Optional

from .config import API_KEYS_FILE
from .persistence import load_json, save_json

logger = logging.getLogger("trust_layer.keys")


def load_api_keys() -> dict:
    return load_json(API_KEYS_FILE, {})


def save_api_keys(keys: dict):
    save_json(API_KEYS_FILE, keys)


def generate_api_key(test_mode: bool = False) -> str:
    """Generate a new API key with appropriate prefix."""
    prefix = "mcp_test_" if test_mode else "mcp_pro_"
    return f"{prefix}{secrets.token_hex(24)}"


def validate_api_key(key: str) -> Optional[dict]:
    """Return key info if valid and active, else None."""
    keys = load_api_keys()
    info = keys.get(key)
    if info and info.get("active"):
        return info
    return None


def create_api_key(stripe_customer_id: str, ref_id: str, email: str = "", test_mode: bool = False) -> str:
    """Create and persist a new API key."""
    keys = load_api_keys()
    key = generate_api_key(test_mode=test_mode)
    keys[key] = {
        "active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "stripe_customer_id": stripe_customer_id,
        "stripe_ref_id": ref_id,
        "email": email,
        "transactions_total": 0,
    }
    save_api_keys(keys)
    logger.info("API key created for customer %s", stripe_customer_id)
    return key


def deactivate_key_by_ref(ref_id: str):
    """Deactivate all keys matching a Stripe ref (subscription/payment intent)."""
    keys = load_api_keys()
    for key, info in keys.items():
        if info.get("stripe_ref_id") == ref_id:
            info["active"] = False
            info["deactivated_at"] = datetime.now(timezone.utc).isoformat()
            logger.info("API key deactivated for ref %s", ref_id)
    save_api_keys(keys)


def find_key_by_ref(ref_id: str) -> Optional[str]:
    """Find an active key by Stripe ref."""
    keys = load_api_keys()
    for key, info in keys.items():
        if info.get("stripe_ref_id") == ref_id and info.get("active"):
            return key
    return None


def is_test_key(api_key: str) -> bool:
    """Check if an API key is a test mode key."""
    return api_key.startswith("mcp_test_")
