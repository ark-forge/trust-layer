"""API key lifecycle — generate, validate, deactivate."""

import secrets
import threading
import logging
from datetime import datetime, timezone
from typing import Optional

from .config import API_KEYS_FILE
from .persistence import load_json, save_json

logger = logging.getLogger("trust_layer.keys")

# Global lock — serialises all api_keys.json write operations.
# Prevents lost updates when multiple threads call create_api_key,
# deactivate_key_by_ref, or any other function that does load+modify+save.
_KEYS_LOCK = threading.Lock()


def load_api_keys() -> dict:
    return load_json(API_KEYS_FILE, {})


def save_api_keys(keys: dict):
    save_json(API_KEYS_FILE, keys)


def generate_api_key(test_mode: bool = False, plan: str = "pro") -> str:
    """Generate a new API key with appropriate prefix.

    Plans: 'free' (500/month), 'pro' (€39/month, 5 000/month),
           'enterprise' (€149/month, 50 000/month), 'test' (internal).
    """
    if plan == "free":
        prefix = "mcp_free_"
    elif plan == "enterprise":
        prefix = "mcp_ent_"
    elif test_mode:
        prefix = "mcp_test_"
    else:
        prefix = "mcp_pro_"
    return f"{prefix}{secrets.token_hex(24)}"


def validate_api_key(key: str) -> Optional[dict]:
    """Return key info if valid and active, else None."""
    keys = load_api_keys()
    info = keys.get(key)
    if info and info.get("active"):
        return info
    return None


def create_api_key(stripe_customer_id: str, ref_id: str, email: str = "",
                   test_mode: bool = False, plan: str = "pro") -> str:
    """Create and persist a new API key."""
    key = generate_api_key(test_mode=test_mode, plan=plan)
    with _KEYS_LOCK:
        keys = load_api_keys()
        keys[key] = {
            "active": True,
            "plan": plan,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "stripe_customer_id": stripe_customer_id,
            "stripe_ref_id": ref_id,
            "email": email,
            "transactions_total": 0,
            "credit_balance": 0.0,
            "total_credits_purchased": 0.0,
        }
        save_api_keys(keys)
    logger.info("API key created for customer %s (plan=%s)", stripe_customer_id, plan)
    return key


def deactivate_key_by_ref(ref_id: str):
    """Deactivate all keys matching a Stripe ref (subscription/payment intent)."""
    with _KEYS_LOCK:
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


def is_free_key(api_key: str) -> bool:
    """Check if an API key is a free tier key."""
    return api_key.startswith("mcp_free_")


def is_enterprise_key(api_key: str) -> bool:
    """Check if an API key is an enterprise tier key."""
    return api_key.startswith("mcp_ent_")


def get_key_plan(api_key: str) -> str:
    """Return the plan for an API key ('free', 'pro', 'enterprise', or 'test')."""
    if api_key.startswith("mcp_free_"):
        return "free"
    if api_key.startswith("mcp_test_"):
        return "test"
    if api_key.startswith("mcp_ent_"):
        return "enterprise"
    return "pro"
