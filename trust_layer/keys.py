"""API key lifecycle — generate, validate, deactivate."""

import secrets
import threading
import logging
from datetime import datetime, timezone
from typing import Optional

from .config import API_KEYS_FILE, OVERAGE_CAP_DEFAULT, OVERAGE_CAP_MIN, OVERAGE_CAP_MAX, OVERAGE_PRICES
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

    Plans: 'free' (100 proofs/month, public), 'pro' (unlimited).
    """
    if plan == "free":
        prefix = "mcp_free_"
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
            "overage_enabled": False,
            "overage_cap_eur": OVERAGE_CAP_DEFAULT,
            "overage_consent_at": None,
            "overage_consent_rate": None,
            "overage_disabled_at": None,
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


def get_key_plan(api_key: str) -> str:
    """Return the plan for an API key ('free', 'pro', or 'test')."""
    if api_key.startswith("mcp_free_"):
        return "free"
    if api_key.startswith("mcp_test_"):
        return "test"
    return "pro"


def get_overage_settings(api_key: str) -> dict:
    """Return overage settings for a key (read-only)."""
    key_info = validate_api_key(api_key) or {}
    plan = get_key_plan(api_key)
    return {
        "overage_enabled": key_info.get("overage_enabled", False),
        "overage_cap_eur": key_info.get("overage_cap_eur", OVERAGE_CAP_DEFAULT),
        "overage_consent_at": key_info.get("overage_consent_at"),
        "overage_consent_rate": key_info.get("overage_consent_rate"),
        "plan": plan,
        "overage_price": OVERAGE_PRICES.get(plan, 0),
    }


def update_overage_settings(api_key: str, enabled: bool, cap_eur: float, overage_rate: float) -> dict:
    """Enable or disable overage billing for a key. Returns updated settings.

    Raises ValueError on invalid input or unsupported plan.
    """
    plan = get_key_plan(api_key)
    if plan not in ("pro", "enterprise"):
        raise ValueError(f"Overage billing only available for Pro and Enterprise plans, got '{plan}'")

    if not isinstance(enabled, bool):
        raise ValueError("'enabled' must be a boolean")

    if not (OVERAGE_CAP_MIN <= cap_eur <= OVERAGE_CAP_MAX):
        raise ValueError(
            f"cap_eur must be between {OVERAGE_CAP_MIN} and {OVERAGE_CAP_MAX}, got {cap_eur}"
        )

    now = datetime.now(timezone.utc).isoformat()

    with _KEYS_LOCK:
        keys = load_api_keys()
        info = keys.get(api_key)
        if not info or not info.get("active"):
            raise ValueError("API key not found or inactive")

        if enabled:
            info["overage_enabled"] = True
            info["overage_cap_eur"] = cap_eur
            info["overage_consent_at"] = now
            info["overage_consent_rate"] = overage_rate
            info.pop("overage_disabled_at", None)
        else:
            info["overage_enabled"] = False
            info["overage_disabled_at"] = now
            # Preserve consent_at and consent_rate for audit trail

        save_api_keys(keys)
        logger.info("Overage billing %s for key %s (cap=%.2f)", "enabled" if enabled else "disabled", api_key[:12], cap_eur)

    return get_overage_settings(api_key)
