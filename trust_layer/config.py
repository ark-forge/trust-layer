"""Configuration — env vars, paths, constants."""

import os
from pathlib import Path

# --- Paths ---
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
PROOFS_DIR = BASE_DIR / "proofs"
DATA_DIR.mkdir(exist_ok=True)
PROOFS_DIR.mkdir(exist_ok=True)

API_KEYS_FILE = DATA_DIR / "api_keys.json"
RATE_LIMITS_FILE = DATA_DIR / "rate_limits.json"
BACKGROUND_TASKS_LOG = DATA_DIR / "background_tasks_log.jsonl"
PROOF_ACCESS_LOG = DATA_DIR / "proof_access_log.jsonl"
IDEMPOTENCY_DIR = DATA_DIR / "idempotency"
AGENTS_DIR = DATA_DIR / "agents"
SERVICES_DIR = DATA_DIR / "services"
for _d in (IDEMPOTENCY_DIR, AGENTS_DIR, SERVICES_DIR):
    _d.mkdir(exist_ok=True)

# --- Load secrets: vault first, settings.env fallback ---
def _load_secrets() -> None:
    """Populate os.environ from vault (primary) then settings.env (fallback)."""
    # 1. Try vault
    _vault_loaded = False
    try:
        import sys as _sys
        _vault_path = os.environ.get("VAULT_PATH", "/opt/claude-ceo")
        if _vault_path not in _sys.path:
            _sys.path.insert(0, _vault_path)
        from automation.vault import vault as _vault  # type: ignore[import]
        _stripe = _vault.get_section("stripe") or {}
        _smtp = _vault.get_section("smtp") or {}
        _mapping = {
            "STRIPE_LIVE_SECRET_KEY":        _stripe.get("live_secret_key", ""),
            "STRIPE_TEST_SECRET_KEY":         _stripe.get("test_secret_key", ""),
            "STRIPE_TL_WEBHOOK_SECRET":       _stripe.get("tl_webhook_secret", ""),
            "STRIPE_TL_WEBHOOK_SECRET_TEST":  _stripe.get("tl_webhook_secret_test", ""),
            "STRIPE_PRO_PRICE_ID":             _stripe.get("pro_price_id", ""),
            "STRIPE_PRO_PRICE_ID_TEST":        _stripe.get("pro_price_id_test", ""),
            "STRIPE_ENTERPRISE_PRICE_ID":      _stripe.get("enterprise_price_id", ""),
            "STRIPE_ENTERPRISE_PRICE_ID_TEST": _stripe.get("enterprise_price_id_test", ""),
            "STRIPE_PRO_PRODUCT_ID":           _stripe.get("pro_product_id", ""),
            "SMTP_HOST":                      _smtp.get("host", ""),
            "SMTP_LOGIN":                     _smtp.get("login", ""),
            "SMTP_USER":                      _smtp.get("user", ""),
            "SMTP_PASSWORD":                  _smtp.get("password", ""),
        }
        for _k, _v in _mapping.items():
            if _v:
                os.environ.setdefault(_k, _v)
        _vault_loaded = True
    except Exception:
        pass  # vault unavailable → fall through to settings.env

    # 2. settings.env fallback (fills any gaps vault didn't cover)
    _settings_env = Path(os.environ.get(
        "SETTINGS_ENV_PATH",
        "/opt/claude-ceo/config/settings.env",
    ))
    if _settings_env.exists():
        for _line in _settings_env.read_text().splitlines():
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _, _v = _line.partition("=")
                os.environ.setdefault(_k.strip(), _v.strip())

    import logging as _log
    _log.getLogger("trust_layer.config").debug(
        "Secrets loaded from %s", "vault" if _vault_loaded else "settings.env only"
    )

_load_secrets()

# --- Stripe ---
STRIPE_LIVE_KEY = os.environ.get("STRIPE_LIVE_SECRET_KEY", "")
STRIPE_TEST_KEY = os.environ.get("STRIPE_TEST_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET_LIVE = os.environ.get("STRIPE_TL_WEBHOOK_SECRET", os.environ.get("STRIPE_WEBHOOK_SECRET", ""))
STRIPE_WEBHOOK_SECRET_TEST = os.environ.get("STRIPE_TL_WEBHOOK_SECRET_TEST", os.environ.get("STRIPE_WEBHOOK_SECRET_TEST", ""))
STRIPE_PRO_PRICE_ID = os.environ.get("STRIPE_PRO_PRICE_ID", "")        # live
STRIPE_PRO_PRICE_ID_TEST = os.environ.get("STRIPE_PRO_PRICE_ID_TEST", "")  # test
STRIPE_ENTERPRISE_PRICE_ID = os.environ.get("STRIPE_ENTERPRISE_PRICE_ID", "")        # live
STRIPE_ENTERPRISE_PRICE_ID_TEST = os.environ.get("STRIPE_ENTERPRISE_PRICE_ID_TEST", "")  # test
STRIPE_PRO_PRODUCT_ID = os.environ.get("STRIPE_PRO_PRODUCT_ID", "")

# --- SMTP ---
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.resend.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_LOGIN = os.environ.get("SMTP_LOGIN", "resend")           # SMTP auth login (e.g. "resend" for Resend.com)
SMTP_USER = os.environ.get("SMTP_USER", os.environ.get("IMAP_USER", "noreply@arkforge.fr"))  # From address
SMTP_CONTACT = os.environ.get("SMTP_CONTACT", "contact@arkforge.fr") # reply-to (human inbox)
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", os.environ.get("IMAP_PASSWORD", ""))

# --- Proxy limits ---
SUPPORTED_CURRENCIES = ["eur", "usd", "gbp"]
MIN_AMOUNT = 0.50
MAX_AMOUNT = 50.00
PROXY_TIMEOUT_SECONDS = 120
MAX_RESPONSE_STORE_BYTES = 1_000_000  # 1 MB

# --- Prepaid credits ---
PROOF_PRICE = 0.10                # EUR per proof (Pro/Test)
MIN_CREDIT_PURCHASE = 1.00        # Min credit purchase off-session (= 10 proofs)
MAX_CREDIT_PURCHASE = 100.00      # Max credit purchase (= 1000 proofs)
PRO_SETUP_MIN_AMOUNT = 10.00      # Min amount for Checkout setup (= 100 proofs)
CREDIT_TRANSACTIONS_LOG = DATA_DIR / "credit_transactions.jsonl"
RATE_LIMIT_PER_KEY_PER_DAY = 500      # Fallback daily cap (used when plan unknown)
FREE_TIER_MONTHLY_LIMIT = 500         # Free: 500 proofs/month
PRO_MONTHLY_LIMIT = 5_000             # Pro €29/month: 5 000 proofs/month
ENTERPRISE_MONTHLY_LIMIT = 50_000     # Enterprise €149/month: 50 000 proofs/month

# Daily caps per plan.
# Free/Pro/Enterprise: set to monthly quota — the monthly counter fires first,
# the daily cap never adds a constraint beyond what is already sold.
# Test keys: hard 100/day guard (no monthly quota, prevents infinite runaway loops).
DAILY_LIMITS_PER_PLAN = {
    "free":       FREE_TIER_MONTHLY_LIMIT,   # 500  — daily cap = monthly quota
    "pro":        PRO_MONTHLY_LIMIT,          # 5 000 — daily cap = monthly quota
    "enterprise": ENTERPRISE_MONTHLY_LIMIT,   # 50 000 — daily cap = monthly quota
    "test":       100,                        # hard daily guard only
}
# Overage rates (credits billed when monthly quota exceeded)
PRO_OVERAGE_PRICE = 0.01              # EUR per proof over 5 000
ENTERPRISE_OVERAGE_PRICE = 0.005      # EUR per proof over 50 000
IDEMPOTENCY_TTL_HOURS = 24

# --- Overage billing (opt-in) ---
PRO_OVERAGE_PRICE = 0.01          # EUR per proof beyond monthly quota (Pro)
ENTERPRISE_OVERAGE_PRICE = 0.005  # EUR per proof beyond monthly quota (Enterprise)
OVERAGE_CAP_MIN = 5.00            # EUR minimum monthly cap
OVERAGE_CAP_MAX = 100.00          # EUR maximum monthly cap
OVERAGE_CAP_DEFAULT = 20.00       # EUR default suggested cap

# Plan → overage price mapping
OVERAGE_PRICES = {
    "pro": PRO_OVERAGE_PRICE,
    "enterprise": ENTERPRISE_OVERAGE_PRICE,
}

# Monthly quotas per plan (None = unlimited daily cap only)
_PRO_MONTHLY_LIMIT = 5000
_ENTERPRISE_MONTHLY_LIMIT = 50000

# --- Internal Secret (forwarded to upstream services for service-to-service auth) ---
INTERNAL_SECRET = os.environ.get("TRUST_LAYER_INTERNAL_SECRET", "")

# --- Webhook idempotency (prevents replay attacks on Stripe webhooks) ---
WEBHOOK_IDEMPOTENCY_FILE = DATA_DIR / "webhook_idempotency.jsonl"

# --- CORS allowed origins ---
CORS_ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get("CORS_ALLOWED_ORIGINS", "https://arkforge.tech,https://arkforge.fr,https://www.arkforge.fr").split(",")
    if o.strip()
]

# --- Trust Layer URL ---
TRUST_LAYER_BASE_URL = os.environ.get("TRUST_LAYER_BASE_URL", "https://trust.arkforge.tech")

# --- Redis ---
REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")

# --- RFC 3161 Timestamp Authority pool ---
# Tried in order — first success wins. All are free public endpoints.
# Primary: FreeTSA (community), Secondary: DigiCert (WebTrust), Tertiary: Sectigo (WebTrust).
# For eIDAS-qualified QTSP: set TSA_PRIMARY_URL + TSA_CA_FILE + TSA_CERT_FILE (on request).
TSA_SERVERS = [
    {"url": os.environ.get("TSA_PRIMARY_URL", "https://freetsa.org/tsr"),       "provider": os.environ.get("TSA_PRIMARY_PROVIDER", "freetsa.org")},
    {"url": os.environ.get("TSA_SECONDARY_URL", "http://timestamp.digicert.com"), "provider": "digicert.com"},
    {"url": os.environ.get("TSA_TERTIARY_URL", "http://timestamp.sectigo.com"),   "provider": "sectigo.com"},
]

_TSA_CERTS_DIR = BASE_DIR / "trust_layer" / "certs"
# TSA verification certificates — configurable for custom/QTSP endpoints.
# Defaults to bundled FreeTSA certs. Override with your TSA provider's certs.
TSA_CA_FILE   = Path(os.environ.get("TSA_CA_FILE",   str(_TSA_CERTS_DIR / "cacert.pem")))
TSA_CERT_FILE = Path(os.environ.get("TSA_CERT_FILE", str(_TSA_CERTS_DIR / "tsa.crt")))

# --- Sigstore Rekor transparency log ---
REKOR_URL = os.environ.get("REKOR_URL", "https://rekor.sigstore.dev")
REKOR_EC_KEY_PATH = Path(os.environ.get(
    "REKOR_EC_KEY_PATH",
    str(BASE_DIR / "trust_layer" / ".rekor_ec_key.pem"),
))
# Set REKOR_ENABLED=false in dev/test to skip Sigstore Rekor submissions (avoids polluting the public log).
REKOR_ENABLED = os.environ.get("REKOR_ENABLED", "true").lower() == "true"
# Set TRUST_LAYER_ENV=development in dev/test. Exposed in /v1/health → environment field.
TRUST_LAYER_ENV = os.environ.get("TRUST_LAYER_ENV", "production")

# --- Ed25519 Signing ---
SIGNING_KEY_PATH = Path(os.environ.get(
    "SIGNING_KEY_PATH",
    str(BASE_DIR / "trust_layer" / ".signing_key.pem"),
))

# Fail-fast: load signing key at import time.
# If absent, the server refuses to start — unsigned proofs are not allowed.
try:
    from .crypto import load_signing_key, get_public_key_b64url
    _SIGNING_KEY = load_signing_key(SIGNING_KEY_PATH)
    ARKFORGE_PUBLIC_KEY = get_public_key_b64url(_SIGNING_KEY)
except Exception as _e:
    raise RuntimeError(
        f"Signing key unavailable at {SIGNING_KEY_PATH}: {_e}. "
        "Generate it with: python3 -m trust_layer.crypto"
    ) from _e


def get_signing_key():
    """Return the Ed25519 private key, or None if not configured."""
    return _SIGNING_KEY
