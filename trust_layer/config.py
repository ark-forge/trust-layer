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
IDEMPOTENCY_DIR = DATA_DIR / "idempotency"
AGENTS_DIR = DATA_DIR / "agents"
SERVICES_DIR = DATA_DIR / "services"
for _d in (IDEMPOTENCY_DIR, AGENTS_DIR, SERVICES_DIR):
    _d.mkdir(exist_ok=True)

# --- Load settings.env ---
SETTINGS_ENV = Path(os.environ.get(
    "SETTINGS_ENV_PATH",
    str(Path(__file__).resolve().parent.parent.parent / "mcp-servers" / "eu-ai-act" / "config" / "settings.env"),
))
if SETTINGS_ENV.exists():
    for _line in SETTINGS_ENV.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

# --- Stripe ---
STRIPE_LIVE_KEY = os.environ.get("STRIPE_LIVE_SECRET_KEY", "")
STRIPE_TEST_KEY = os.environ.get("STRIPE_TEST_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET_LIVE = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_WEBHOOK_SECRET_TEST = os.environ.get("STRIPE_WEBHOOK_SECRET_TEST", "")

# --- SMTP ---
SMTP_HOST = os.environ.get("SMTP_HOST", "ssl0.ovh.net")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("IMAP_USER", "contact@arkforge.fr")
SMTP_PASSWORD = os.environ.get("IMAP_PASSWORD", "")

# --- Proxy limits ---
SUPPORTED_CURRENCIES = ["eur", "usd", "gbp"]
MIN_AMOUNT = 0.50
MAX_AMOUNT = 50.00
PROXY_TIMEOUT_SECONDS = 120
MAX_RESPONSE_STORE_BYTES = 1_000_000  # 1 MB
RATE_LIMIT_PER_KEY_PER_DAY = 100
IDEMPOTENCY_TTL_HOURS = 24

# --- Trust Layer URL ---
TRUST_LAYER_BASE_URL = os.environ.get("TRUST_LAYER_BASE_URL", "https://trust.arkforge.fr")
