"""Configuration — env vars, paths, constants."""

import logging as _logging
import os
import re
from pathlib import Path

# --- Paths ---
BASE_DIR = Path(__file__).parent.parent
# Surchargeable par env — prod ACA : TRUST_DATA_DIR=/mnt/share/data (Azure Files),
# TRUST_PROOFS_DIR=/mnt/share/proofs. Sans override : data/ et proofs/ du repo.
DATA_DIR = Path(os.environ.get("TRUST_DATA_DIR") or BASE_DIR / "data")
PROOFS_DIR = Path(os.environ.get("TRUST_PROOFS_DIR") or BASE_DIR / "proofs")
ATTESTATIONS_DIR = DATA_DIR / "attestations"
DATA_DIR.mkdir(parents=True, exist_ok=True)
PROOFS_DIR.mkdir(parents=True, exist_ok=True)
ATTESTATIONS_DIR.mkdir(exist_ok=True)

API_KEYS_FILE = DATA_DIR / "api_keys.json"
RATE_LIMITS_FILE = DATA_DIR / "rate_limits.json"
BACKGROUND_TASKS_LOG = DATA_DIR / "background_tasks_log.jsonl"
PROOF_ACCESS_LOG = DATA_DIR / "proof_access_log.jsonl"
CONVERSION_EVENTS_LOG = DATA_DIR / "conversion_events.jsonl"
FUNNEL_EVENTS_LOG = DATA_DIR / "funnel_events.jsonl"
MCP_REGISTRATION_LOG = Path(
    os.environ.get(
        "MCP_REGISTRATION_LOG",
        "/opt/claude-ceo/workspace/mcp-servers/eu-ai-act/data/registration_log.jsonl",
    )
)
MCP_SCAN_PINGS_LOG = DATA_DIR / "mcp_scan_pings.jsonl"
IDEMPOTENCY_DIR = DATA_DIR / "idempotency"
AGENTS_DIR = DATA_DIR / "agents"
SERVICES_DIR = DATA_DIR / "services"
MCP_BASELINES_DIR = DATA_DIR / "mcp_baselines"
ASSESSMENTS_DIR = DATA_DIR / "assessments"
PROOF_INDEX_FILE = DATA_DIR / "proof_index.jsonl"
for _d in (IDEMPOTENCY_DIR, AGENTS_DIR, SERVICES_DIR, MCP_BASELINES_DIR, ASSESSMENTS_DIR):
    _d.mkdir(exist_ok=True)

# Access posture, not secret values: when the vault is read, it decides these,
# empty included. With setdefault, a stray TRUST_LAYER_CHALLENGE_OPEN=true in the
# unit file or settings.env would open the corpus whatever the vault says.
_VAULT_AUTHORITATIVE = {"TRUST_LAYER_CHALLENGE_OPEN", "TRUST_LAYER_CHALLENGE_KEYS"}


def _apply_vault_values(mapping: dict, environ) -> None:
    for k, v in mapping.items():
        if k in _VAULT_AUTHORITATIVE:
            environ[k] = v
        elif v:
            environ.setdefault(k, v)


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
        from automation import vault as _vault_mod  # type: ignore[import]
        _vault = _vault_mod.vault
        # Under its own user, the service cannot read ubuntu's vault files:
        # systemd hands them over (LoadCredential=vault.json.enc, vault_key). The
        # master key goes through VAULT_MASTER_KEY, the vault's own interface, only
        # while the sections load: openssl subprocesses must not inherit it.
        _creds = Path(os.environ.get("CREDENTIALS_DIRECTORY", "/nonexistent"))
        _from_creds = (_creds / "vault.json.enc").exists() and (_creds / "vault_key").exists()
        if _from_creds:
            _vault_mod.VAULT_FILE = _creds / "vault.json.enc"
            os.environ["VAULT_MASTER_KEY"] = (_creds / "vault_key").read_text().strip()
        try:
            _stripe = _vault.get_section("stripe") or {}
            _smtp = _vault.get_section("smtp") or {}
            _proveit = _vault.get_section("proveit") or {}
        finally:
            if _from_creds:
                os.environ.pop("VAULT_MASTER_KEY", None)
        _mapping = {
            "STRIPE_LIVE_SECRET_KEY":        _stripe.get("live_secret_key", ""),
            "STRIPE_TEST_SECRET_KEY":         _stripe.get("test_secret_key", ""),
            "STRIPE_TL_WEBHOOK_SECRET":       _stripe.get("tl_webhook_secret", ""),
            "STRIPE_TL_WEBHOOK_SECRET_TEST":  _stripe.get("tl_webhook_secret_test", ""),
            "STRIPE_PRO_PRICE_ID":                 _stripe.get("pro_price_id", ""),
            "STRIPE_PRO_PRICE_ID_TEST":            _stripe.get("pro_price_id_test", ""),
            "STRIPE_ENTERPRISE_PRICE_ID":          _stripe.get("enterprise_price_id", ""),
            "STRIPE_ENTERPRISE_PRICE_ID_TEST":     _stripe.get("enterprise_price_id_test", ""),
            "STRIPE_PLATFORM_PRICE_ID":            _stripe.get("platform_price_id", ""),
            "STRIPE_PLATFORM_PRICE_ID_TEST":       _stripe.get("platform_price_id_test", ""),
            "STRIPE_SCANNER_PRO_PRICE_ID":         _stripe.get("scanner_pro_price_id", ""),
            "STRIPE_SCANNER_PRO_PRICE_ID_TEST":    _stripe.get("scanner_pro_price_id_test", ""),
            "STRIPE_PRO_PRODUCT_ID":               _stripe.get("pro_product_id", ""),
            "SMTP_HOST":                      _smtp.get("host", ""),
            "SMTP_LOGIN":                     _smtp.get("login", ""),
            "SMTP_USER":                      _smtp.get("user", ""),
            "SMTP_PASSWORD":                  _smtp.get("password", ""),
            # PROVE IT challenge corpus. Written by scripts/provision_challenge_secret.py;
            # never set by hand on a host — see that script's docstring.
            "TRUST_LAYER_CHALLENGE_SECRET":   _proveit.get("challenge_secret", ""),
            "TRUST_LAYER_CHALLENGE_HOSTS":    _proveit.get("challenge_hosts", ""),
            "TRUST_LAYER_CHALLENGE_OPEN":     _proveit.get("challenge_open", ""),
            "TRUST_LAYER_CHALLENGE_KEYS":     _proveit.get("challenge_keys", ""),
        }
        _apply_vault_values(_mapping, os.environ)
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
STRIPE_PLATFORM_PRICE_ID = os.environ.get("STRIPE_PLATFORM_PRICE_ID", "")           # live
STRIPE_PLATFORM_PRICE_ID_TEST = os.environ.get("STRIPE_PLATFORM_PRICE_ID_TEST", "")  # test
STRIPE_SCANNER_PRO_PRICE_ID = os.environ.get("STRIPE_SCANNER_PRO_PRICE_ID", "")           # live
STRIPE_SCANNER_PRO_PRICE_ID_TEST = os.environ.get("STRIPE_SCANNER_PRO_PRICE_ID_TEST", "")  # test
STRIPE_PRO_PRODUCT_ID = os.environ.get("STRIPE_PRO_PRODUCT_ID", "")

# --- SMTP ---
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.resend.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_LOGIN = os.environ.get("SMTP_LOGIN", "resend")           # SMTP auth login (e.g. "resend" for Resend.com)
SMTP_USER = os.environ.get("SMTP_USER", os.environ.get("IMAP_USER", "noreply@arkforge.tech"))  # From address
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
PLATFORM_MONTHLY_LIMIT = 500_000      # Platform €599/month: 500 000 proofs/month

# Daily caps per plan.
# Free/Pro/Enterprise: set to monthly quota — the monthly counter fires first,
# the daily cap never adds a constraint beyond what is already sold.
# Test keys: hard 100/day guard (no monthly quota, prevents infinite runaway loops).
DAILY_LIMITS_PER_PLAN = {
    "free":       FREE_TIER_MONTHLY_LIMIT,   # 500  — daily cap = monthly quota
    "trial":      PRO_MONTHLY_LIMIT,          # 5 000 — same as pro (card-free trial)
    "pro":        PRO_MONTHLY_LIMIT,          # 5 000 — daily cap = monthly quota
    "enterprise": ENTERPRISE_MONTHLY_LIMIT,   # 50 000 — daily cap = monthly quota
    "platform":   PLATFORM_MONTHLY_LIMIT,     # 500 000 — daily cap = monthly quota
    "test":       100,                        # hard daily guard only
    "internal":   10_000,                     # CEO internal key — no monthly quota, 10k/day hard cap
}
# Overage rates (credits billed when monthly quota exceeded)
PRO_OVERAGE_PRICE = 0.01              # EUR per proof over 5 000
ENTERPRISE_OVERAGE_PRICE = 0.005      # EUR per proof over 50 000
PLATFORM_OVERAGE_PRICE = 0.002        # EUR per proof over 500 000
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
    "platform": PLATFORM_OVERAGE_PRICE,
}

# Monthly quotas per plan (None = unlimited daily cap only)
_PRO_MONTHLY_LIMIT = 5000
_ENTERPRISE_MONTHLY_LIMIT = 50000
_PLATFORM_MONTHLY_LIMIT = 500000

# --- Internal Secret (forwarded to upstream services for service-to-service auth) ---
INTERNAL_SECRET = os.environ.get("TRUST_LAYER_INTERNAL_SECRET", "")

# Hostnames allowed to receive INTERNAL_SECRET when proxied through /v1/proxy.
# Empty by default: no external forward of this header unless explicitly listed.
TRUSTED_INTERNAL_HOSTS = {
    h.strip().lower()
    for h in os.environ.get("TRUST_LAYER_TRUSTED_INTERNAL_HOSTS", "").split(",")
    if h.strip()
}

# --- Challenge Secret (PROVE IT corpus) ---
# Deliberately NOT the same secret as INTERNAL_SECRET: the corpus is exposed to
# challenge participants, while INTERNAL_SECRET opens the deployment smoke test.
# Sharing one secret would make its rotation an event for both, and would extend
# to a participant-facing service the secret whose leak was the v1.7.0 flaw.
CHALLENGE_SECRET = os.environ.get("TRUST_LAYER_CHALLENGE_SECRET", "")

# Hostnames allowed to receive CHALLENGE_SECRET when proxied through /v1/proxy.
CHALLENGE_HOSTS = {
    h.strip().lower()
    for h in os.environ.get("TRUST_LAYER_CHALLENGE_HOSTS", "").split(",")
    if h.strip()
}

# Sellers whose proofs POST /v1/proofs serves in batch: the PROVE IT corpus and the
# season service (freeze proofs). Not CHALLENGE_HOSTS: that list decides where the
# challenge secret is forwarded, and the season service never receives it.
PROVEIT_PROOF_SELLERS = frozenset({"corpus.arkforge.tech", "proveit.arkforge.tech"})

_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


def parse_challenge_open(raw: str) -> bool:
    """Season state. Only an explicit "true" opens it: an unreadable vault
    yields "", and must keep the corpus closed rather than open it to everyone."""
    return raw.strip().lower() == "true"


def parse_challenge_keys(raw: str) -> tuple:
    """Fingerprints (sha256 of the API key) allowed to reach the corpus before
    the season opens. Returns (fingerprints, rejected entry descriptions).

    Rejected entries are described by position, never by value: a raw API key
    pasted by mistake must not end up in a log line.
    """
    keys, rejected = set(), []
    for i, entry in enumerate((e.strip().lower() for e in raw.split(",")), start=1):
        if not entry:
            continue
        if _FINGERPRINT_RE.match(entry):
            keys.add(entry)
        else:
            rejected.append(f"entry #{i} of challenge_keys is not a sha256 fingerprint, ignored")
    return keys, rejected


# Before the season opens, the corpus is reserved to our own keys. Anyone gets a
# key from /v1/keys/free-signup, so an allowlist on the host alone would expose
# the private corpus. Keys are named by fingerprint, not by ref: a free key's ref
# is free_signup_<email>, which anyone can recreate once the original is inactive.
# Written by scripts/provision_challenge_secret.py (--allow-key-ref, --open).
CHALLENGE_OPEN = parse_challenge_open(os.environ.get("TRUST_LAYER_CHALLENGE_OPEN", ""))
CHALLENGE_KEYS, _challenge_keys_rejected = parse_challenge_keys(
    os.environ.get("TRUST_LAYER_CHALLENGE_KEYS", "")
)


def challenge_config_problems(secret: str, hosts: set, *, open_: bool, keys: set) -> list:
    """Incoherences between the challenge secret and its allowlist.

    Both come from the vault, and the vault loader swallows every exception. If
    the vault is unreachable, the secret silently becomes "" while the allowlist
    may still be set from settings.env: the proxy then forwards nothing, the
    corpus answers 403 to every participant, and the outage reads as a corpus
    failure rather than a configuration one. This turns that into a message.

    Pure function so it can be tested without importing a vault.
    """
    problems = []
    if hosts and not secret:
        problems.append(
            "challenge hosts are configured but TRUST_LAYER_CHALLENGE_SECRET is empty: "
            "the corpus will reject every participant. Check the vault section 'proveit'."
        )
    if secret and not hosts:
        problems.append(
            "TRUST_LAYER_CHALLENGE_SECRET is set but no challenge host is allowlisted: "
            "the secret is inert and the corpus is unreachable through the proxy."
        )
    if secret and hosts and not open_ and not keys:
        problems.append(
            "the challenge season is closed and challenge_keys is empty: no key, ours "
            "included, can reach the corpus. Check the vault section 'proveit'."
        )
    return problems


for _problem in _challenge_keys_rejected + challenge_config_problems(
        CHALLENGE_SECRET, CHALLENGE_HOSTS, open_=CHALLENGE_OPEN, keys=CHALLENGE_KEYS):
    _logging.getLogger("trust_layer.config").error("Challenge config: %s", _problem)


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

# --- OATR (Open Agent Trust Registry) ---
OATR_MANIFEST_URL = os.environ.get(
    "OATR_MANIFEST_URL",
    "https://raw.githubusercontent.com/FransDevelopment/open-agent-trust-registry/main/registry/manifest.json",
)

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

# Which CA material verifies which issuer. The pool fails over across three TSAs and a
# token is only verifiable against its own issuer's root, so the mapping has to exist
# somewhere — shipping one bundle and hoping is how a proof becomes unverifiable.
#   bundled    : self-signed root, not in any OS trust store, shipped in trust_layer/certs
#   system CA  : public WebTrust CA already trusted by the OS; the token carries its chain
TSA_BUNDLED_PROVIDERS = {os.environ.get("TSA_PRIMARY_PROVIDER", "freetsa.org")}
TSA_SYSTEM_CA_PROVIDERS = {"digicert.com", "sectigo.com"}

_SYSTEM_CA_CANDIDATES = [
    "/etc/ssl/certs/ca-certificates.crt",   # Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",     # RHEL/Fedora
    "/etc/ssl/cert.pem",                    # Alpine/macOS
]


def _find_system_ca_file():
    override = os.environ.get("TSA_SYSTEM_CA_FILE")
    if override:
        return Path(override)
    for candidate in _SYSTEM_CA_CANDIDATES:
        if Path(candidate).exists():
            return Path(candidate)
    return None


TSA_SYSTEM_CA_FILE = _find_system_ca_file()

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

# Published key history (kid, public key, node, validity), identical on every node.
PUBLISHED_KEYS_FILE = BASE_DIR / "trust_layer" / "published_keys.json"

# Signer mode: TL_SIGNER_SOCKET names the tl-signer socket. The private keys
# then live in tl-signer only; nothing here reads or creates a key file. Unset, the
# legacy .pem next to the package is used (default until the switch).
SIGNER_SOCKET = os.environ.get("TL_SIGNER_SOCKET", "")

# Fail-fast: the server refuses to start without a way to sign (unsigned proofs are
# not allowed) and, in signer mode, with a key missing from the published history.
if SIGNER_SOCKET:
    from .signing import SocketSigner, check_registered
    _SIGNING_KEY = None
    _SIGNER = SocketSigner(SIGNER_SOCKET)
    check_registered(_SIGNER, PUBLISHED_KEYS_FILE)
    ARKFORGE_PUBLIC_KEY = _SIGNER.public
else:
    _SIGNER = None
    try:
        from .crypto import load_signing_key, get_public_key_b64url
        _SIGNING_KEY = load_signing_key(SIGNING_KEY_PATH)
        ARKFORGE_PUBLIC_KEY = get_public_key_b64url(_SIGNING_KEY)
    except Exception as _e:
        raise RuntimeError(
            f"Signing key unavailable at {SIGNING_KEY_PATH}: {_e}. "
            "Generate it with: python3 -m trust_layer.crypto"
        ) from _e


def get_signer():
    """The node's signer (trust_layer.signing), or None if not configured."""
    if _SIGNER is not None:
        return _SIGNER
    if _SIGNING_KEY is None:
        return None
    from .signing import LocalSigner
    return LocalSigner(_SIGNING_KEY)
