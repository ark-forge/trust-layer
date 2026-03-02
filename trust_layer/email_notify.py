"""SMTP email notifications — welcome + proof emails."""

import logging
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate, make_msgid

from .config import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD

logger = logging.getLogger("trust_layer.email")


def _send_email(to: str, subject: str, body: str):
    """Send a plain-text email via SMTP SSL. Best effort."""
    if not to or not SMTP_PASSWORD:
        logger.warning("Email skipped: %s", "no recipient" if not to else "SMTP not configured")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"ArkForge <{SMTP_USER}>"
    msg["To"] = to
    msg["Reply-To"] = SMTP_USER
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="arkforge.fr")
    msg["List-Unsubscribe"] = f"<mailto:{SMTP_USER}?subject=unsubscribe>"
    msg.attach(MIMEText(body, "plain", "utf-8"))

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=15) as server:
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, to, msg.as_string())

    logger.info("Email sent to %s: %s", to, subject)


def send_welcome_email(email: str, api_key: str):
    """Send welcome email with API key after card setup."""
    subject = "Your ArkForge Trust Layer API Key"
    body = f"""Welcome to ArkForge Trust Layer!

Your API key: {api_key}

Quick start — pay any API with one curl:

  curl -X POST https://arkforge.fr/trust/v1/proxy \\
    -H "Authorization: Bearer {api_key}" \\
    -H "Content-Type: application/json" \\
    -d '{{"target": "https://any-api.com/endpoint",
         "amount": 0.50,
         "payload": {{"key": "value"}}}}'

How it works:
  1. You send a request with a target URL, amount, and payload
  2. ArkForge charges your card, forwards the payload to the target
  3. You get back the response + a cryptographic proof

Verify any proof: https://arkforge.fr/trust/v1/proof/<proof_id>

Docs: https://arkforge.fr/trust
Support: contact@arkforge.fr
"""
    try:
        _send_email(email, subject, body)
    except Exception as e:
        logger.warning("Welcome email failed: %s", e)


def send_quota_alert_email(email: str, api_key: str, used: int, limit: int, period: str):
    """Send a quota warning email when a key reaches 80% of its limit.

    period: 'monthly' (free tier) or 'daily' (pro tier)
    """
    remaining = limit - used
    pct = round(used / limit * 100)
    if period == "monthly":
        period_label = "monthly"
        upgrade_hint = (
            "Upgrade to Pro for 100 proofs/day and no monthly cap:\n"
            "  https://arkforge.fr/en/pricing.html"
        )
    else:
        period_label = "daily"
        upgrade_hint = (
            "Buy more credits to keep your agent running:\n"
            "  curl -X POST https://arkforge.fr/trust/v1/credits/buy \\\n"
            f"    -H 'Authorization: Bearer {api_key}' \\\n"
            "    -H 'Content-Type: application/json' \\\n"
            "    -d '{\"amount\": 10}'"
        )

    subject = f"[ArkForge] Quota alert — {pct}% of {period_label} limit used"
    body = f"""ArkForge Trust Layer — Quota Warning
{'=' * 50}

Your API key has used {used}/{limit} proofs ({pct}%) of your {period_label} quota.
{remaining} proof(s) remaining.

{upgrade_hint}

Check your usage anytime:
  curl https://arkforge.fr/trust/v1/usage \\
    -H "Authorization: Bearer {api_key}"

{'=' * 50}
ArkForge Trust Layer — https://arkforge.fr/trust
"""
    try:
        _send_email(email, subject, body)
    except Exception as e:
        logger.warning("Quota alert email failed: %s", e)


def send_proof_email(email: str, proof_id: str, proof_data: dict):
    """Send transaction proof email after a proxy call."""
    cert_fee = proof_data.get("certification_fee", {})
    hashes = proof_data.get("hashes", {})
    ts = proof_data.get("timestamp", "")
    verification_url = proof_data.get("verification_url", "")

    parties = proof_data.get("parties", {})
    buyer_fp = parties.get("buyer_fingerprint", "N/A")
    seller_domain = parties.get("seller", "N/A")

    provider_payment = proof_data.get("provider_payment") or {}
    pp_section = ""
    if provider_payment:
        pp_fields = provider_payment.get("parsed_fields") or {}
        pp_amount = pp_fields.get("amount", "N/A")
        pp_currency = (pp_fields.get("currency") or "").upper() or "EUR"
        pp_status = pp_fields.get("status", "N/A")
        pp_receipt = provider_payment.get("receipt_url", "N/A")
        pp_verify = provider_payment.get("verification_status", "N/A")
        pp_section = f"""
PROVIDER PAYMENT (direct, not via ArkForge)
  Amount:         {pp_amount} {pp_currency}
  Status:         {pp_status}
  Receipt:        {pp_receipt}
  Verified:       {pp_verify}
"""

    receipt_line = ""
    if cert_fee.get("receipt_url"):
        receipt_line = f"\n  Receipt:        {cert_fee['receipt_url']}"

    subject = f"[PROOF] ArkForge Transaction — {proof_id}"
    body = f"""ARKFORGE TRUST LAYER — PROOF OF TRANSACTION
{'=' * 50}

Timestamp:  {ts}
Proof ID:   {proof_id}

PARTIES
  Buyer:          {buyer_fp[:16]}...
  Seller:         {seller_domain}

CERTIFICATION FEE (ArkForge proof — 0.10 EUR)
  Method:         {cert_fee.get('method', 'N/A')}
  Transaction:    {cert_fee.get('transaction_id', 'N/A')}
  Amount:         {cert_fee.get('amount', 'N/A')} {(cert_fee.get('currency') or 'EUR').upper()}
  Status:         {cert_fee.get('status', 'N/A')}{receipt_line}
{pp_section}
CRYPTOGRAPHIC PROOF
  Request hash:   {hashes.get('request', 'N/A')}
  Response hash:  {hashes.get('response', 'N/A')}
  Chain hash:     {hashes.get('chain', 'N/A')}

VERIFY
  {verification_url}

{'=' * 50}
This is an automated proof of an agent-to-agent transaction.
Anyone can verify this proof independently at the URL above.
Service: ArkForge Trust Layer (https://arkforge.fr/trust)
"""
    try:
        _send_email(email, subject, body)
    except Exception as e:
        logger.warning("Proof email failed: %s", e)


def send_low_credits_email(email: str, api_key: str, balance: float, proofs_remaining: int):
    """Send a warning email when the credit balance is running low."""
    subject = "[ArkForge] Low credits — action required"
    body = f"""ArkForge Trust Layer — Low Credits Warning
{'=' * 50}

Your credit balance is running low.

  Current balance:   {balance:.2f} EUR
  Proofs remaining:  ~{proofs_remaining}

Your agent will stop working when credits reach zero.

Recharge now (no browser required):

  curl -X POST https://arkforge.fr/trust/v1/credits/buy \\
    -H "X-Api-Key: {api_key}" \\
    -H "Content-Type: application/json" \\
    -d '{{"amount": 10}}'

Or check your balance:

  curl https://arkforge.fr/trust/v1/usage \\
    -H "X-Api-Key: {api_key}"

{'=' * 50}
ArkForge Trust Layer — https://arkforge.fr/trust
"""
    try:
        _send_email(email, subject, body)
        logger.info("Low credits alert sent to %s (balance=%.2f)", email, balance)
    except Exception as e:
        logger.warning("Low credits email failed: %s", e)


def send_credits_exhausted_email(email: str, api_key: str):
    """Send an alert email when credits are fully exhausted."""
    subject = "[ArkForge] Credits exhausted — agent stopped"
    body = f"""ArkForge Trust Layer — Credits Exhausted
{'=' * 50}

Your credit balance has reached zero.

Your agent's API calls are currently being rejected (HTTP 402).

Recharge now to resume operations:

  curl -X POST https://arkforge.fr/trust/v1/credits/buy \\
    -H "X-Api-Key: {api_key}" \\
    -H "Content-Type: application/json" \\
    -d '{{"amount": 10}}'

This will charge the card saved during your initial setup.
10 EUR = 100 proofs.

{'=' * 50}
ArkForge Trust Layer — https://arkforge.fr/trust
"""
    try:
        _send_email(email, subject, body)
        logger.info("Credits exhausted alert sent to %s", email)
    except Exception as e:
        logger.warning("Credits exhausted email failed: %s", e)
