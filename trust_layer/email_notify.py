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

  curl -X POST https://trust.arkforge.fr/v1/proxy \\
    -H "Authorization: Bearer {api_key}" \\
    -H "Content-Type: application/json" \\
    -d '{{"target": "https://any-api.com/endpoint",
         "amount": 0.50,
         "payload": {{"key": "value"}}}}'

How it works:
  1. You send a request with a target URL, amount, and payload
  2. ArkForge charges your card, forwards the payload to the target
  3. You get back the response + a cryptographic proof

Verify any proof: https://trust.arkforge.fr/v1/proof/<proof_id>

Docs: https://trust.arkforge.fr
Support: contact@arkforge.fr
"""
    try:
        _send_email(email, subject, body)
    except Exception as e:
        logger.warning("Welcome email failed: %s", e)


def send_proof_email(email: str, proof_id: str, proof_data: dict):
    """Send transaction proof email after a proxy call."""
    payment = proof_data.get("payment", {})
    hashes = proof_data.get("hashes", {})
    ts = proof_data.get("timestamp", "")
    verification_url = proof_data.get("verification_url", "")

    parties = proof_data.get("parties", {})
    buyer_fp = parties.get("buyer_fingerprint", "N/A")
    seller_domain = parties.get("seller", "N/A")

    subject = f"[PROOF] ArkForge Transaction — {proof_id}"
    body = f"""ARKFORGE TRUST LAYER — PROOF OF TRANSACTION
{'=' * 50}

Timestamp:  {ts}
Proof ID:   {proof_id}

PARTIES
  Buyer:          {buyer_fp[:16]}...
  Seller:         {seller_domain}

PAYMENT
  Provider:       {payment.get('provider', 'stripe')}
  Transaction:    {payment.get('transaction_id', 'N/A')}
  Amount:         {payment.get('amount', 'N/A')} {payment.get('currency', 'EUR').upper()}
  Status:         {payment.get('status', 'N/A')}
  Receipt:        {payment.get('receipt_url', 'N/A')}

CRYPTOGRAPHIC PROOF
  Request hash:   {hashes.get('request', 'N/A')}
  Response hash:  {hashes.get('response', 'N/A')}
  Chain hash:     {hashes.get('chain', 'N/A')}

VERIFY
  {verification_url}

{'=' * 50}
This is an automated proof of an agent-to-agent transaction.
Anyone can verify this proof independently at the URL above.
Service: ArkForge Trust Layer (https://trust.arkforge.fr)
"""
    try:
        _send_email(email, subject, body)
    except Exception as e:
        logger.warning("Proof email failed: %s", e)
