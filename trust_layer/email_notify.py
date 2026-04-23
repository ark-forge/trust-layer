"""SMTP email notifications — welcome + proof emails."""

import logging
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate, make_msgid

from .config import SMTP_HOST, SMTP_PORT, SMTP_LOGIN, SMTP_USER, SMTP_CONTACT, SMTP_PASSWORD

logger = logging.getLogger("trust_layer.email")


_TEST_TLDS = {"invalid", "local", "test", "example", "localhost"}
# RFC 2606 reserved domains + universally-used test placeholders
_TEST_DOMAINS = {
    "example.com", "example.org", "example.net", "example.io",
    "test.com", "test.org", "test.net",
    "smoke.invalid", "smoke.local",
}
# Local-part prefixes that are never real recipients
_TEST_LOCAL_PREFIXES = ("smoke_", "smoke-", "noreply", "no-reply", "mailer-daemon")


def _is_test_email(to: str) -> tuple[bool, str]:
    """Return (True, reason) if the address is a test/reserved/fake address."""
    to = to.strip().lower()
    if "@" not in to:
        return True, "invalid_format"
    local, domain = to.rsplit("@", 1)
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    if tld in _TEST_TLDS:
        return True, f"reserved_tld:.{tld}"
    if domain in _TEST_DOMAINS:
        return True, f"reserved_domain:{domain}"
    if any(local.startswith(p) for p in _TEST_LOCAL_PREFIXES):
        return True, f"test_local_prefix:{local}"
    return False, ""


def _send_email(to: str, subject: str, body: str):
    """Send a plain-text email via SMTP SSL. Best effort."""
    if not to or not SMTP_PASSWORD:
        logger.warning("Email skipped: %s", "no recipient" if not to else "SMTP not configured")
        return

    # Block test/reserved/fake addresses — never deliver, never consume quota
    _blocked, _reason = _is_test_email(to)
    if _blocked:
        logger.warning("Email skipped (%s): %s", _reason, to)
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"ArkForge <{SMTP_USER}>"
    msg["To"] = to
    msg["Reply-To"] = SMTP_CONTACT
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="arkforge.fr")
    msg["List-Unsubscribe"] = f"<mailto:{SMTP_CONTACT}?subject=unsubscribe>"
    msg.attach(MIMEText(body, "plain", "utf-8"))

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=15) as server:
        server.login(SMTP_LOGIN, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, to, msg.as_string())

    logger.info("Email sent to %s: %s", to, subject)


def send_welcome_email(email: str, api_key: str):
    """Send welcome email with API key after free signup."""
    subject = "Your ArkForge Trust Layer API Key"
    body = f"""Welcome to ArkForge Trust Layer!

Your API key: {api_key}

Create your first proof right now (copy-paste this):

  curl -X POST https://trust.arkforge.tech/v1/proxy \\
    -H "X-API-Key: {api_key}" \\
    -H "Content-Type: application/json" \\
    -d '{{"target": "https://httpbin.org/post",
         "payload": {{"test": "my first proof"}}}}'

You'll get back the API response + a cryptographic proof with:
  - Ed25519 digital signature
  - SHA-256 hash chain
  - RFC 3161 timestamp

Verify any proof: https://trust.arkforge.tech/v1/proof/<proof_id>

Your free plan: 500 proofs/month, no credit card needed.
Check usage anytime:

  curl https://trust.arkforge.tech/v1/usage \\
    -H "X-API-Key: {api_key}"

---

Need unlimited scans or 5,000+ proofs/month?

Upgrade to Pro — 14-day free trial, no charge until day 15:
  https://arkforge.tech/en/pro-signup.html

Pro includes: unlimited compliance scans, CI/CD API, compliance
roadmap generation, and Trust Layer audit trail.
29 EUR/month, cancel anytime.

---

Docs: https://arkforge.tech/trust
Support: contact@arkforge.fr
"""
    try:
        _send_email(email, subject, body)
    except Exception as e:
        logger.warning("Welcome email failed: %s", e)


def send_welcome_email_pro(email: str, api_key: str, plan_name: str = "pro"):
    """Send welcome email with API key after Pro/Enterprise subscription (with trial mention)."""
    quotas = {
        "pro": "5,000 proofs/month",
        "enterprise": "50,000 proofs/month",
    }
    quota_label = quotas.get(plan_name, "5,000 proofs/month")
    subject = "Your ArkForge Trust Layer Pro API Key"
    body = f"""Welcome to ArkForge Trust Layer — {plan_name.capitalize()} plan!

Your API key: {api_key}

Your 14-day free trial is active. Your card won't be charged until day 15.
Cancel anytime during the trial and you won't be billed.

Create your first proof right now (copy-paste this):

  curl -X POST https://trust.arkforge.tech/v1/proxy \\
    -H "X-Api-Key: {api_key}" \\
    -H "Content-Type: application/json" \\
    -d '{{"target": "https://httpbin.org/post",
         "payload": {{"test": "my first proof"}}}}'

You'll get back the API response + a cryptographic proof with:
  - Ed25519 digital signature
  - SHA-256 hash chain
  - RFC 3161 timestamp

Verify any proof: https://trust.arkforge.tech/v1/proof/<proof_id>

Your plan: {quota_label}
Check usage anytime:

  curl https://trust.arkforge.tech/v1/usage \\
    -H "X-Api-Key: {api_key}"

Manage your subscription or cancel anytime:

  curl -X POST https://trust.arkforge.tech/v1/keys/portal \\
    -H "X-Api-Key: {api_key}"

Docs: https://arkforge.tech/trust
Support: contact@arkforge.fr
"""
    try:
        _send_email(email, subject, body)
    except Exception as e:
        logger.warning("Welcome pro email failed: %s", e)


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
            "  https://arkforge.tech/en/pricing.html?utm_source=email&utm_medium=notification"
        )
    else:
        period_label = "daily"
        upgrade_hint = (
            "Buy more credits to keep your agent running:\n"
            "  curl -X POST https://trust.arkforge.tech/v1/credits/buy \\\n"
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
  curl https://trust.arkforge.tech/v1/usage \\
    -H "Authorization: Bearer {api_key}"

{'=' * 50}
ArkForge Trust Layer — https://arkforge.tech/trust
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

    transparency_log = proof_data.get("transparency_log") or {}
    rekor_verify_url = transparency_log.get("verify_url", "") if transparency_log.get("status") == "verified" else ""

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
  Proof (ArkForge):    {verification_url}
{"  Independent (Rekor): " + rekor_verify_url if rekor_verify_url else ""}

{'=' * 50}
This is an automated proof of an agent-to-agent transaction.
Verify independently on Sigstore Rekor using the URL above — no ArkForge account required.
Service: ArkForge Trust Layer (https://arkforge.tech/trust)
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

  curl -X POST https://trust.arkforge.tech/v1/credits/buy \\
    -H "X-Api-Key: {api_key}" \\
    -H "Content-Type: application/json" \\
    -d '{{"amount": 10}}'

Or check your balance:

  curl https://trust.arkforge.tech/v1/usage \\
    -H "X-Api-Key: {api_key}"

{'=' * 50}
ArkForge Trust Layer — https://arkforge.tech/trust
"""
    try:
        _send_email(email, subject, body)
        logger.info("Low credits alert sent to %s (balance=%.2f)", email, balance)
    except Exception as e:
        logger.warning("Low credits email failed: %s", e)


def send_overage_first_email(email: str, api_key: str, plan: str, spent: float, cap: float):
    """Send email on first overage proof of the month."""
    from .config import OVERAGE_PRICES
    rate = OVERAGE_PRICES.get(plan, 0.01)
    subject = "[ArkForge] Overage billing active — monthly quota exceeded"
    body = f"""ArkForge Trust Layer — Overage Billing Active
{'=' * 50}

Your monthly quota has been reached. Overage billing is now active.

Your agent will continue to work, but each proof beyond the quota
is billed from your prepaid credits at the overage rate.

  Plan:            {plan}
  Overage rate:    {rate:.3f} EUR / proof
  Spent (overage): {spent:.4f} EUR
  Monthly cap:     {cap:.2f} EUR

Check your current usage:
  curl https://trust.arkforge.tech/v1/usage \\
    -H "X-Api-Key: {api_key}"

To disable overage billing:
  curl -X POST https://trust.arkforge.tech/v1/keys/overage \\
    -H "X-Api-Key: {api_key}" \\
    -H "Content-Type: application/json" \\
    -d '{{"enabled": false, "cap_eur": {cap:.2f}}}'

When you reach your cap ({cap:.2f} EUR), requests will be blocked until
you increase the cap or wait for the next monthly reset.

{'=' * 50}
ArkForge Trust Layer — https://arkforge.tech/trust
"""
    try:
        _send_email(email, subject, body)
    except Exception as e:
        logger.warning("Overage first email failed: %s", e)


def send_overage_80pct_email(email: str, api_key: str, plan: str, spent: float, cap: float):
    """Send email when 80% of overage cap is consumed."""
    remaining = round(cap - spent, 4)
    subject = "[ArkForge] Overage alert — 80% of monthly cap used"
    body = f"""ArkForge Trust Layer — Overage Cap Warning
{'=' * 50}

You have used 80% of your monthly overage cap.

  Spent:           {spent:.4f} EUR / {cap:.2f} EUR cap
  Remaining:       {remaining:.4f} EUR

Your agent may stop working soon when the cap is reached.

Options:
  1. Increase your monthly cap:
     curl -X POST https://trust.arkforge.tech/v1/keys/overage \\
       -H "X-Api-Key: {api_key}" \\
       -H "Content-Type: application/json" \\
       -d '{{"enabled": true, "cap_eur": {min(cap * 2, 100):.2f}}}'

  2. Buy more prepaid credits:
     curl -X POST https://trust.arkforge.tech/v1/credits/buy \\
       -H "X-Api-Key: {api_key}" \\
       -H "Content-Type: application/json" \\
       -d '{{"amount": 10}}'

  3. Disable overage (requests will be rejected at quota):
     curl -X POST https://trust.arkforge.tech/v1/keys/overage \\
       -H "X-Api-Key: {api_key}" \\
       -H "Content-Type: application/json" \\
       -d '{{"enabled": false, "cap_eur": {cap:.2f}}}'

{'=' * 50}
ArkForge Trust Layer — https://arkforge.tech/trust
"""
    try:
        _send_email(email, subject, body)
    except Exception as e:
        logger.warning("Overage 80pct email failed: %s", e)


def send_overage_cap_email(email: str, api_key: str, plan: str, spent: float, cap: float):
    """Send email when overage cap is reached and requests are being blocked."""
    subject = "[ArkForge] Overage cap reached — requests blocked"
    body = f"""ArkForge Trust Layer — Overage Cap Reached
{'=' * 50}

Your monthly overage cap of {cap:.2f} EUR has been reached.

All requests beyond the monthly quota are now blocked (HTTP 429)
until you take one of the following actions:

  1. Increase your monthly cap (max 100 EUR):
     curl -X POST https://trust.arkforge.tech/v1/keys/overage \\
       -H "X-Api-Key: {api_key}" \\
       -H "Content-Type: application/json" \\
       -d '{{"enabled": true, "cap_eur": {min(cap * 2, 100):.2f}}}'

  2. Buy more prepaid credits:
     curl -X POST https://trust.arkforge.tech/v1/credits/buy \\
       -H "X-Api-Key: {api_key}" \\
       -H "Content-Type: application/json" \\
       -d '{{"amount": 10}}'

  3. Wait for the next monthly reset (first day of next month).

  Spent this month: {spent:.4f} EUR
  Cap:              {cap:.2f} EUR

{'=' * 50}
ArkForge Trust Layer — https://arkforge.tech/trust
"""
    try:
        _send_email(email, subject, body)
    except Exception as e:
        logger.warning("Overage cap email failed: %s", e)


def send_trial_ended_email(email: str, api_key: str):
    """Send email when trial ends without conversion (subscription deleted during/after trial)."""
    subject = "Your ArkForge Trust Layer trial has ended"
    body = f"""ArkForge Trust Layer — Trial Ended

Your 14-day free trial has ended. No charges were made to your card.

Your API key has been deactivated:
  {api_key}

To continue using ArkForge Trust Layer, resubscribe anytime:
  https://arkforge.tech/en/pricing.html?utm_source=email&utm_medium=notification

Your proofs remain accessible for 30 days after trial end:
  https://trust.arkforge.tech/v1/proof/<proof_id>

{'=' * 50}
ArkForge Trust Layer — https://arkforge.tech/trust
Support: contact@arkforge.fr
"""
    try:
        _send_email(email, subject, body)
    except Exception as e:
        logger.warning("Trial ended email failed: %s", e)


def send_subscription_suspended_email(email: str, api_key: str):
    """Send email when subscription is suspended due to payment failure."""
    subject = "[ArkForge] API key suspended — payment issue"
    body = f"""ArkForge Trust Layer — Subscription Suspended

Your API key has been suspended due to a payment issue.

  API key: {api_key}

Your agent's API calls are currently being rejected (HTTP 403).

Update your payment method to reactivate your key:

  curl -X POST https://trust.arkforge.tech/v1/keys/portal \\
    -H "X-Api-Key: {api_key}"

This will return a Stripe billing portal URL where you can update
your card and retry the payment. Your key will be reactivated
automatically once payment succeeds.

{'=' * 50}
ArkForge Trust Layer — https://arkforge.tech/trust
Support: contact@arkforge.fr
"""
    try:
        _send_email(email, subject, body)
    except Exception as e:
        logger.warning("Subscription suspended email failed: %s", e)


def send_subscription_reactivated_email(email: str, api_key: str):
    """Send email when subscription is reactivated after a payment recovery."""
    subject = "[ArkForge] API key reactivated — payment received"
    body = f"""ArkForge Trust Layer — Subscription Reactivated

Good news: your payment was received and your API key is active again.

  API key: {api_key}

Your agent can resume operations immediately.

Check your usage:
  curl https://trust.arkforge.tech/v1/usage \\
    -H "X-Api-Key: {api_key}"

{'=' * 50}
ArkForge Trust Layer — https://arkforge.tech/trust
Support: contact@arkforge.fr
"""
    try:
        _send_email(email, subject, body)
    except Exception as e:
        logger.warning("Subscription reactivated email failed: %s", e)


def send_demo_request_email(
    first_name: str,
    last_name: str,
    email: str,
    company: str,
    use_case: str = "",
    message: str = "",
):
    """Send enterprise demo request — notification to admin + confirmation to prospect."""
    use_case_label = use_case.replace("_", " ").capitalize() if use_case else "Not specified"

    # 1. Notification to admin inbox
    admin_subject = f"[Enterprise Demo] {company} — {first_name} {last_name}"
    admin_body = f"""New enterprise demo request
{'=' * 50}

Name:      {first_name} {last_name}
Email:     {email}
Company:   {company}
Use case:  {use_case_label}

Message:
{message if message else "(none)"}

{'=' * 50}
Reply directly to this email to contact the prospect.
"""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = admin_subject
        msg["From"] = f"ArkForge <{SMTP_USER}>"
        msg["To"] = SMTP_CONTACT
        msg["Reply-To"] = email
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain="arkforge.fr")
        msg.attach(MIMEText(admin_body, "plain", "utf-8"))

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=15) as server:
            server.login(SMTP_LOGIN, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, SMTP_CONTACT, msg.as_string())
        logger.info("Demo request notification sent to admin for %s / %s", email, company)
    except Exception as e:
        logger.warning("Demo request admin notification failed: %s", e)

    # 2. Confirmation to prospect
    confirm_subject = "ArkForge — We received your enterprise request"
    confirm_body = f"""Hi {first_name},

Thanks for reaching out. We received your demo request for {company} and will get back to you within one business day.

In the meantime, you can explore the docs at https://github.com/ark-forge/trust-layer
or try the API directly with a free key: https://arkforge.tech/en/signup.html

Looking forward to talking.

David, ArkForge
contact@arkforge.tech
"""
    try:
        _send_email(email, confirm_subject, confirm_body)
    except Exception as e:
        logger.warning("Demo request confirmation email failed for %s: %s", email, e)


def send_credits_exhausted_email(email: str, api_key: str):
    """Send an alert email when credits are fully exhausted."""
    subject = "[ArkForge] Credits exhausted — agent stopped"
    body = f"""ArkForge Trust Layer — Credits Exhausted
{'=' * 50}

Your credit balance has reached zero.

Your agent's API calls are currently being rejected (HTTP 402).

Recharge now to resume operations:

  curl -X POST https://trust.arkforge.tech/v1/credits/buy \\
    -H "X-Api-Key: {api_key}" \\
    -H "Content-Type: application/json" \\
    -d '{{"amount": 10}}'

This will charge the card saved during your initial setup.
10 EUR = 100 proofs.

{'=' * 50}
ArkForge Trust Layer — https://arkforge.tech/trust
"""
    try:
        _send_email(email, subject, body)
        logger.info("Credits exhausted alert sent to %s", email)
    except Exception as e:
        logger.warning("Credits exhausted email failed: %s", e)


def send_checkout_abandoned_email(email: str, plan: str = "pro", lang: str = "en"):
    """Send recovery email when a checkout session expires without payment."""
    plan_label = plan.capitalize()
    checkout_url = f"https://arkforge.tech/{lang}/pricing.html?intent={plan}&utm_source=email&utm_medium=abandoned_checkout"

    subject = f"Your {plan_label} checkout didn't complete"
    body = f"""ArkForge Trust Layer — Checkout Not Completed

Your {plan_label} plan checkout session expired before payment was completed.

No charges were made to your card.

If you ran into an issue or have questions about the plan,
reply to this email — we read every message.

To restart checkout:
  {checkout_url}

{'=' * 50}
ArkForge Trust Layer — https://arkforge.tech/trust
Support: contact@arkforge.fr
"""
    try:
        _send_email(email, subject, body)
        logger.info("Checkout abandoned recovery email sent to %s (plan=%s)", email, plan)
    except Exception as e:
        logger.warning("Checkout abandoned email failed: %s", e)
